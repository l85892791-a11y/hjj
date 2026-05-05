// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Cursor SDK executor for Shannon agents.
 *
 * Provides the same ClaudePromptResult interface as claude-executor.ts,
 * but routes agent execution through the Cursor SDK (@cursor/sdk) instead
 * of the Anthropic Claude Agent SDK. This enables users with a Cursor
 * subscription to run Shannon using their Cursor API key.
 *
 * API key: user key from https://cursor.com/dashboard/integrations
 * or service account key from team settings.
 */

import { Agent } from '@cursor/sdk';
import { fs, path } from 'zx';
import type { AuditSession } from '../audit/index.js';
import { deliverablesDir } from '../paths.js';
import { isRetryableError, PentestError } from '../services/error-handling.js';
import type { ActivityLogger } from '../types/activity-logger.js';
import { isSpendingCapBehavior } from '../utils/billing-detection.js';
import { formatTimestamp } from '../utils/formatting.js';
import { Timer } from '../utils/metrics.js';
import type { ClaudePromptResult } from './claude-executor.js';
import { type ModelTier, resolveModel } from './models.js';

/** Map Shannon model tiers to Cursor SDK model IDs. */
function resolveCursorModel(tier: ModelTier): string {
  const model = resolveModel(tier);
  // Cursor SDK uses 'composer-2' as the default agent model.
  // If the user has not overridden model tiers, use composer-2.
  // If they have custom model IDs, pass them through — Cursor SDK
  // supports specifying Claude model IDs directly.
  if (model.startsWith('claude-')) {
    return model;
  }
  return 'composer-2';
}

async function writeErrorLog(
  err: Error & { code?: string; status?: number },
  sourceDir: string,
  fullPrompt: string,
  duration: number,
): Promise<void> {
  try {
    const errorLog = {
      timestamp: formatTimestamp(),
      agent: 'cursor-executor',
      error: {
        name: err.constructor.name,
        message: err.message,
        code: err.code,
        status: err.status,
        stack: err.stack,
      },
      context: {
        sourceDir,
        prompt: `${fullPrompt.slice(0, 200)}...`,
        retryable: isRetryableError(err),
      },
      duration,
    };
    const logPath = path.join(deliverablesDir(sourceDir), 'error.log');
    await fs.appendFile(logPath, `${JSON.stringify(errorLog)}\n`);
  } catch {
    // Best-effort error log writing
  }
}

/**
 * Execute a Shannon agent prompt using the Cursor SDK.
 *
 * Drop-in replacement for runClaudePrompt when CURSOR_API_KEY is configured.
 * Uses Cursor's local runtime: the agent runs inline against the repo filesystem.
 */
export async function runCursorPrompt(
  prompt: string,
  sourceDir: string,
  context: string = '',
  description: string = 'Cursor analysis',
  _agentName: string | null = null,
  _auditSession: AuditSession | null = null,
  logger: ActivityLogger,
  modelTier: ModelTier = 'medium',
): Promise<ClaudePromptResult> {
  // 1. Initialize timing and prompt
  const timer = new Timer(`agent-${description.toLowerCase().replace(/\s+/g, '-')}`);
  const fullPrompt = context ? `${context}\n\n${prompt}` : prompt;

  const apiKey = process.env.CURSOR_API_KEY;
  if (!apiKey) {
    return {
      error: 'CURSOR_API_KEY is not set',
      errorType: 'ConfigurationError',
      success: false,
      duration: 0,
      cost: 0,
      retryable: false,
    };
  }

  logger.info(`Running Cursor agent: ${description}...`);

  const model = resolveCursorModel(modelTier);
  let turnCount = 0;
  let result: string | null = null;
  let totalCost = 0;

  try {
    // 2. Create a local Cursor agent against the repo directory
    const agent = await Agent.create({
      apiKey,
      model: { id: model },
      local: { cwd: sourceDir },
    });

    // 3. Send the prompt and stream results
    const run = await agent.send(fullPrompt);

    const textParts: string[] = [];

    for await (const event of run.stream()) {
      switch (event.type) {
        case 'assistant':
          turnCount++;
          for (const block of event.message.content) {
            if ('text' in block && block.text) {
              textParts.push(block.text);
            }
          }
          break;
        case 'tool_call':
          if (event.status === 'completed') {
            logger.info(`[cursor] tool: ${event.name} completed`);
          }
          break;
        case 'status':
          logger.info(`[cursor] status: ${event.status}`);
          break;
      }
    }

    // 4. Collect final result
    const runResult = await run.wait();
    result = runResult.result || textParts.join('\n') || null;

    // 5. Dispose the agent
    agent.close();

    // 6. Spending cap check
    if (isSpendingCapBehavior(turnCount, totalCost, result || '')) {
      throw new PentestError(
        `Spending cap likely reached (turns=${turnCount}, cost=$0): ${result?.slice(0, 100)}`,
        'billing',
        true,
      );
    }

    // 7. Finalize successful result
    const duration = timer.stop();

    logger.info(`Cursor agent completed: ${description} (${turnCount} turns, ${Math.floor(duration / 1000)}s)`);

    return {
      result,
      success: true,
      duration,
      turns: turnCount,
      cost: totalCost,
      model,
    };
  } catch (error) {
    // 8. Handle errors
    const duration = timer.stop();
    const err = error as Error & { code?: string; status?: number };

    logger.error(`Cursor agent error in ${description}: ${err.message}`);
    await writeErrorLog(err, sourceDir, fullPrompt, duration);

    return {
      error: err.message,
      errorType: err.constructor.name,
      prompt: `${fullPrompt.slice(0, 100)}...`,
      success: false,
      duration,
      cost: totalCost,
      retryable: isRetryableError(err),
    };
  }
}

/** Check whether Cursor mode is active based on environment. */
export function isCursorMode(): boolean {
  return !!process.env.CURSOR_API_KEY && !process.env.ANTHROPIC_API_KEY && !process.env.CLAUDE_CODE_OAUTH_TOKEN;
}
