import { tool } from "ai";
import { HarnessAgent } from "@ai-sdk/harness/agent";
import { grokBuild, VERSION as GROK_BUILD_VERSION } from "@ai-sdk/harness-grok-build";
import { z } from "zod";
import type { GatewayDecision } from "./gateway.ts";

/**
 * Pinned Grok Build harness packages. permissionMode allow-all is intentional:
 * BearPortal eligibility is enforced by the operation gateway, not by the CLI prompt.
 * This module does not call the model.
 */
export const HARNESS_PIN = {
  packages: {
    "@ai-sdk/harness": "1.0.170",
    "@ai-sdk/harness-grok-build": "1.0.109",
    ai: "7.0.159",
  },
  grokBuildVersion: GROK_BUILD_VERSION,
  permissionMode: "allow-all" as const,
  model: "grok-build-0.1",
};

export class HarnessUnavailableError extends Error {
  readonly code = "HARNESS_UNAVAILABLE";

  constructor(message = "Live Grok Build is not configured.") {
    super(message);
    this.name = "HarnessUnavailableError";
  }
}

/** A developer shell key is not control-plane authentication. */
export function harnessAuthMode(env: Record<string, string | undefined>): "unavailable" | "configured" {
  if (env.BEARPORTAL_XAI_API_KEY || env.BEARPORTAL_AI_GATEWAY_API_KEY) return "configured";
  return "unavailable";
}

/**
 * Live generation stays disabled. A configured key still does not start a model
 * loop from this process, and an inherited developer session is ignored.
 */
export function assertLiveHarnessDisabled(env: Record<string, string | undefined>): never {
  if (harnessAuthMode(env) === "unavailable") {
    throw new HarnessUnavailableError("Live Grok Build is not configured.");
  }
  throw new HarnessUnavailableError("Live Grok Build execution is disabled on this control plane.");
}

export type GatewayCaller = (toolName: string, args: Record<string, unknown>) => GatewayDecision | Promise<GatewayDecision>;

/** Host tool backed by the gateway. Built-in scratch tools stay on the harness and are not given a worker. */
export function createOversightAgent(callGateway: GatewayCaller) {
  const readDeploymentState = tool({
    description: "Read redacted deployment state through the BearPortal operation gateway.",
    inputSchema: z.object({}).strict(),
    execute: async (args) => callGateway("read_deployment_state", args),
  });
  return new HarnessAgent({
    harness: grokBuild,
    id: "bearportal-oversight",
    model: HARNESS_PIN.model,
    permissionMode: HARNESS_PIN.permissionMode,
    tools: { read_deployment_state: readDeploymentState },
  });
}
