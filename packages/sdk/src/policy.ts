/**
 * Capability & sandbox policy for bounded agents.
 *
 * The policy is the single source of truth for what an agent may do. Every
 * tool/command/cross-site action is checked against it BEFORE execution.
 * Policies are **deny-by-default**: an empty policy allows nothing.
 */
import {
  isPrivateOrLoopbackHost,
  type SchemaObject,
} from '@tls-agent-gate/core';

/** One allowlisted tool with optional JSON-Schema argument validation. */
export interface ToolSpec {
  name: string;
  description?: string;
  /** JSON Schema (draft-07 subset supported by core's mini validator). */
  argSchema?: SchemaObject;
  /** When true, invoking this tool always asks for user consent. */
  requiresConsent?: boolean;
}

/** Sensitive-data redaction rule applied before outbound calls / audit logs. */
export interface RedactionRule {
  /** Regex (values) or literal key name (keys). */
  pattern: RegExp | string;
  replacement?: string;
  /** Where to apply: 'keys' (JSON object keys), 'values' (strings), or both. */
  targets?: Array<'keys' | 'values'>;
}

/** Which actions require explicit human consent. */
export type ConsentTrigger =
  | { type: 'cross-site'; origins?: string[] }
  | { type: 'tool'; tools?: string[] }
  | { type: 'command'; commands?: string[] }
  | { type: 'all' };

export interface AgentCapabilityPolicy {
  /** Allowlisted tools (with argument schema validation). */
  allowedTools: ToolSpec[];
  /** Allowlisted low-level command names (handlers provided by the app). */
  allowedCommands: string[];
  /** Exact origins allowed for outbound fetches / agent calls. */
  allowedOrigins: string[];
  /** Optional full-URL regex patterns (complement allowedOrigins). */
  allowedTargetPatterns: RegExp[];
  /** Allow localhost/private-network targets (dev only, still allowlist-gated). */
  allowLocalAgents: boolean;
  /** Dev key thumbprints accepted when allowLocalAgents is true. */
  allowedDevKeyThumbprints?: string[];
  /** Max tool/fetch/agent-call executions per turn. */
  maxCallsPerTurn: number;
  /** Max proposed actions per turn (denied proposals count too). */
  maxStepsPerTurn: number;
  /** Max serialized outbound payload size in bytes. */
  maxPayloadBytes: number;
  /** Per-execution timeout in milliseconds. */
  executionTimeoutMs: number;
  /** Redaction rules applied to outbound payloads and audit detail. */
  dataRedactionRules: RedactionRule[];
  /** Actions that require user consent. */
  requireConsentFor: ConsentTrigger[];
  /** When true (default), invoking a tool not in allowedTools is denied. */
  strictTools: boolean;
}

export const DEFAULT_POLICY: AgentCapabilityPolicy = {
  allowedTools: [],
  allowedCommands: [],
  allowedOrigins: [],
  allowedTargetPatterns: [],
  allowLocalAgents: false,
  allowedDevKeyThumbprints: [],
  maxCallsPerTurn: 50,
  maxStepsPerTurn: 200,
  maxPayloadBytes: 1024 * 1024,
  executionTimeoutMs: 30_000,
  dataRedactionRules: [],
  requireConsentFor: [{ type: 'cross-site' }],
  strictTools: true,
};

/**
 * Merge a partial policy over the defaults. Arrays provided by the caller
 * replace the default (an omitted array stays empty → strictest behavior).
 */
export function normalizePolicy(partial?: Partial<AgentCapabilityPolicy>): AgentCapabilityPolicy {
  return {
    allowedTools: partial?.allowedTools ?? DEFAULT_POLICY.allowedTools,
    allowedCommands: partial?.allowedCommands ?? DEFAULT_POLICY.allowedCommands,
    allowedOrigins: partial?.allowedOrigins ?? DEFAULT_POLICY.allowedOrigins,
    allowedTargetPatterns: partial?.allowedTargetPatterns ?? DEFAULT_POLICY.allowedTargetPatterns,
    allowLocalAgents: partial?.allowLocalAgents ?? DEFAULT_POLICY.allowLocalAgents,
    allowedDevKeyThumbprints: partial?.allowedDevKeyThumbprints ?? DEFAULT_POLICY.allowedDevKeyThumbprints,
    maxCallsPerTurn: partial?.maxCallsPerTurn ?? DEFAULT_POLICY.maxCallsPerTurn,
    maxStepsPerTurn: partial?.maxStepsPerTurn ?? DEFAULT_POLICY.maxStepsPerTurn,
    maxPayloadBytes: partial?.maxPayloadBytes ?? DEFAULT_POLICY.maxPayloadBytes,
    executionTimeoutMs: partial?.executionTimeoutMs ?? DEFAULT_POLICY.executionTimeoutMs,
    dataRedactionRules: partial?.dataRedactionRules ?? DEFAULT_POLICY.dataRedactionRules,
    requireConsentFor: partial?.requireConsentFor ?? DEFAULT_POLICY.requireConsentFor,
    strictTools: partial?.strictTools ?? DEFAULT_POLICY.strictTools,
  };
}

/** Find an allowlisted tool by name. */
export function policyAllowsTool(policy: AgentCapabilityPolicy, name: string): ToolSpec | undefined {
  return policy.allowedTools.find((t) => t.name === name);
}

export function policyAllowsCommand(policy: AgentCapabilityPolicy, command: string): boolean {
  return policy.allowedCommands.includes(command);
}

/**
 * Origin policy. A target is allowed only when:
 *  - it is not a private/loopback host, OR allowLocalAgents is true; and
 *  - its origin is in allowedOrigins OR a full-URL pattern matches.
 */
export function policyAllowsOrigin(policy: AgentCapabilityPolicy, url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  const hostname = parsed.hostname.toLowerCase();
  if (isPrivateOrLoopbackHost(hostname) && !policy.allowLocalAgents) {
    return false;
  }
  const origin = parsed.origin.toLowerCase();
  if (policy.allowedOrigins.some((o) => o.toLowerCase() === origin)) return true;
  return policy.allowedTargetPatterns.some((re) => re.test(url));
}

/** Determine whether an action type requires consent under the policy. */
export function policyRequiresConsent(
  policy: AgentCapabilityPolicy,
  kind: 'tool' | 'command' | 'fetch' | 'agent-call',
  subject: string,
  origin?: string,
): boolean {
  for (const trigger of policy.requireConsentFor) {
    if (trigger.type === 'all') return true;
    if (trigger.type === 'cross-site' && (kind === 'agent-call' || kind === 'fetch')) {
      if (trigger.origins && origin) {
        if (trigger.origins.some((o) => o.toLowerCase() === origin.toLowerCase())) return true;
      } else {
        return true;
      }
    }
    if (trigger.type === 'tool' && kind === 'tool') {
      if (trigger.tools ? trigger.tools.includes(subject) : true) return true;
    }
    if (trigger.type === 'command' && kind === 'command') {
      if (trigger.commands ? trigger.commands.includes(subject) : true) return true;
    }
  }
  return false;
}
