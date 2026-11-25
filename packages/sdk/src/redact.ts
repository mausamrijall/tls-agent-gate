/**
 * Sensitive-field redaction. Used before outbound calls and before anything
 * is written to the audit trail so secrets never leave the boundary.
 */
import type { RedactionRule } from './policy.ts';

const DEFAULT_REPLACEMENT = '[REDACTED]';

function valueMatches(value: string, pattern: RegExp | string): boolean {
  return typeof pattern === 'string' ? value === pattern : pattern.test(value);
}

function keyMatches(key: string, pattern: RegExp | string): boolean {
  return typeof pattern === 'string' ? key.toLowerCase().includes(pattern.toLowerCase()) : pattern.test(key);
}

/** Redact a value recursively according to the supplied rules. */
export function redactValue(value: unknown, rules: RedactionRule[], depth = 0): unknown {
  if (rules.length === 0) return value;
  if (depth > 12) return '[MAX_DEPTH]';

  if (value === null) return null;
  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, rules, depth + 1));
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      const matched = rules.find((r) => (r.targets ?? ['keys', 'values']).includes('keys') && keyMatches(key, r.pattern));
      if (matched) {
        // Key is sensitive → mask its whole value.
        out[key] = matched.replacement ?? DEFAULT_REPLACEMENT;
        continue;
      }
      out[key] = redactValue(val, rules, depth + 1);
    }
    return out;
  }
  if (typeof value === 'string') {
    let out = value;
    for (const rule of rules) {
      const targets = rule.targets ?? ['keys', 'values'];
      if (targets.includes('values') && valueMatches(out, rule.pattern)) {
        out = rule.replacement ?? DEFAULT_REPLACEMENT;
      }
    }
    return out;
  }
  return value;
}

/** Redact a plain object (used for headers/payloads/audit detail). */
export function redactObject(obj: Record<string, unknown>, rules: RedactionRule[]): Record<string, unknown> {
  return redactValue(obj, rules, 0) as Record<string, unknown>;
}
