/**
 * Minimal argv parser (no dependencies).
 */

export interface ParsedArgs {
  command: string;
  positional: string[];
  flags: Record<string, string | boolean>;
}

/** Flags that take a value (all others are boolean switches). */
const VALUE_FLAGS = new Set([
  'out',
  'domain',
  'subject',
  'primary',
  'kid',
  'kind',
  'timeout-ms',
  'identity-url',
  'key-file',
  'schema',
]);

export function parseArgs(argv: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  let command = '';

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      const key = arg.slice(2, eq === -1 ? undefined : eq);
      if (eq !== -1) {
        flags[key] = arg.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (VALUE_FLAGS.has(key) && next !== undefined && !next.startsWith('-')) {
          flags[key] = next;
          i++;
        } else {
          flags[key] = true;
        }
      }
    } else if (arg.startsWith('-') && arg.length > 1) {
      // single-dash flag: -o value (abbreviated flags not supported)
      const key = arg.slice(1);
      const next = argv[i + 1];
      if (VALUE_FLAGS.has(key) && next !== undefined && !next.startsWith('-')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else if (!command) {
      command = arg;
    } else {
      positional.push(arg);
    }
  }

  return { command, positional, flags };
}

export function flagString(flags: Record<string, string | boolean>, name: string, fallback?: string): string | undefined {
  const v = flags[name];
  if (v === undefined || typeof v === 'boolean') return fallback;
  return v;
}

export function flagBool(flags: Record<string, string | boolean>, name: string): boolean {
  return flags[name] === true || flags[name] === 'true' || flags[name] === '1';
}
