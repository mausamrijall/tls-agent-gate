#!/usr/bin/env node
/**
 * tls-agent-gate CLI.
 *
 * Commands:
 *   keygen   generate .well-known/agent-identity.json + key material
 *   validate  check identity/manifest JSON against the bundled schemas
 *   probe    inspect a live HTTPS agent endpoint and report verification behavior
 */
import { parseArgs, flagString, flagBool } from './args.ts';
import { keygen } from './keygen.ts';
import { validateFile, validateJsonString, type ValidateKind } from './validate.ts';
import { probe, renderProbe, type ProbeOptions } from './probe.ts';
import type { KeyAlgorithm } from '@tls-agent-gate/core';

const HELP = `tls-agent-gate — trust layer for the Open Agentic Web

USAGE
  tls-agent-gate <command> [options]

COMMANDS
  keygen [--out DIR] [--domain HOST] [--subject URL]
         [--primary ed25519|es256] [--secondary] [--allow-local] [--kid ID]
      Generates .well-known/agent-identity.json plus key material in
      ./keys (private key chmod 600). Deploy the identity file to
      https://HOST/.well-known/agent-identity.json and keep the private
      key out of any public repository.

  validate <file.json> [--kind identity|manifest|auto]
      Validates an agent identity or manifest document against the bundled
      JSON Schemas. Default --kind auto (sniffs capabilities).

  probe <url> [--timeout-ms N] [--identity-url URL] [--key-file PATH]
      Fetches the target's identity + manifest, then reports whether the
      endpoint enforces agent verification, including a signed probe with
      an ephemeral key. Pass --identity-url and --key-file to run a real
      signed call.

GLOBAL
  --help   show this help

EXAMPLES
  tls-agent-gate keygen --out ./site-a --domain caller.example
  tls-agent-gate validate ./site-a/.well-known/agent-identity.json
  tls-agent-gate probe https://protected.example/api/agent
`;

export interface CliIo {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
}

function print(io: CliIo, s: string): void {
  io.stdout(s.endsWith('\n') ? s : `${s}\n`);
}

export async function main(argv: string[], io: CliIo = { stdout: console.log, stderr: console.error }): Promise<number> {
  const { command, positional, flags } = parseArgs(argv);

  if (command === '--help' || command === 'help' || (!command && (flags['help'] === true || flags['h'] === true))) {
    print(io, HELP);
    return 0;
  }
  if (!command) {
    print(io, HELP);
    return 2;
  }

  try {
    switch (command) {
      case 'keygen': {
        const outDir = flagString(flags, 'out') ?? '.';
        const domain = flagString(flags, 'domain') ?? 'localhost';
        const primaryRaw = flagString(flags, 'primary', 'ed25519')?.toLowerCase();
        const primary: KeyAlgorithm = primaryRaw === 'es256' ? 'ES256' : 'Ed25519';
        const result = await keygen({
          outDir,
          domain,
          subject: flagString(flags, 'subject'),
          primary,
          secondary: flagBool(flags, 'secondary'),
          kidOverride: flagString(flags, 'kid'),
          allowLocalAgents: flagBool(flags, 'allow-local'),
        });
        print(
          io,
          [
            `Identity     -> ${result.identityPath}`,
            `Private key  -> ${result.privateKeyPath}  (chmod 600)`,
            `Public key   -> ${result.publicKeyPath}`,
            `Primary key  -> ${result.primary.alg} kid=${result.primary.kid}`,
            `  thumbprint -> ${result.primary.thumbprint}`,
            ...(result.secondary ? [`Secondary key -> ${result.secondary.alg} kid=${result.secondary.kid}`] : []),
            '',
            'DEPLOY: serve the identity file at',
            `  https://${domain}/.well-known/agent-identity.json`,
            'Keep the private JWK out of source control and load it from a secret store.',
          ].join('\n'),
        );
        return 0;
      }

      case 'validate': {
        const file = positional[0];
        if (!file) {
          io.stderr('error: validate requires a JSON file path');
          return 2;
        }
        const kind = (flagString(flags, 'kind', 'auto') ?? 'auto') as ValidateKind;
        if (file === '-') {
          // read from stdin
          let raw = '';
          for await (const chunk of process.stdin) raw += chunk;
          const { result } = validateJsonString(raw, kind);
          print(io, result.valid ? 'valid' : ['invalid', ...result.errors.map((e) => `  - ${e.path} ${e.message}`)].join('\n'));
          return result.valid ? 0 : 1;
        }
        const outcome = await validateFile(file, kind);
        if (outcome.valid) {
          print(io, `${outcome.file}: valid ${outcome.kind}`);
          return 0;
        }
        print(io, `${outcome.file}: INVALID ${outcome.kind}`);
        for (const e of outcome.errors) print(io, `  - ${e}`);
        return 1;
      }

      case 'probe': {
        const url = positional[0];
        if (!url) {
          io.stderr('error: probe requires a URL');
          return 2;
        }
        const probeOpts: ProbeOptions = {
          url,
          timeoutMs: Number(flagString(flags, 'timeout-ms', '10000') ?? 10000),
          identityUrl: flagString(flags, 'identity-url'),
          keyFile: flagString(flags, 'key-file'),
        };
        const finding = await probe(probeOpts);
        print(io, renderProbe(finding));
        if (flagBool(flags, 'json')) {
          io.stderr(JSON.stringify({ ...finding, identityErrors: finding.identityErrors, manifestErrors: finding.manifestErrors }, null, 2));
        }
        return finding.enforcement === 'error' ? 1 : 0;
      }

      default:
        io.stderr(`unknown command: ${command}`);
        print(io, HELP);
        return 2;
    }
  } catch (err) {
    io.stderr(`error: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}

// Entry point when executed directly.
import { pathToFileURL } from 'node:url';
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
