import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../src/args.ts';

test('parses command, positional args, and flags', () => {
  const parsed = parseArgs(['keygen', '--out', './x', '--secondary', 'value.json', '--json']);
  assert.equal(parsed.command, 'keygen');
  assert.deepEqual(parsed.positional, ['value.json']);
  assert.equal(parsed.flags['out'], './x');
  assert.equal(parsed.flags['json'], true);
});

test('supports --flag=value syntax', () => {
  const parsed = parseArgs(['probe', '--timeout-ms=2500']);
  assert.equal(parsed.flags['timeout-ms'], '2500');
});

test('command is first non-flag token', () => {
  const parsed = parseArgs(['--verbose', 'validate', 'f.json']);
  assert.equal(parsed.command, 'validate');
  assert.deepEqual(parsed.positional, ['f.json']);
});
