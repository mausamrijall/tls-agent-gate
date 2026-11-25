import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyHostname, isPrivateOrLoopbackHost } from '../src/hostPolicy.ts';

test('core hostPolicy classifies local/private vs public', () => {
  assert.equal(classifyHostname('localhost'), 'loopback');
  assert.equal(classifyHostname('127.0.0.1'), 'loopback');
  assert.equal(classifyHostname('::1'), 'loopback');
  assert.equal(classifyHostname('10.0.0.1'), 'private');
  assert.equal(classifyHostname('172.16.0.1'), 'private');
  assert.equal(classifyHostname('192.168.0.1'), 'private');
  assert.equal(classifyHostname('100.64.0.1'), 'private');
  assert.equal(classifyHostname('169.254.1.1'), 'link-local');
  assert.equal(classifyHostname('example.com'), 'public');
  assert.equal(classifyHostname('8.8.8.8'), 'public');
  assert.equal(classifyHostname('192.0.2.1'), 'reserved');
});

test('isPrivateOrLoopbackHost matches expectations', () => {
  assert.equal(isPrivateOrLoopbackHost('localhost'), true);
  assert.equal(isPrivateOrLoopbackHost('10.1.2.3'), true);
  assert.equal(isPrivateOrLoopbackHost('example.com'), false);
  assert.equal(isPrivateOrLoopbackHost('93.184.216.34'), false);
});
