import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyHostname, isPrivateOrLoopbackHost } from '../src/hostPolicy.ts';

test('classifies loopback hosts', () => {
  assert.equal(classifyHostname('localhost'), 'loopback');
  assert.equal(classifyHostname('sub.localhost'), 'loopback');
  assert.equal(classifyHostname('127.0.0.1'), 'loopback');
  assert.equal(classifyHostname('127.255.255.254'), 'loopback');
  assert.equal(classifyHostname('::1'), 'loopback');
});

test('classifies private ranges', () => {
  assert.equal(classifyHostname('10.0.0.1'), 'private');
  assert.equal(classifyHostname('10.255.255.255'), 'private');
  assert.equal(classifyHostname('172.16.0.1'), 'private');
  assert.equal(classifyHostname('172.31.255.255'), 'private');
  assert.equal(classifyHostname('192.168.1.1'), 'private');
  assert.equal(classifyHostname('100.64.0.1'), 'private');
  assert.equal(classifyHostname('fd12:3456::1'), 'private');
  assert.equal(classifyHostname('device.local'), 'private');
});

test('classifies link-local', () => {
  assert.equal(classifyHostname('169.254.1.1'), 'link-local');
  assert.equal(classifyHostname('fe80::1'), 'link-local');
});

test('classifies public DNS and public IPs', () => {
  assert.equal(classifyHostname('example.com'), 'public');
  assert.equal(classifyHostname('agent.services.example.com'), 'public');
  assert.equal(classifyHostname('8.8.8.8'), 'public');
  assert.equal(classifyHostname('93.184.216.34'), 'public');
});

test('classifies reserved/documentation addresses', () => {
  assert.equal(classifyHostname('0.0.0.1'), 'reserved');
  assert.equal(classifyHostname('192.0.2.1'), 'reserved');
  assert.equal(classifyHostname('198.51.100.1'), 'reserved');
  assert.equal(classifyHostname('203.0.113.1'), 'reserved');
  assert.equal(classifyHostname('224.0.0.1'), 'reserved');
});

test('isPrivateOrLoopbackHost gate', () => {
  assert.equal(isPrivateOrLoopbackHost('localhost'), true);
  assert.equal(isPrivateOrLoopbackHost('10.0.0.9'), true);
  assert.equal(isPrivateOrLoopbackHost('192.168.0.9'), true);
  assert.equal(isPrivateOrLoopbackHost('example.com'), false);
  assert.equal(isPrivateOrLoopbackHost('93.184.216.34'), false);
});
