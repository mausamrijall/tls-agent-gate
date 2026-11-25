/**
 * Origin classification for agent identity URLs. We must never let a
 * caller anchor its identity to a private/loopback origin unless the site
 * operator has explicitly allowlisted a dev key — otherwise this becomes
 * a trivial SSRF / spoofing bypass.
 *
 * This module is pure (no `node:net`), so it runs on Cloudflare Workers,
 * browsers, and Node alike.
 */

export type HostClass =
  | 'public'
  | 'loopback'
  | 'private'
  | 'link-local'
  | 'reserved'
  | 'invalid';

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function ipv4ToInt(parts: [string, string, string, string]): number | null {
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => n < 0 || n > 255)) return null;
  return ((nums[0]! << 24) | (nums[1]! << 16) | (nums[2]! << 8) | nums[3]!) >>> 0;
}

function classifyIpv4(ip: string): HostClass {
  const m = IPV4_RE.exec(ip);
  if (!m) return 'invalid';
  const int = ipv4ToInt([m[1]!, m[2]!, m[3]!, m[4]!]);
  if (int === null) return 'invalid';

  // 127.0.0.0/8 loopback
  if ((int >>> 24) === 127) return 'loopback';
  // 10.0.0.0/8
  if ((int >>> 24) === 10) return 'private';
  // 172.16.0.0/12
  if ((int >>> 20) === 0xac1) return 'private';
  // 192.168.0.0/16
  if ((int >>> 16) === 0xc0a8) return 'private';
  // 169.254.0.0/16 link-local
  if ((int >>> 16) === 0xa9fe) return 'link-local';
  // 100.64.0.0/10 CGNAT (100.64.0.0 - 100.127.255.255)
  const secondOctet = (int >>> 16) & 0xff;
  if ((int >>> 24) === 100 && secondOctet >= 64 && secondOctet <= 127) return 'private';
  // 0.0.0.0/8
  if ((int >>> 24) === 0) return 'reserved';
  // Documentation ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
  const inDoc192 = int >= 0xc0000200 && int <= 0xc00002ff;
  const inDoc198 = int >= 0xc6336400 && int <= 0xc63364ff;
  const inDoc203 = int >= 0xcb007100 && int <= 0xcb0071ff;
  if (inDoc192 || inDoc198 || inDoc203) return 'reserved';
  // 224.0.0.0/4 multicast + broadcast
  if (int >= 0xe0000000) return 'reserved';

  return 'public';
}

function classifyIpv6(ip: string): HostClass {
  const lower = ip.toLowerCase();
  if (lower === '::1') return 'loopback';
  if (lower.startsWith('fc') || lower.startsWith('fd')) return 'private'; // fc00::/7 ULA
  if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
    return 'link-local'; // fe80::/10
  }
  if (lower.startsWith('ff')) return 'reserved'; // multicast
  if (lower.startsWith('::')) return 'reserved'; // unspecified / IPv4-mapped handled below
  return 'public';
}

/** Classify a hostname or IP literal (no DNS resolution). */
export function classifyHostname(host: string): HostClass {
  const value = host.trim().toLowerCase();
  if (!value) return 'invalid';

  // Well-known local hostnames.
  if (value === 'localhost' || value.endsWith('.localhost')) return 'loopback';
  if (value.endsWith('.local')) return 'private'; // mDNS

  if (value.includes(':')) {
    // IPv6 literal. Only a bracketed form may carry a port: [addr]:port.
    let addr = value;
    if (addr.startsWith('[')) {
      const close = addr.indexOf(']');
      addr = close === -1 ? addr.slice(1) : addr.slice(1, close);
    }
    if (!/^[0-9a-f:]+$/.test(addr)) return 'invalid';
    return classifyIpv6(addr);
  }

  // IPv4 literal (optionally with port).
  const base = value.split(':')[0]!;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(base)) return classifyIpv4(base);

  // Public DNS hostname.
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(value)) {
    return 'public';
  }
  return 'invalid';
}

/** True for origins that must be blocked unless explicitly allowlisted. */
export function isPrivateOrLoopbackHost(host: string): boolean {
  const c = classifyHostname(host);
  return c === 'loopback' || c === 'private' || c === 'link-local';
}

/** True when the host is a literal IP address. */
export function isIpLiteral(host: string): boolean {
  const value = host.trim().toLowerCase();
  if (value.includes(':')) return /^[0-9a-f:\[\]]+$/.test(value);
  return IPV4_RE.test(value.split(':')[0]!);
}
