import { isIP } from 'node:net';

/**
 * Whether an IP address is one a probe may reach: a globally routable
 * unicast address. Loopback, private (RFC 1918, ULA), link-local (including
 * cloud metadata at 169.254.169.254 and fd00:ec2::254), CGNAT, unspecified,
 * multicast, broadcast and reserved ranges are refused, and so is any IPv6
 * form that embeds such an IPv4 address (mapped, compatible, NAT64, 6to4).
 * Documentation ranges (192.0.2.0/24 and similar) are not refused: they are
 * not routable anyway.
 */

function v4Parts(ip: string): number[] | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const n = parts.map((p) => (/^\d{1,3}$/.test(p) ? Number(p) : NaN));
  return n.every((x) => x >= 0 && x <= 255) ? n : null;
}

function privateV4(n: number[]): boolean {
  const [a, b] = [n[0]!, n[1]!];
  return (
    a === 0 || // "this network", including 0.0.0.0
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) || // CGNAT
    (a === 169 && b === 254) || // link-local, metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && n[2] === 0) || // IETF protocol assignments
    (a === 198 && (b === 18 || b === 19)) || // benchmarking
    a >= 224 // multicast, reserved, broadcast
  );
}

/** Eight 16-bit groups, or null. */
function v6Groups(ip: string): number[] | null {
  let s = ip.toLowerCase().replace(/%.*$/, '');
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) {
    const n = v4Parts(tail[1]!);
    if (!n) return null;
    s = s.slice(0, -tail[1]!.length) + `${((n[0]! << 8) | n[1]!).toString(16)}:${((n[2]! << 8) | n[3]!).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parse = (h: string) => (h === '' ? [] : h.split(':').map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN)));
  const head = parse(halves[0]!);
  const rest = halves.length === 2 ? parse(halves[1]!) : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  const groups = [...head, ...Array<number>(Math.max(fill, 0)).fill(0), ...rest];
  return groups.length === 8 && groups.every((g) => Number.isInteger(g)) ? groups : null;
}

function privateV6(g: number[]): boolean {
  const embedded = (hi: number, lo: number) => privateV4([hi >> 8, hi & 255, lo >> 8, lo & 255]);
  if (g.every((x) => x === 0)) return true; // ::
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return true; // ::1
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) return embedded(g[6]!, g[7]!) || g[5] === 0; // mapped / compatible
  if (g[0] === 0x64 && g[1] === 0xff9b) return embedded(g[6]!, g[7]!); // NAT64
  if (g[0] === 0x2002) return embedded(g[1]!, g[2]!); // 6to4
  if ((g[0]! & 0xfe00) === 0xfc00) return true; // ULA fc00::/7, includes fd00:ec2::254
  if ((g[0]! & 0xffc0) === 0xfe80 || (g[0]! & 0xffc0) === 0xfec0) return true; // link-local, site-local
  if ((g[0]! & 0xff00) === 0xff00) return true; // multicast
  return false;
}

/** True for any address a probe must not reach; unparseable input counts as non-public. */
export function isNonPublic(ip: string): boolean {
  const bare = ip.replace(/^\[|\]$/g, '');
  const kind = isIP(bare.replace(/%.*$/, ''));
  if (kind === 4) return privateV4(v4Parts(bare)!);
  if (kind === 6) {
    const g = v6Groups(bare);
    return g ? privateV6(g) : true;
  }
  return true;
}

/** The host of a parsed URL as an IP literal, or null when it is a name. */
export function ipLiteral(hostname: string): string | null {
  const bare = hostname.replace(/^\[|\]$/g, '');
  return isIP(bare) ? bare : null;
}
