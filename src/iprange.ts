// CIDR parsing for upstream IP lists (one CIDR per line, e.g. cloudflare.com/ips-v4).

export function parseCidrList(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "").trim();
    if (line) out.push(line);
  }
  return out;
}

export function isIpv4Cidr(s: string): boolean {
  return !s.includes(":") && /^[\d.]+\/\d+$/.test(s);
}
