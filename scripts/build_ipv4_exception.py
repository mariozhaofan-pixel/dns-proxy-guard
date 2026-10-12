#!/usr/bin/env python3
"""Generate, but never apply, a narrow Mihomo JavaScript profile exception.

Requires observed IPv6 endpoints and existing PROCESS-NAME,...,DIRECT rules.
This is an exceptional compatibility workaround, not a general DNS repair.
The sniffer is destination-IP/port scoped; ONLY the routing change is process scoped.
"""

import argparse
import ipaddress
import json
import sys
from pathlib import Path


class BuildError(ValueError):
    pass


def parse_ipv6(value):
    try:
        if "%" in value:
            raise ValueError
        network = ipaddress.ip_network(value if "/" in value else value + "/128", strict=True)
        if network.version != 6 or network.prefixlen != 128:
            raise ValueError
        address = network.network_address
        if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local or address.ipv4_mapped:
            raise ValueError
        return address
    except ValueError:
        raise BuildError("Each endpoint must be one IPv6 unicast address or an exact /128, without a zone identifier.") from None


def ipv6_complement(addresses):
    """Return disjoint CIDRs covering every IPv6 address except these exact IPs."""
    networks = [ipaddress.IPv6Network("::/0")]
    for address in sorted(set(addresses), key=int):
        excluded = ipaddress.IPv6Network((address, 128))
        remaining = []
        for network in networks:
            if address in network:
                remaining.extend(network.address_exclude(excluded))
            else:
                remaining.append(network)
        networks = remaining
    return [str(network) for network in ipaddress.collapse_addresses(networks)]


def _name(value, process=False):
    if not value or value != value.strip() or any(ord(char) < 32 for char in value) or "," in value:
        raise BuildError("Names must be nonempty, trimmed, and contain no commas or control characters.")
    if process and ("/" in value or "\\" in value or value in (".", "..")):
        raise BuildError("Use a process basename, not a filesystem path.")
    return value


def build_profile(processes, endpoints, protocol, ports, outbound):
    processes = sorted({_name(value, process=True) for value in processes})
    addresses = sorted({parse_ipv6(value) for value in endpoints}, key=int)
    outbound = _name(outbound)
    if not processes or not addresses or not ports:
        raise BuildError("At least one explicit process, IPv6 endpoint, and port are required.")
    if protocol not in ("HTTP", "TLS"):
        raise BuildError("Protocol must be HTTP or TLS; UDP/QUIC recovery is unsupported.")
    if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
        raise BuildError("Each port must be an integer from 1 to 65535.")
    if outbound.upper() in {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "GLOBAL", "COMPATIBLE"}:
        raise BuildError("Choose a new explicit outbound name, not a built-in policy name.")
    settings = {
        "processes": processes,
        "proxy": {"name": outbound, "type": "direct", "ip-version": "ipv4"},
        "sniffer": {
            "enable": True,
            "force-dns-mapping": False,
            "parse-pure-ip": True,
            "override-destination": True,
            "force-domain": [],
            "skip-domain": [],
            "sniff": {protocol: {"ports": sorted(set(ports))}},
            "skip-dst-address": ["0.0.0.0/0"] + ipv6_complement(addresses),
        },
    }
    payload = json.dumps(settings, ensure_ascii=True, indent=2)
    script = """// Generated offline. Review before attaching to any profile.
// This is an exceptional compatibility workaround, not a DNS leak test.
// Sniffing affects ALL processes at the selected IPv6 destinations and TCP ports.
// Only the replacement PROCESS-NAME routing rules are process scoped.
// No UDP/QUIC recovery or successful hostname extraction is promised.
function main(config) {
  const desired = __PAYLOAD__;
  const fail = message => { throw new Error("dns-proxy-guard: " + message); };
  const object = value => value !== null && typeof value === "object" && !Array.isArray(value);
  const canonical = value => {
    if (Array.isArray(value)) return value.map(canonical);
    if (object(value)) return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
    return value;
  };
  const same = (left, right) => JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
  if (!object(config)) fail("configuration root must be an object");
  if (!Array.isArray(config.rules) || !config.rules.every(rule => typeof rule === "string"))
    fail("an existing string rule list is required");
  const proxies = config.proxies === undefined ? [] : config.proxies;
  const groups = config["proxy-groups"] === undefined ? [] : config["proxy-groups"];
  if (!Array.isArray(proxies) || !proxies.every(proxy => object(proxy) && typeof proxy.name === "string"))
    fail("unsupported proxy list");
  if (!Array.isArray(groups) || !groups.every(group => object(group) && typeof group.name === "string"))
    fail("unsupported proxy-group list");
  if (groups.some(group => group.name === desired.proxy.name)) fail("outbound name conflicts with a proxy group");
  const matching = proxies.filter(proxy => proxy.name === desired.proxy.name);
  if (matching.length > 1 || (matching.length === 1 && !same(matching[0], desired.proxy)))
    fail("outbound name conflicts with an existing proxy");
  if (Object.prototype.hasOwnProperty.call(config, "sniffer") && !same(config.sniffer, desired.sniffer))
    fail("existing sniffer conflicts; inspect and reconcile it explicitly before applying");
  const selected = new Set(desired.processes);
  const found = new Set();
  const rules = config.rules.map(rule => {
    const fields = rule.split(",").map(field => field.trim());
    if (fields[0] !== "PROCESS-NAME" || !selected.has(fields[1])) return rule;
    if (fields.length !== 3 || !["DIRECT", desired.proxy.name].includes(fields[2]))
      fail("a selected process has a conflicting or unsupported rule");
    found.add(fields[1]);
    return fields[2] === desired.proxy.name ? rule : ["PROCESS-NAME", fields[1], desired.proxy.name].join(",");
  });
  if (found.size !== selected.size) fail("each selected process needs an existing DIRECT rule; no rule will be invented");
  // All validation occurs before constructing the result. Input objects are never mutated.
  return {
    ...config,
    proxies: matching.length ? proxies : [...proxies, desired.proxy],
    rules,
    sniffer: desired.sniffer
  };
}
""".replace("__PAYLOAD__", payload)
    return script, addresses


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--process", action="append", required=True, metavar="BASENAME")
    parser.add_argument("--ipv6", action="append", required=True, metavar="OBSERVED_IP")
    parser.add_argument("--protocol", choices=("HTTP", "TLS"), required=True)
    parser.add_argument("--port", action="append", type=int, required=True)
    parser.add_argument("--outbound", required=True, metavar="NAME")
    parser.add_argument("--output", required=True, metavar="FILE.js")
    args = parser.parse_args(argv)
    try:
        script, addresses = build_profile(args.process, args.ipv6, args.protocol, args.port, args.outbound)
        destination = Path(args.output)
        if destination.exists():
            if destination.read_text(encoding="utf-8") != script:
                raise BuildError("Output already exists with different content; choose another output file.")
        else:
            with destination.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(script)
        print("Generated offline profile; no configuration was applied and no server was contacted.", file=sys.stderr)
        if any(address in ipaddress.IPv6Network("2001:db8::/32") for address in addresses):
            print("WARNING: 2001:db8::/32 addresses are documentation examples and cannot serve as a real repair.", file=sys.stderr)
        print("Review sniffer conflicts and test hostname extraction, application behavior, routing, and DNS transport separately.", file=sys.stderr)
        return 0
    except BuildError as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    except (OSError, UnicodeError):
        print("error: Cannot read or create the offline output file.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
