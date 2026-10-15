#!/usr/bin/env python3
"""Offline, redacted Mihomo configuration summary and preservation checks.

JSON uses only the standard library. YAML additionally requires PyYAML.
No network requests, controller calls, or configuration writes are performed.
"""

import argparse
import ipaddress
import json
import math
import sys
from pathlib import Path


class AuditError(ValueError):
    """An error whose message is safe to show without source configuration."""


ALIAS_ERROR = "Repeated or recursive container aliases are unsupported; use explicit mappings and lists."


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("Duplicate configuration keys are unsupported.")
        result[key] = value
    return result


def _json_tree(value, seen=None, depth=0):
    if depth > 100:
        raise AuditError("Configuration nesting is too deep.")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float) and math.isfinite(value):
        return
    if not isinstance(value, (dict, list)):
        raise AuditError("Configuration must contain JSON-compatible values.")
    seen = set() if seen is None else seen
    if id(value) in seen:
        # Reject even nonrecursive sharing: JSON serialization and later comparison
        # would otherwise expand a small YAML alias DAG into an exponential tree.
        raise AuditError(ALIAS_ERROR)
    seen.add(id(value))
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise AuditError("Configuration keys must be strings.")
        children = value.values()
    else:
        children = value
    for child in children:
        _json_tree(child, seen, depth + 1)


def load_config(path):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise AuditError("Configuration exceeds the 16 MiB offline input limit.")
        source = raw.decode("utf-8-sig")
    except (OSError, UnicodeError):
        raise AuditError("Cannot read the configuration as UTF-8.") from None
    try:
        data = json.loads(source, object_pairs_hook=_pairs)
    except json.JSONDecodeError:
        if Path(path).suffix.lower() not in (".yaml", ".yml"):
            raise AuditError("Cannot parse JSON; YAML input needs a .yaml or .yml suffix.") from None
        try:
            import yaml
        except ImportError:
            raise AuditError("YAML input requires optional PyYAML; JSON needs no package.") from None

        class UniqueLoader(yaml.SafeLoader):
            def compose_node(self, parent, index):
                # Reject container alias references before construction: YAML merge
                # flattening can itself expand exponentially, before _json_tree runs.
                if self.check_event(yaml.events.AliasEvent):
                    target = self.anchors.get(self.peek_event().anchor)
                    if isinstance(target, (yaml.nodes.MappingNode, yaml.nodes.SequenceNode)):
                        raise AuditError(ALIAS_ERROR)
                return super().compose_node(parent, index)

        def unique_mapping(loader, node, deep=False):
            loader.flatten_mapping(node)
            return _pairs(loader.construct_pairs(node, deep=deep))

        UniqueLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping
        )
        try:
            data = yaml.load(source, Loader=UniqueLoader)
        except AuditError:
            raise
        except Exception:
            raise AuditError("Cannot parse YAML safely; check syntax and duplicate keys.") from None
    except (RecursionError, ValueError):
        raise AuditError("Cannot parse JSON safely; check structure and duplicate keys.") from None
    _json_tree(data)
    if not isinstance(data, dict):
        raise AuditError("The configuration root must be a mapping.")
    return data


def _bool(value):
    return value if isinstance(value, bool) else None


def _count(value):
    return len(value) if isinstance(value, (list, dict)) else 0


def resolver_summary(value):
    """Classify syntax only; do not report hosts, URLs, fragments, or credentials."""
    result = {key: 0 for key in ("https", "tls", "quic", "plain_ip", "system", "other")}
    entries = value if isinstance(value, list) else []
    for entry in entries:
        kind = "other"
        if isinstance(entry, str):
            text = entry.lower()
            if text.startswith("https://"):
                kind = "https"
            elif text.startswith("tls://"):
                kind = "tls"
            elif text.startswith("quic://"):
                kind = "quic"
            elif text == "system" or text.startswith("dhcp://"):
                kind = "system"
            else:
                try:
                    ipaddress.ip_address(entry)
                    kind = "plain_ip"
                except ValueError:
                    pass
        result[kind] += 1
    return {"entry_count": len(entries), "syntax_counts": result}


def summarize(config):
    dns = config.get("dns") if isinstance(config.get("dns"), dict) else {}
    tun = config.get("tun") if isinstance(config.get("tun"), dict) else {}
    sniffer = config.get("sniffer") if isinstance(config.get("sniffer"), dict) else {}
    mode = dns.get("enhanced-mode")
    return {
        "tun": {"present": "tun" in config, "enabled": _bool(tun.get("enable"))},
        "dns": {
            "present": "dns" in config,
            "enabled": _bool(dns.get("enable")),
            "ipv6": _bool(dns.get("ipv6")),
            "respect_rules": _bool(dns.get("respect-rules")),
            "enhanced_mode": mode if mode in ("fake-ip", "redir-host") else "unspecified_or_other",
            "resolvers": {
                key: resolver_summary(dns.get(key))
                for key in (
                    "nameserver", "fallback", "default-nameserver",
                    "proxy-server-nameserver", "direct-nameserver",
                )
            },
            "nameserver_policy_count": _count(dns.get("nameserver-policy")),
        },
        "sniffer": {"present": "sniffer" in config, "enabled": _bool(sniffer.get("enable"))},
        "proxy_count": _count(config.get("proxies")),
        "proxy_group_count": _count(config.get("proxy-groups")),
        "proxy_provider_count": _count(config.get("proxy-providers")),
        "rule_count": _count(config.get("rules")),
    }


def _equal_field(left, right, key, preserve_object_order=False):
    return (key in left) == (key in right) and _same(
        left.get(key), right.get(key), preserve_object_order=preserve_object_order
    )


def _same(left, right, preserve_object_order=False):
    # Python considers True == 1; those are different configuration values.
    return json.dumps(left, sort_keys=not preserve_object_order) == json.dumps(
        right, sort_keys=not preserve_object_order
    )


def _process_rule(rule):
    if not isinstance(rule, str):
        return None
    fields = [part.strip() for part in rule.split(",")]
    return fields if len(fields) == 3 and fields[0] == "PROCESS-NAME" else None


def compare_configs(baseline, candidate, allow_process=(), allow_outbound=()):
    processes, outbounds = set(allow_process), set(allow_outbound)
    before, after = baseline.get("rules", []), candidate.get("rules", [])
    rules_ok = (
        ("rules" in baseline) == ("rules" in candidate)
        and isinstance(before, list) and isinstance(after, list) and len(before) == len(after)
    )
    allowed_changes = 0
    if rules_ok:
        for old, new in zip(before, after):
            if _same(old, new):
                continue
            old_fields, new_fields = _process_rule(old), _process_rule(new)
            permitted = (
                old_fields is not None and new_fields is not None
                and old_fields[1] in processes and new_fields[1] == old_fields[1]
                and old_fields[2] == "DIRECT" and new_fields[2] in outbounds
            )
            if permitted:
                allowed_changes += 1
            else:
                rules_ok = False
    old_nodes, new_nodes = baseline.get("proxies", []), candidate.get("proxies", [])
    nodes_ok = (
        isinstance(old_nodes, list) and isinstance(new_nodes, list)
        and len(new_nodes) >= len(old_nodes) and _same(new_nodes[:len(old_nodes)], old_nodes)
    )
    excluded = {"tun", "dns", "sniffer", "rules", "proxies", "proxy-groups", "proxy-providers"}
    checks = {
        "tun_unchanged": _equal_field(baseline, candidate, "tun"),
        "existing_proxy_objects_and_order_preserved": nodes_ok,
        "proxy_groups_unchanged": _equal_field(baseline, candidate, "proxy-groups"),
        "proxy_providers_unchanged": _equal_field(baseline, candidate, "proxy-providers"),
        "unrelated_rules_and_rule_order_preserved": rules_ok,
        "other_configuration_unchanged": _same(
            {key: value for key, value in baseline.items() if key not in excluded},
            {key: value for key, value in candidate.items() if key not in excluded},
        ),
    }
    return {
        "preservation_checks": checks,
        "preservation_checks_passed": all(checks.values()),
        "allowed_process_rule_changes": allowed_changes,
        "added_proxy_count": len(new_nodes) - len(old_nodes) if nodes_ok else None,
        # Policy mappings can use first-match precedence. Keep ordering throughout
        # the DNS tree to cover supported policy variants without a stale key list.
        # This deliberately also reports harmless DNS mapping reordering for review.
        "dns_changed": not _equal_field(baseline, candidate, "dns", preserve_object_order=True),
        "dns_comparison": "Values and mapping order throughout the DNS tree; even harmless mapping reordering is conservatively reported.",
        "sniffer_changed": not _equal_field(baseline, candidate, "sniffer"),
        "review_required": "Inspect every DNS, sniffer, and added-proxy change separately; preservation is not an approval or a connectivity test.",
    }


def compare_equivalence(baseline, candidate):
    """Compare every field without reporting source keys, values, or differences.

    Unlike preservation checks, this allows no DNS, sniffer, rule, or proxy changes.
    DNS mapping order is retained conservatively; other mapping order is ignored.
    """
    fields = ("tun", "dns", "sniffer", "rules", "proxies", "proxy-groups", "proxy-providers")
    checks = {
        key.replace("-", "_") + "_equal": _equal_field(
            baseline, candidate, key, preserve_object_order=key == "dns"
        )
        for key in fields
    }
    checks["other_configuration_equal"] = _same(
        {key: value for key, value in baseline.items() if key not in fields},
        {key: value for key, value in candidate.items() if key not in fields},
    )
    return {
        "equivalence_checks": checks,
        "configuration_equivalent": all(checks.values()),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", help="Baseline JSON or optional YAML configuration")
    parser.add_argument("--compare", metavar="CANDIDATE")
    parser.add_argument(
        "--require-equivalent", action="store_true",
        help="Require every field to match --compare; allowlists do not permit differences",
    )
    parser.add_argument("--allow-process", action="append", default=[], metavar="NAME")
    parser.add_argument("--allow-outbound", action="append", default=[], metavar="NAME")
    args = parser.parse_args(argv)
    if args.require_equivalent and not args.compare:
        parser.error("--require-equivalent requires --compare")
    try:
        baseline = load_config(args.config)
        result = {
            "schema_version": 1,
            "offline_only": True,
            "dns_leak_status": "not_tested",
            "limitations": "Resolver syntax and configuration differences cannot prove DNS routing, encryption on the wire, or absence of leaks.",
            "baseline": summarize(baseline),
        }
        passed = True
        if args.compare:
            candidate = load_config(args.compare)
            result["candidate"] = summarize(candidate)
            result["comparison"] = compare_configs(
                baseline, candidate, args.allow_process, args.allow_outbound
            )
            passed = result["comparison"]["preservation_checks_passed"]
            if args.require_equivalent:
                result["equivalence"] = compare_equivalence(baseline, candidate)
                passed = result["equivalence"]["configuration_equivalent"]
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0 if passed else 2
    except AuditError as exc:
        # AuditError messages are fixed, source-independent text. Never print the
        # original parser or filesystem exception, which can contain source secrets.
        print("error: " + str(exc), file=sys.stderr)
        return 2
    except RecursionError:
        print("error: Configuration nesting is too deep to audit safely.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
