"""Run: python -m unittest discover -s tests -v

Everything uses synthetic temporary inputs. Node.js enables generated-profile
behavior tests; those tests are explicitly skipped when Node is unavailable.
"""

import importlib.util
import ipaddress
import json
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = load_module("audit_mihomo")
builder = load_module("build_ipv4_exception")


def baseline():
    return {
        "tun": {"enable": True, "stack": "mixed", "dns-hijack": ["any:53"], "mtu": 1500},
        "dns": {"enable": True, "ipv6": False, "nameserver": ["https://resolver.example/dns-query"]},
        "proxies": [{"name": "Existing", "type": "socks5", "server": "proxy.example", "password": "SYNTHETIC_CREDENTIAL"}],
        "proxy-groups": [{"name": "Select", "type": "select", "proxies": ["Existing"]}],
        "proxy-providers": {"Example": {"url": "https://subscription.example/?token=SYNTHETIC_TOKEN"}},
        "rules": ["DOMAIN,unrelated.example,DIRECT", "PROCESS-NAME,ExampleApp.exe,DIRECT", "MATCH,Select"],
        "custom-unknown": {"path": "SYNTHETIC_PERSONAL_PATH", "preserve": [True, 3, None]},
    }


def profile():
    return builder.build_profile(
        ["ExampleApp.exe"], ["2001:db8::1", "2001:db8::3/128"], "TLS", [443], "Example-IPv4"
    )[0]


def run_profile(config, script=None):
    code = r"""
const fs = require('fs');
const vm = require('vm');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const context = {};
vm.createContext(context);
vm.runInContext(input.script, context);
try {
  const result = context.main(input.config);
  const again = context.main(result);
  process.stdout.write(JSON.stringify({ok:true, result, again, inputAfter:input.config}));
} catch (error) {
  process.stdout.write(JSON.stringify({ok:false, error:String(error.message), inputAfter:input.config}));
}
"""
    completed = subprocess.run(
        [shutil.which("node"), "-e", code],
        input=json.dumps({"script": script or profile(), "config": config}),
        text=True, capture_output=True, check=True,
    )
    return json.loads(completed.stdout)


class ComplementTests(unittest.TestCase):
    def test_exact_complement_size_disjointness_and_membership(self):
        excluded = {ipaddress.IPv6Address("2001:db8::1"), ipaddress.IPv6Address("2001:db8::3")}
        networks = [ipaddress.IPv6Network(value) for value in builder.ipv6_complement(excluded)]
        self.assertEqual(sum(network.num_addresses for network in networks), 2**128 - len(excluded))
        for left, right in zip(networks, networks[1:]):
            self.assertLess(int(left.broadcast_address), int(right.network_address))
        for address in excluded:
            self.assertFalse(any(address in network for network in networks))
        rng = random.Random(42)
        checks = [ipaddress.IPv6Address(value) for value in (0, 2**128 - 1)]
        checks += [ipaddress.IPv6Address(int(address) + delta) for address in excluded for delta in (-1, 1)]
        checks += [ipaddress.IPv6Address(rng.getrandbits(128)) for _ in range(100)]
        for address in checks:
            self.assertEqual(any(address in network for network in networks), address not in excluded)

    def test_rejects_subnets_non_ipv6_and_special_addresses(self):
        for value in ("2001:db8::/64", "192.0.2.1", "::1", "::", "ff02::1", "fe80::1%7", "::ffff:192.0.2.1"):
            with self.subTest(value=value), self.assertRaises(builder.BuildError):
                builder.parse_ipv6(value)

    def test_explicit_inputs_and_deterministic_output(self):
        script, _ = builder.build_profile(["ExampleApp.exe"], ["2001:db8::3", "2001:db8::1", "2001:db8::1"], "TLS", [443, 443], "Example-IPv4")
        self.assertEqual(script, profile())
        for args in (
            ([], ["2001:db8::1"], "TLS", [443], "Example-IPv4"),
            (["ExampleApp.exe"], [], "TLS", [443], "Example-IPv4"),
            (["ExampleApp.exe"], ["2001:db8::1"], "QUIC", [443], "Example-IPv4"),
            (["ExampleApp.exe"], ["2001:db8::1"], "TLS", [0], "Example-IPv4"),
            (["folder/ExampleApp.exe"], ["2001:db8::1"], "TLS", [443], "Example-IPv4"),
            (["ExampleApp.exe"], ["2001:db8::1"], "TLS", [443], "DIRECT"),
        ):
            with self.subTest(args=args), self.assertRaises(builder.BuildError):
                builder.build_profile(*args)

    def test_http_has_only_explicit_ports(self):
        script, _ = builder.build_profile(["ExampleApp.exe"], ["2001:db8::1"], "HTTP", [8080, 80], "Example-IPv4")
        start = script.index("const desired = ") + len("const desired = ")
        payload, _ = json.JSONDecoder().raw_decode(script[start:])
        self.assertEqual(payload["sniffer"]["sniff"], {"HTTP": {"ports": [80, 8080]}})

    def test_cli_documentation_warning_idempotent_write_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "example.js"
            command = [sys.executable, str(ROOT / "scripts/build_ipv4_exception.py"), "--process", "ExampleApp.exe", "--ipv6", "2001:db8::1", "--protocol", "TLS", "--port", "443", "--outbound", "Example-IPv4", "--output", str(output)]
            first = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("documentation examples", first.stderr)
            initial = output.read_bytes()
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertEqual(output.read_bytes(), initial)
            output.write_text("keep existing content", encoding="utf-8")
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep existing content")


class AuditTests(unittest.TestCase):
    def test_summary_redacts_secrets_addresses_names_and_paths(self):
        config = baseline()
        output = json.dumps(audit.summarize(config))
        for marker in ("SYNTHETIC_CREDENTIAL", "SYNTHETIC_TOKEN", "SYNTHETIC_PERSONAL_PATH", "proxy.example", "resolver.example", "subscription.example", "ExampleApp.exe", "Existing"):
            self.assertNotIn(marker, output)
        self.assertEqual(audit.summarize(config)["dns"]["resolvers"]["nameserver"]["syntax_counts"]["https"], 1)

    def test_dns_change_is_reported_without_implying_network_test(self):
        before, after = baseline(), baseline()
        after["dns"]["ipv6"] = True
        result = audit.compare_configs(before, after)
        self.assertTrue(result["preservation_checks_passed"])
        self.assertTrue(result["dns_changed"])

    def test_dns_policy_precedence_reordering_is_reported(self):
        for policy_key in ("nameserver-policy", "proxy-server-nameserver-policy"):
            with self.subTest(policy_key=policy_key):
                before, after = baseline(), baseline()
                before["dns"][policy_key] = {
                    "geosite:cn": ["https://regional.example/dns-query"],
                    "private.example": ["https://private-resolver.example/dns-query"],
                }
                after["dns"][policy_key] = dict(reversed(list(before["dns"][policy_key].items())))
                # A normal dict equality check misses the precedence change.
                self.assertEqual(before["dns"][policy_key], after["dns"][policy_key])
                result = audit.compare_configs(before, after)
                self.assertTrue(result["dns_changed"])
                self.assertTrue(result["preservation_checks_passed"])

    def test_nonpolicy_dns_mapping_reordering_is_conservatively_reported(self):
        before, after = baseline(), baseline()
        before["dns"]["fallback-filter"] = {"geoip": True, "geoip-code": "CN"}
        after["dns"]["fallback-filter"] = {"geoip-code": "CN", "geoip": True}
        self.assertTrue(audit.compare_configs(before, after)["dns_changed"])

    def test_ordinary_object_reordering_outside_dns_is_not_a_change(self):
        before, after = baseline(), baseline()
        for key in ("tun", "custom-unknown"):
            after[key] = dict(reversed(list(after[key].items())))
        after["proxies"][0] = dict(reversed(list(after["proxies"][0].items())))
        result = audit.compare_configs(before, after)
        self.assertTrue(result["preservation_checks_passed"])
        self.assertFalse(result["dns_changed"])

    def test_rejects_tun_node_rule_group_provider_and_unknown_changes(self):
        cases = [
            lambda value: value["tun"].update({"enable": False}),
            lambda value: value["tun"].update({"enable": 1}),
            lambda value: value["proxies"][0].update({"server": "different.example"}),
            lambda value: value["rules"].reverse(),
            lambda value: value["rules"].append("DOMAIN,new.example,DIRECT"),
            lambda value: value["proxy-groups"][0].update({"type": "fallback"}),
            lambda value: value["proxy-providers"]["Example"].update({"url": "https://different.example"}),
            lambda value: value["custom-unknown"].update({"preserve": False}),
        ]
        for mutate in cases:
            before, after = baseline(), baseline()
            mutate(after)
            self.assertFalse(audit.compare_configs(before, after)["preservation_checks_passed"])

    def test_only_allowlisted_process_and_outbound_changes(self):
        before, after = baseline(), baseline()
        after["rules"][1] = "PROCESS-NAME,ExampleApp.exe,Example-IPv4"
        self.assertFalse(audit.compare_configs(before, after)["preservation_checks_passed"])
        self.assertFalse(audit.compare_configs(before, after, ["ExampleApp.exe"])["preservation_checks_passed"])
        self.assertTrue(audit.compare_configs(before, after, ["ExampleApp.exe"], ["Example-IPv4"])["preservation_checks_passed"])
        after["rules"][0] = "DOMAIN,unrelated.example,Example-IPv4"
        self.assertFalse(audit.compare_configs(before, after, ["ExampleApp.exe"], ["Example-IPv4"])["preservation_checks_passed"])

    def test_rule_field_presence_change_is_reported(self):
        self.assertFalse(audit.compare_configs({}, {"rules": []})["preservation_checks_passed"])

    def test_json_input_duplicates_nonfinite_and_error_redaction(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "SYNTHETIC_PERSONAL_PATH.json"
            for text in ('{"dns":{},"dns":{}}', '{"value": NaN}', '{"value": Infinity}'):
                source.write_text(text, encoding="utf-8")
                with self.assertRaises(audit.AuditError):
                    audit.load_config(source)
            source.write_text('{"SYNTHETIC_TOKEN": invalid}', encoding="utf-8")
            result = subprocess.run([sys.executable, str(ROOT / "scripts/audit_mihomo.py"), str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("SYNTHETIC_TOKEN", result.stdout + result.stderr)
            self.assertNotIn("SYNTHETIC_PERSONAL_PATH", result.stdout + result.stderr)
            source.write_text(json.dumps(baseline()), encoding="utf-8")
            result = subprocess.run([sys.executable, str(ROOT / "scripts/audit_mihomo.py"), str(source)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)["dns_leak_status"], "not_tested")

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "optional PyYAML not installed")
    def test_yaml_loading_rejects_duplicates_and_recursive_aliases(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "example.yaml"
            source.write_text("tun:\n  enable: true\nrules: []\n", encoding="utf-8")
            self.assertTrue(audit.load_config(source)["tun"]["enable"])
            for text in ("dns: {}\ndns: {}\n", "a: &a\n  self: *a\n"):
                source.write_text(text, encoding="utf-8")
                with self.assertRaises(audit.AuditError):
                    audit.load_config(source)

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "optional PyYAML not installed")
    def test_yaml_repeated_aliases_cannot_expand_exponentially(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "alias-example.yaml"
            source.write_text("first: &shared [x]\nsecond: *shared\n", encoding="utf-8")
            with self.assertRaisesRegex(audit.AuditError, "Repeated or recursive container aliases"):
                audit.load_config(source)
            # A sequence DAG expands during traversal/JSON serialization; a merge
            # DAG can expand earlier inside the YAML constructor. Bound both paths.
            for merge in (False, True):
                with self.subTest(merge=merge):
                    lines = ["a0: &a0 {x: 1}" if merge else "a0: &a0 [x]"]
                    for level in range(1, 11):
                        aliases = ", ".join(["*a" + str(level - 1)] * 10)
                        value = "{<<: [" + aliases + "]}" if merge else "[" + aliases + "]"
                        lines.append("a{0}: &a{0} {1}".format(level, value))
                    source.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    result = subprocess.run(
                        [sys.executable, str(ROOT / "scripts/audit_mihomo.py"), str(source)],
                        capture_output=True, text=True, timeout=3,
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("Repeated or recursive container aliases", result.stderr)
                    self.assertEqual(result.stdout, "")


class EquivalenceTests(unittest.TestCase):
    @staticmethod
    def run_audit(before, after, *options):
        with tempfile.TemporaryDirectory() as folder:
            source, candidate = Path(folder) / "baseline.json", Path(folder) / "candidate.json"
            source.write_text(json.dumps(before), encoding="utf-8")
            candidate.write_text(json.dumps(after), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(ROOT / "scripts/audit_mihomo.py"), str(source),
                 "--compare", str(candidate), *options],
                capture_output=True, text=True, timeout=5,
            )

    def test_identical_configurations_have_only_fixed_boolean_categories(self):
        result = audit.compare_equivalence(baseline(), baseline())
        expected = {
            "tun_equal", "dns_equal", "sniffer_equal", "rules_equal", "proxies_equal",
            "proxy_groups_equal", "proxy_providers_equal", "other_configuration_equal",
        }
        self.assertEqual(set(result), {"equivalence_checks", "configuration_equivalent"})
        self.assertEqual(set(result["equivalence_checks"]), expected)
        self.assertTrue(result["configuration_equivalent"])
        self.assertTrue(all(value is True for value in result["equivalence_checks"].values()))

    def test_every_configuration_category_can_fail_strict_cli_comparison(self):
        cases = [
            ("tun_equal", lambda value: value["tun"].update({"enable": False})),
            ("dns_equal", lambda value: value["dns"].update({"ipv6": True})),
            ("sniffer_equal", lambda value: value.update({"sniffer": {"enable": True}})),
            ("rules_equal", lambda value: value["rules"].reverse()),
            ("proxies_equal", lambda value: value["proxies"].append({"name": "Added", "type": "direct"})),
            ("proxy_groups_equal", lambda value: value["proxy-groups"][0].update({"type": "fallback"})),
            ("proxy_providers_equal", lambda value: value["proxy-providers"]["Example"].update({"url": "https://different.example"})),
            ("other_configuration_equal", lambda value: value["custom-unknown"].update({"preserve": False})),
        ]
        for category, mutate in cases:
            with self.subTest(category=category):
                before, after = baseline(), baseline()
                mutate(after)
                result = self.run_audit(before, after, "--require-equivalent")
                self.assertEqual(result.returncode, 2, result.stderr)
                comparison = json.loads(result.stdout)["equivalence"]
                self.assertFalse(comparison["configuration_equivalent"])
                self.assertEqual(
                    [key for key, equal in comparison["equivalence_checks"].items() if not equal],
                    [category],
                )

    def test_dns_mapping_order_is_preserved_at_every_depth(self):
        before = {"dns": {"enable": True, "ipv6": False}}
        after = {"dns": dict(reversed(list(before["dns"].items())))}
        self.assertFalse(audit.compare_equivalence(before, after)["configuration_equivalent"])
        for key in ("nameserver-policy", "proxy-server-nameserver-policy", "future-policy"):
            with self.subTest(key=key):
                values = {"regional.example": ["first"], "specific.example": ["second"]}
                before = {"dns": {key: values}}
                after = {"dns": {key: dict(reversed(list(values.items())))}}
                self.assertFalse(audit.compare_equivalence(before, after)["configuration_equivalent"])
        before = {"dns": {"future-options": [{"first": True, "second": False}]}}
        after = {"dns": {"future-options": [{"second": False, "first": True}]}}
        self.assertFalse(audit.compare_equivalence(before, after)["configuration_equivalent"])

    def test_other_mapping_order_is_ignored_including_root_and_nested_objects(self):
        def reverse_keys(value):
            if isinstance(value, dict):
                return {key: reverse_keys(item) for key, item in reversed(list(value.items()))}
            if isinstance(value, list):
                return [reverse_keys(item) for item in value]
            return value

        before = baseline()
        before["sniffer"] = {"enable": True, "sniff": {"TLS": {"ports": [443], "override-destination": False}}}
        after = {key: value if key == "dns" else reverse_keys(value)
                 for key, value in reversed(list(before.items()))}
        result = self.run_audit(before, after, "--require-equivalent")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["equivalence"]["configuration_equivalent"])

    def test_list_order_and_scalar_types_remain_significant(self):
        cases = [
            ({"dns": {"nameserver": ["first", "second"]}}, {"dns": {"nameserver": ["second", "first"]}}),
            ({"future": {"nested": [1, 2]}}, {"future": {"nested": [2, 1]}}),
            ({"tun": {"enable": True}}, {"tun": {"enable": 1}}),
            ({"dns": {"ipv6": False}}, {"dns": {"ipv6": 0}}),
            ({"future": [True]}, {"future": [1]}),
            ({"future": 1}, {"future": 1.0}),
        ]
        for before, after in cases:
            with self.subTest(before=before):
                self.assertFalse(audit.compare_equivalence(before, after)["configuration_equivalent"])

    def test_missing_null_and_empty_fields_are_distinct_in_both_directions(self):
        for key in ("tun", "dns", "sniffer", "rules", "proxies", "proxy-groups", "proxy-providers", "future"):
            for value in (None, {}, []):
                with self.subTest(key=key, value=value):
                    self.assertFalse(audit.compare_equivalence({}, {key: value})["configuration_equivalent"])
                    self.assertFalse(audit.compare_equivalence({key: value}, {})["configuration_equivalent"])
        for before, after in ((None, {}), (None, []), ({}, [])):
            self.assertFalse(audit.compare_equivalence({"future": before}, {"future": after})["configuration_equivalent"])
        self.assertFalse(audit.compare_equivalence({"future": {}}, {"future": {"nested": None}})["configuration_equivalent"])

    def test_strict_mode_rejects_changes_allowed_by_preservation_allowlists(self):
        before, after = baseline(), baseline()
        after["dns"]["ipv6"] = True
        after["sniffer"] = {"enable": True}
        after["proxies"].append({"name": "Example-IPv4", "type": "direct", "ip-version": "ipv4"})
        after["rules"][1] = "PROCESS-NAME,ExampleApp.exe,Example-IPv4"
        allowlists = ("--allow-process", "ExampleApp.exe", "--allow-outbound", "Example-IPv4")
        ordinary = self.run_audit(before, after, *allowlists)
        self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
        self.assertNotIn("equivalence", json.loads(ordinary.stdout))
        strict = self.run_audit(before, after, *allowlists, "--require-equivalent")
        self.assertEqual(strict.returncode, 2, strict.stderr)
        result = json.loads(strict.stdout)
        self.assertTrue(result["comparison"]["preservation_checks_passed"])
        self.assertFalse(result["equivalence"]["configuration_equivalent"])
        identical = self.run_audit(before, before, *allowlists, "--require-equivalent")
        self.assertEqual(identical.returncode, 0, identical.stderr)

    def test_cli_redacts_unknown_keys_secrets_and_changed_values(self):
        before, after = baseline(), baseline()
        before["SYNTHETIC_SECRET_FIELD"] = {"SYNTHETIC_PRIVATE_DOMAIN": "SYNTHETIC_OLD_SECRET"}
        after["SYNTHETIC_SECRET_FIELD"] = {"SYNTHETIC_PRIVATE_DOMAIN": "SYNTHETIC_NEW_SECRET"}
        result = self.run_audit(before, after, "--require-equivalent")
        self.assertEqual(result.returncode, 2, result.stderr)
        for marker in ("SYNTHETIC_SECRET_FIELD", "SYNTHETIC_PRIVATE_DOMAIN", "SYNTHETIC_OLD_SECRET",
                       "SYNTHETIC_NEW_SECRET", "SYNTHETIC_CREDENTIAL", "SYNTHETIC_TOKEN",
                       "SYNTHETIC_PERSONAL_PATH", "proxy.example", "subscription.example"):
            self.assertNotIn(marker, result.stdout + result.stderr)

    def test_require_equivalent_needs_compare_before_reading_input(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/audit_mihomo.py"),
             "SYNTHETIC_PERSONAL_PATH.json", "--require-equivalent"],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--require-equivalent requires --compare", result.stderr)
        self.assertNotIn("SYNTHETIC_PERSONAL_PATH", result.stderr)
        self.assertEqual(result.stdout, "")


@unittest.skipUnless(shutil.which("node"), "Node.js not installed; generated JS execution not verified")
class GeneratedProfileTests(unittest.TestCase):
    def test_idempotence_and_preservation_of_nodes_tun_dns_and_unknown_fields(self):
        original = baseline()
        execution = run_profile(original)
        self.assertTrue(execution["ok"])
        result = execution["result"]
        self.assertEqual(execution["inputAfter"], original)
        self.assertEqual(result, execution["again"])
        for key in ("tun", "dns", "proxy-groups", "proxy-providers", "custom-unknown"):
            self.assertEqual(result[key], original[key])
        self.assertEqual(result["proxies"][:-1], original["proxies"])
        self.assertEqual(result["proxies"][-1], {"name": "Example-IPv4", "type": "direct", "ip-version": "ipv4"})
        self.assertEqual(result["rules"][0], original["rules"][0])
        self.assertEqual(result["rules"][2], original["rules"][2])
        self.assertEqual(result["rules"][1], "PROCESS-NAME,ExampleApp.exe,Example-IPv4")
        comparison = audit.compare_configs(original, result, ["ExampleApp.exe"], ["Example-IPv4"])
        self.assertTrue(comparison["preservation_checks_passed"])
        self.assertEqual(comparison["added_proxy_count"], 1)

    def test_sniffer_is_ip_and_tcp_port_scoped_not_process_scoped(self):
        sniffer = run_profile(baseline())["result"]["sniffer"]
        self.assertEqual(sniffer["sniff"], {"TLS": {"ports": [443]}})
        self.assertFalse(sniffer["force-dns-mapping"])
        self.assertTrue(sniffer["parse-pure-ip"])
        self.assertEqual(sniffer["force-domain"], [])
        self.assertEqual(sniffer["skip-domain"], [])
        networks = [ipaddress.ip_network(value) for value in sniffer["skip-dst-address"]]
        self.assertIn(ipaddress.IPv4Network("0.0.0.0/0"), networks)
        self.assertEqual(sum(net.num_addresses for net in networks if net.version == 6), 2**128 - 2)

    def test_existing_sniffer_conflict_fails_without_mutation(self):
        config = baseline()
        config["sniffer"] = {"enable": False, "sniff": {"HTTP": {"ports": [80]}}}
        execution = run_profile(config)
        self.assertFalse(execution["ok"])
        self.assertIn("existing sniffer conflicts", execution["error"])
        self.assertEqual(execution["inputAfter"], config)

    def test_missing_conflicting_or_unsupported_process_rule_fails(self):
        for rule in ("PROCESS-NAME,Other.exe,DIRECT", "PROCESS-NAME,ExampleApp.exe,Select", "PROCESS-NAME,ExampleApp.exe,DIRECT,no-resolve"):
            config = baseline()
            config["rules"][1] = rule
            execution = run_profile(config)
            self.assertFalse(execution["ok"])
            self.assertEqual(execution["inputAfter"], config)

    def test_every_explicit_process_must_have_a_rule(self):
        script, _ = builder.build_profile(["ExampleApp.exe", "AnotherApp.exe"], ["2001:db8::1"], "TLS", [443], "Example-IPv4")
        self.assertFalse(run_profile(baseline(), script)["ok"])
        config = baseline()
        config["rules"].insert(2, "PROCESS-NAME,AnotherApp.exe,DIRECT")
        execution = run_profile(config, script)
        self.assertTrue(execution["ok"])
        self.assertEqual(execution["result"]["rules"][1:3], ["PROCESS-NAME,ExampleApp.exe,Example-IPv4", "PROCESS-NAME,AnotherApp.exe,Example-IPv4"])

    def test_proxy_and_group_name_collisions_fail_without_mutation(self):
        for key, entry in (
            ("proxies", {"name": "Example-IPv4", "type": "socks5", "server": "existing.example"}),
            ("proxy-groups", {"name": "Example-IPv4", "type": "select", "proxies": ["Existing"]}),
        ):
            config = baseline()
            config[key].append(entry)
            execution = run_profile(config)
            self.assertFalse(execution["ok"])
            self.assertEqual(execution["inputAfter"], config)


if __name__ == "__main__":
    unittest.main()
