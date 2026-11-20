import os, sys, subprocess, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bastion import engine
from bastion.library import LIBRARY


def cfg(rules, **settings):
    s = engine.normalize_settings(settings)
    return {"settings": s, "zones": [], "rules": [engine.normalize_rule(r) for r in rules]}


class Validation(unittest.TestCase):
    def test_ports(self):
        self.assertEqual(engine.ports_to_str(engine.parse_ports("80, 443 ,1000-2000")), "80,443,1000-2000")
        for bad in ("0", "70000", "abc", "10-5", "80;rm -rf"):
            with self.assertRaises(engine.ValidationError): engine.parse_ports(bad)

    def test_addrs(self):
        self.assertEqual([a for a, _ in engine.parse_addrs("192.168.1.5, 10.0.0.0/8, 1.1.1.1-1.1.1.9, ::1")],
                         ["192.168.1.5", "10.0.0.0/8", "1.1.1.1-1.1.1.9", "::1"])
        for bad in ("999.1.1.1", "1.1.1.1-::2", "x; drop"):
            with self.assertRaises(engine.ValidationError): engine.parse_addrs(bad)

    def test_injection_blocked(self):
        r = engine.normalize_rule({"name": 'a"; flush ruleset; "', "action": "block", "direction": "in"})
        self.assertNotIn('"', r["name"]); self.assertNotIn(";", r["name"])
        for k, v in (("app", 'C:\\x" & calc'), ("user", "root; id")):
            with self.assertRaises(engine.ValidationError): engine.normalize_rule({k: v})
        with self.assertRaises(engine.ValidationError): engine.normalize_rule({"protocol": "icmp", "local_ports": "80"})


class Linux(unittest.TestCase):
    def test_script(self):
        c = cfg([{"name": "web", "action": "allow", "direction": "in", "protocol": "tcp", "local_ports": "80,443", "remote_ip": "192.168.0.0/16"},
                 {"name": "ping", "action": "block", "direction": "in", "protocol": "icmp", "icmp_type": "8"},
                 {"name": "both", "action": "block", "direction": "both", "protocol": "any", "local_ports": "6881-6889"},
                 {"name": "v6", "action": "allow", "direction": "out", "protocol": "tcp", "remote_ip": "2001:db8::/32,10.0.0.0/8", "remote_ports": "443"}])
        out = engine.compile_linux(c)["script"]
        self.assertIn("ip saddr 192.168.0.0/16 tcp dport { 80, 443 } accept", out)
        self.assertIn("icmp type 8 drop", out)
        self.assertIn("tcp dport 6881-6889 drop", out); self.assertIn("udp dport 6881-6889 drop", out)
        self.assertIn("ip6 daddr 2001:db8::/32 tcp dport 443 accept", out)
        self.assertIn("ip daddr 10.0.0.0/8 tcp dport 443 accept", out)

    def test_order_preserved(self):
        c = cfg([{"name": "a", "action": "allow", "direction": "in", "protocol": "tcp", "local_ports": "22", "remote_ip": "10.0.0.0/8"},
                 {"name": "b", "action": "block", "direction": "in", "protocol": "tcp", "local_ports": "22"}])
        out = engine.compile_linux(c)["script"]
        self.assertLess(out.index("ip saddr 10.0.0.0/8 tcp dport 22 accept"), out.index("tcp dport 22 drop"))

    def test_app_rule_skipped_with_warning(self):
        c = cfg([{"name": "ff", "action": "allow", "direction": "out", "app": "C:\\a.exe"}])
        res = engine.compile_linux(c)
        self.assertTrue(res["warnings"]); self.assertIn("ignorée", list(res["status"].values())[0])

    def test_nft_syntax_all_library(self):
        rules = [e["rule"] for e in LIBRARY if e["os"] in (None, "linux")]
        for e in rules:
            if e["user"] in ("invite",): e = dict(e, user="root")
        rules = [dict(r, user=("root" if r["user"] else "")) for r in rules]
        script = engine.compile_linux(cfg(rules, stealth=True))["script"]
        self.check_nft(script)
        self.check_nft(engine.compile_linux(cfg(rules, stealth=False, policy_in="allow", policy_out="block"))["script"])

    def check_nft(self, script):
        try:
            p = subprocess.run(["nft", "-c", "-f", "-"], input=script, capture_output=True, text=True)
        except FileNotFoundError:
            self.skipTest("nft absent")
        if "Operation not permitted" in p.stderr or "Permission denied" in p.stderr:
            self.skipTest("nft non autorisé dans ce bac à sable")
        self.assertEqual(p.returncode, 0, p.stderr + "\n" + script)


class Mac(unittest.TestCase):
    R = staticmethod(lambda **k: dict({"name": "m", "action": "block", "direction": "both", "protocol": "any", "mac": "AA-BB-CC-DD-EE-FF"}, **k))

    def test_normalize_and_invalid(self):
        self.assertEqual(engine.normalize_rule(self.R())["mac"], "aa:bb:cc:dd:ee:ff")
        for bad in ("aa:bb", "zz:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff; drop"):
            with self.assertRaises(engine.ValidationError): engine.normalize_rule(self.R(mac=bad))
        with self.assertRaises(engine.ValidationError): engine.normalize_rule(self.R(remote_ip="1.2.3.4"))

    def test_linux_native_in_and_resolved_out(self):
        c = cfg([self.R(protocol="tcp", local_ports="22", direction="both")])
        res = lambda m: ["192.168.1.50"] if m == "aa:bb:cc:dd:ee:ff" else []
        out = engine.compile_linux(c, res)["script"]
        self.assertIn("ether saddr aa:bb:cc:dd:ee:ff tcp dport 22 drop", out)
        self.assertIn("ip daddr 192.168.1.50 tcp sport 22 drop", out)
        self.check_nft(out)

    def test_linux_out_unresolved_is_reported(self):
        c = cfg([self.R(direction="out")])
        res = engine.compile_linux(c, lambda m: [])
        self.assertTrue(res["warnings"])

    def test_windows_resolves_to_ip(self):
        c = cfg([self.R()])
        r = engine.compile_windows(c, lambda m: ["192.168.1.50"])
        adds = [" ".join(x["args"]) for x in r["commands"] if "add" in x["args"]]
        self.assertTrue(any("remoteip=192.168.1.50" in a and "dir=in" in a for a in adds))
        self.assertTrue(any("remoteip=192.168.1.50" in a and "dir=out" in a for a in adds))
        self.assertTrue(r["warnings"])

    def check_nft(self, script):
        p = subprocess.run(["nft", "-c", "-f", "-"], input=script, capture_output=True, text=True)
        if "Operation not permitted" in p.stderr or "not found" in p.stderr.lower() and p.returncode == 127:
            self.skipTest("nft indisponible")
        self.assertEqual(p.returncode, 0, p.stderr)


class Windows(unittest.TestCase):
    def test_netsh(self):
        c = cfg([{"name": "ff", "action": "allow", "direction": "out", "protocol": "tcp", "remote_ports": "80,443", "app": "C:\\Program Files\\Mozilla Firefox\\firefox.exe"},
                 {"name": "ping", "action": "block", "direction": "in", "protocol": "icmp", "icmp_type": "8"},
                 {"name": "both", "action": "block", "direction": "both", "protocol": "any", "local_ports": "6881-6889"}])
        res = engine.compile_windows(c)
        adds = [x["args"] for x in res["commands"] if x["args"][:4] == ["advfirewall", "firewall", "add", "rule"]]
        flat = [" ".join(a) for a in adds]
        self.assertTrue(any("dir=out action=allow protocol=TCP" in f and "remoteport=80,443" in f and "program=C:\\Program Files\\Mozilla Firefox\\firefox.exe" in f for f in flat))
        self.assertTrue(any("protocol=icmpv4:8,any" in f and "dir=in" in f for f in flat))
        self.assertEqual(sum("localport=6881-6889" in f for f in flat), 4)  # in/out x tcp/udp
        self.assertTrue(res["warnings"])  # allow + block coexistent

    def test_policy(self):
        c = cfg([], policy_in="block", policy_out="block")
        args = [x["args"] for x in engine.compile_windows(c)["commands"]]
        self.assertIn(["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"], args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
