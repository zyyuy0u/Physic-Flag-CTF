"""Evaluate student rules against traffic cases; does not execute kernel iptables."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mode_switch", ROOT / "host/mode-switch/mode_switch.py")
mode_switch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mode_switch)


def verdict(rules, interface, protocol="tcp", source="192.168.50.10", sport="50000", dport="22", state="NEW"):
    """First-match model for the rule options used by HONEYPOT-INPUT."""
    packet = {"-i": interface, "-p": protocol, "-s": source, "--sport": sport, "--dport": dport}
    for rule in rules:
        match = True
        action = None
        for option, value in zip(rule[::2], rule[1::2]):
            if option in ("-A", "-m"):
                continue
            if option == "-j":
                action = value
            elif option == "--ctstate":
                match &= state in value.split(",")
            elif option == "-i" and value.endswith("+"):
                match &= interface.startswith(value[:-1])
            elif option in packet:
                match &= packet[option] == value
            else:
                raise AssertionError(f"Unsupported rule option: {option}")
        if match:
            return action
    return "RETURN"


class WifiFirewallTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.physical = ("wlan0", "wlx001122334455", "enp1s0")
        for name in (*self.physical, "lo", "docker0", "br-demo", "veth123"):
            (root / name).mkdir()
            if name in self.physical:
                (root / name / "device").mkdir()
        for target, value in (("NET_INTERFACES", root), ("_defense_container_ip", lambda: "172.20.0.3")):
            patcher = patch.object(mode_switch, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_dhcp_replies_work_on_physical_interfaces_in_both_families(self):
        for family, ports in (("iptables", ("67", "68")), ("ip6tables", ("547", "546"))):
            rules = mode_switch._student_rules(family)
            for interface in self.physical:
                with self.subTest(family=family, interface=interface):
                    self.assertEqual(verdict(rules, interface, "udp", sport=ports[0], dport=ports[1]), "ACCEPT")
                    # Do not admit arbitrary senders or invert client/server roles.
                    self.assertEqual(verdict(rules, interface, "udp", sport="12345", dport=ports[1]), "DROP")
                    self.assertEqual(verdict(rules, interface, "udp", sport=ports[1], dport=ports[0]), "DROP")
            for interface in ("docker0", "br-demo", "veth123"):
                self.assertEqual(verdict(rules, interface, "udp", sport=ports[0], dport=ports[1]), "DROP")

    def test_new_ssh_and_lan_gpio_remain_blocked_but_existing_ssh_survives(self):
        for family in ("iptables", "ip6tables"):
            rules = mode_switch._student_rules(family)
            for interface in self.physical:
                with self.subTest(family=family, interface=interface):
                    self.assertEqual(verdict(rules, interface, dport="22"), "DROP")
                    self.assertEqual(verdict(rules, interface, dport="8888"), "DROP")
                    self.assertEqual(verdict(rules, interface, dport="22", state="ESTABLISHED"), "ACCEPT")

    def test_only_defense_container_on_docker_bridge_can_reach_pigpio(self):
        rules = mode_switch._student_rules("iptables")
        self.assertEqual(verdict(rules, "br-demo", source="172.20.0.3", dport="8888"), "ACCEPT")
        self.assertEqual(verdict(rules, "br-demo", source="172.20.0.2", dport="8888"), "DROP")
        self.assertEqual(verdict(rules, "wlan0", source="172.20.0.3", dport="8888"), "DROP")


if __name__ == "__main__":
    unittest.main()
