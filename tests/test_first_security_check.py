import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("starter", Path(__file__).parents[1] / "src/first_security_check.py")
starter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(starter)


class SecurityGroupChecks(unittest.TestCase):
    def inspect(self, rules):
        return starter.inspect_group({"GroupId": "sg-example", "IpPermissions": rules}, "123456789012", "ap-south-1", "2026-10-13T00:00:00Z")

    def test_world_ssh(self):
        result = self.inspect([{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
        self.assertEqual([f["rule_id"] for f in result], ["SG_UNRESTRICTED_SSH"])

    def test_ipv6_and_port_range(self):
        result = self.inspect([{"IpProtocol": "6", "FromPort": 3000, "ToPort": 4000, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
        self.assertEqual([f["rule_id"] for f in result], ["SG_UNRESTRICTED_RDP"])

    def test_all_protocols(self):
        self.assertEqual(len(self.inspect([{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])), 2)

    def test_restricted_or_irrelevant_rules(self):
        for rule in [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
            {"IpProtocol": "udp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        ]:
            self.assertEqual(self.inspect([rule]), [])

    def test_duplicates_and_stable_identity(self):
        rule = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        result = self.inspect([rule, rule])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["finding_id"], self.inspect([rule])[0]["finding_id"])

    def test_empty_group(self):
        self.assertEqual(self.inspect([]), [])


if __name__ == "__main__":
    unittest.main()
