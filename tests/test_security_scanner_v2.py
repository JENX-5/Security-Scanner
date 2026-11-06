import importlib.util
from pathlib import Path
import unittest


path = Path(__file__).parents[1] / "src/security_scanner_v2.py"
spec = importlib.util.spec_from_file_location("scanner", path)
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class ScannerRulesTest(unittest.TestCase):
    account = "123456789012"
    region = "eu-north-1"
    timestamp = "2026-10-18T00:00:00Z"

    def test_security_group_world_ssh(self):
        group = {"GroupId": "sg-test", "IpPermissions": [{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }]}
        result = scanner.check_security_group(
            group, self.account, self.region, self.timestamp
        )
        self.assertEqual(result[0]["rule_id"], "SG_UNRESTRICTED_SSH")

    def test_restricted_security_group_is_clean(self):
        group = {"GroupId": "sg-test", "IpPermissions": [{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
        }]}
        self.assertEqual(scanner.check_security_group(
            group, self.account, self.region, self.timestamp
        ), [])

    def test_unencrypted_volume(self):
        result = scanner.check_volume(
            {"VolumeId": "vol-test", "Encrypted": False, "Size": 8},
            self.account, self.region, self.timestamp,
        )
        self.assertEqual(result[0]["rule_id"], "EBS_VOLUME_UNENCRYPTED")

    def test_encrypted_volume_is_clean(self):
        self.assertEqual(scanner.check_volume(
            {"VolumeId": "vol-test", "Encrypted": True},
            self.account, self.region, self.timestamp,
        ), [])

    def test_rds_rules(self):
        result = scanner.check_db_instance({
            "DBInstanceIdentifier": "db-test", "Engine": "postgres",
            "PubliclyAccessible": True, "StorageEncrypted": False,
        }, self.account, self.region, self.timestamp)
        self.assertEqual({item["rule_id"] for item in result}, {
            "RDS_PUBLICLY_ACCESSIBLE", "RDS_STORAGE_UNENCRYPTED"
        })

    def test_secure_rds_is_clean(self):
        self.assertEqual(scanner.check_db_instance({
            "DBInstanceIdentifier": "db-test",
            "PubliclyAccessible": False, "StorageEncrypted": True,
        }, self.account, self.region, self.timestamp), [])

    def test_public_s3_policy(self):
        result = scanner.check_s3_bucket(
            "bucket-test", True, {}, self.account, self.timestamp
        )
        self.assertEqual(result[0]["severity"], "Critical")

    def test_public_s3_policy_restricted_by_block_setting(self):
        self.assertEqual(scanner.check_s3_bucket(
            "bucket-test", True, {"RestrictPublicBuckets": True},
            self.account, self.timestamp,
        ), [])

    def test_private_s3_policy_is_clean(self):
        self.assertEqual(scanner.check_s3_bucket(
            "bucket-test", False, {}, self.account, self.timestamp
        ), [])


if __name__ == "__main__":
    unittest.main()
