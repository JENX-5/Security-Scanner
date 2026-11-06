import importlib
import os
import sys
import types
import unittest
from unittest.mock import Mock, patch


class LambdaHandlerTest(unittest.TestCase):
    def load_handler(self, report):
        fake_boto3 = types.ModuleType("boto3")
        fake_table = Mock()
        fake_boto3.resource = Mock(return_value=Mock(Table=Mock(return_value=fake_table)))

        fake_scanner = types.ModuleType("security_scanner_v2")
        fake_scanner.run_scan = Mock(return_value=report)
        fake_store = types.ModuleType("store_findings")
        fake_store.store_report = Mock(return_value={
            "scan_records": 1,
            "finding_records": len(report["findings"]),
            "new_findings": report["findings"],
        })

        modules = {
            "boto3": fake_boto3,
            "security_scanner_v2": fake_scanner,
            "store_findings": fake_store,
        }
        with patch.dict(sys.modules, modules):
            sys.modules.pop("lambda_function", None)
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
            try:
                handler = importlib.import_module("lambda_function")
            finally:
                sys.path.pop(0)
        return handler

    def test_complete_scan_is_stored(self):
        report = {
            "scan_status": "complete", "errors": [], "findings": [],
            "resources_scanned": {"security_groups": 1},
        }
        handler = self.load_handler(report)
        with patch.dict(os.environ, {"SCANNER_REGION": "eu-north-1", "FINDINGS_TABLE": "security-findings"}):
            result = handler.lambda_handler({}, None)
        self.assertEqual(result["scan_status"], "complete")
        self.assertEqual(result["resources_scanned"], 1)
        self.assertEqual(result["alerts_sent"], 0)
        self.assertFalse(result["dashboard_updated"])

    def test_incomplete_scan_raises(self):
        report = {
            "scan_status": "incomplete", "errors": [{"message": "denied"}],
            "findings": [], "resources_scanned": {},
        }
        handler = self.load_handler(report)
        with self.assertRaises(RuntimeError):
            handler.lambda_handler({}, None)

    def test_alert_message_contains_finding(self):
        finding = {
            "severity": "High", "rule_id": "TEST_RULE",
            "resource_id": "resource-test", "description": "Test issue",
            "recommendation": "Fix the test issue",
        }
        report = {
            "scan_status": "complete", "errors": [], "findings": [finding],
            "resources_scanned": {"security_groups": 1},
            "account_id": "123456789012", "region": "eu-north-1",
            "scan_time": "2026-10-18T00:00:00Z",
        }
        handler = self.load_handler(report)
        message = handler.build_alert_message([finding], report)
        self.assertIn("[High] TEST_RULE", message)
        self.assertIn("resource-test", message)


if __name__ == "__main__":
    unittest.main()
