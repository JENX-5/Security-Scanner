import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


path = Path(__file__).parents[1] / "src/store_findings.py"
spec = importlib.util.spec_from_file_location("store", path)
store = importlib.util.module_from_spec(spec)
spec.loader.exec_module(store)


class StoreFindingsTest(unittest.TestCase):
    def report(self):
        return {
            "scan_time": "2026-10-18T00:00:00Z",
            "scan_status": "complete",
            "resources_scanned": {"security_groups": 1},
            "findings": [],
            "errors": [],
            "account_id": "123456789012",
            "region": "eu-north-1",
        }

    def write_report(self, report):
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(report, handle)
        handle.close()
        self.addCleanup(Path(handle.name).unlink, missing_ok=True)
        return handle.name

    def test_loads_complete_report(self):
        report = self.report()
        self.assertEqual(store.load_report(self.write_report(report)), report)

    def test_rejects_incomplete_report(self):
        report = self.report()
        report["scan_status"] = "incomplete"
        with self.assertRaises(ValueError):
            store.load_report(self.write_report(report))

    def test_rejects_report_with_errors(self):
        report = self.report()
        report["errors"] = [{"message": "denied"}]
        with self.assertRaises(ValueError):
            store.load_report(self.write_report(report))

    def test_builds_clean_scan_record(self):
        item = store.build_scan_item(self.report())
        self.assertEqual(item["record_type"], "scan")
        self.assertEqual(item["finding_count"], 0)
        self.assertTrue(item["finding_id"].startswith("SCAN#"))

    def test_store_report_records_clean_scan(self):
        class Table:
            def __init__(self):
                self.items = []

            def put_item(self, Item):
                self.items.append(Item)

        table = Table()
        result = store.store_report(table, self.report())
        self.assertEqual(result["scan_records"], 1)
        self.assertEqual(result["new_findings"], [])
        self.assertEqual(len(table.items), 1)


if __name__ == "__main__":
    unittest.main()
