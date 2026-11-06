"""Create the project DynamoDB table and store a completed scanner report.

Example:
  python3 store_findings.py findings-v2.json --region eu-north-1
"""

import argparse
import json
from pathlib import Path


DEFAULT_TABLE = "security-findings"


def load_report(path):
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    required = {"scan_time", "scan_status", "resources_scanned", "findings", "errors", "account_id"}
    missing = required - report.keys()
    if missing:
        raise ValueError(f"Report is missing fields: {', '.join(sorted(missing))}")
    if report["scan_status"] != "complete" or report["errors"]:
        raise ValueError("Refusing to store an incomplete scan as a valid result")
    return report


def build_scan_item(report):
    return {
        "finding_id": f"SCAN#{report['scan_time']}",
        "record_type": "scan",
        "scan_time": report["scan_time"],
        "account_id": report["account_id"],
        "region": report.get("region", "unknown"),
        "scan_status": report["scan_status"],
        "resources_scanned": report["resources_scanned"],
        "finding_count": len(report["findings"]),
        "error_count": len(report["errors"]),
    }


def ensure_table(dynamodb, table_name):
    table = dynamodb.Table(table_name)
    try:
        table.load()
        return table, False
    except dynamodb.meta.client.exceptions.ResourceNotFoundException:
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "finding_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
            SSESpecification={"Enabled": True},
            Tags=[{"Key": "Project", "Value": "cloud-compliance-scanner"}],
        )
        table.wait_until_exists()
        return table, True


def store_finding(table, finding):
    names = {
        "#rt": "record_type",
        "#account": "account_id",
        "#region": "region",
        "#service": "service",
        "#resource": "resource_id",
        "#rule": "rule_id",
        "#severity": "severity",
        "#description": "description",
        "#evidence": "evidence",
        "#recommendation": "recommendation",
        "#first": "first_seen",
        "#last": "last_seen",
        "#status": "finding_status",
    }
    values = {
        ":rt": "finding",
        ":account": finding["account_id"],
        ":region": finding["region"],
        ":service": finding["service"],
        ":resource": finding["resource_id"],
        ":rule": finding["rule_id"],
        ":severity": finding["severity"],
        ":description": finding["description"],
        ":evidence": finding["evidence"],
        ":recommendation": finding["recommendation"],
        ":first": finding["timestamp"],
        ":last": finding["timestamp"],
        ":status": finding.get("status", "open"),
    }
    table.update_item(
        Key={"finding_id": finding["finding_id"]},
        UpdateExpression=(
            "SET #rt=:rt, #account=:account, #region=:region, #service=:service, "
            "#resource=:resource, #rule=:rule, #severity=:severity, "
            "#description=:description, #evidence=:evidence, "
            "#recommendation=:recommendation, #first=if_not_exists(#first,:first), "
            "#last=:last, #status=:status"
        ),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def store_report(table, report):
    """Store one scan record and upsert every finding."""
    if report.get("scan_status") != "complete" or report.get("errors"):
        raise ValueError("Refusing to store an incomplete scan as a valid result")
    table.put_item(Item=build_scan_item(report))
    new_findings = []
    for finding in report["findings"]:
        existing = table.get_item(
            Key={"finding_id": finding["finding_id"]},
            ProjectionExpression="finding_id",
        ).get("Item")
        if not existing:
            new_findings.append(finding)
        store_finding(table, finding)
    return {
        "scan_records": 1,
        "finding_records": len(report["findings"]),
        "new_findings": new_findings,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="Path to a completed findings-v2.json report")
    parser.add_argument("--region", required=True, help="DynamoDB Region")
    parser.add_argument("--table", default=DEFAULT_TABLE)
    args = parser.parse_args()

    try:
        import boto3
    except ImportError:
        parser.exit(1, "Install Boto3 first: python3 -m pip install --user boto3\n")

    try:
        report = load_report(args.report)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.exit(1, f"Invalid report: {error}\n")

    session = boto3.Session(region_name=args.region)
    current_account = session.client("sts").get_caller_identity()["Account"]
    if current_account != str(report["account_id"]):
        parser.exit(1, "The report belongs to a different AWS account\n")

    dynamodb = session.resource("dynamodb")
    table, created = ensure_table(dynamodb, args.table)
    stored = store_report(table, report)

    print(f"Table: {args.table} ({'created' if created else 'already existed'})")
    print(f"Scan records stored: {stored['scan_records']}")
    print(f"Finding records stored: {stored['finding_records']}")
    print("Upload status: complete")


if __name__ == "__main__":
    main()
