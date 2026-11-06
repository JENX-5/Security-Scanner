"""AWS Lambda entry point for the cloud compliance scanner."""

import json
import os
from datetime import datetime, timezone

import boto3

from security_scanner_v2 import run_scan
from store_findings import store_report


ALERT_SEVERITIES = {"Critical", "High"}


def publish_dashboard(report):
    """Publish the latest completed scan as private dashboard data."""
    bucket = os.environ.get("DASHBOARD_BUCKET")
    if not bucket:
        return False
    payload = {
        "latest_scan": {
            "scan_time": report["scan_time"],
            "region": report["region"],
            "scan_status": report["scan_status"],
            "resources_scanned": report["resources_scanned"],
            "findings": report["findings"],
            "errors": report["errors"],
        },
        "scan_history": [{
            "scan_time": report["scan_time"],
            "scan_status": report["scan_status"],
            "finding_count": len(report["findings"]),
        }],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    boto3.client("s3", region_name=report["region"]).put_object(
        Bucket=bucket,
        Key="dashboard-data.json",
        Body=json.dumps(payload, default=str).encode("utf-8"),
        ContentType="application/json",
        CacheControl="no-store",
        ServerSideEncryption="AES256",
    )
    return True


def build_alert_message(findings, report):
    lines = [
        "AWS Security Compliance Scanner",
        "",
        f"Account: {report['account_id']}",
        f"Region: {report['region']}",
        f"Scan time: {report['scan_time']}",
        f"New High/Critical findings: {len(findings)}",
        "",
    ]
    for finding in findings:
        lines.extend([
            f"[{finding['severity']}] {finding['rule_id']}",
            f"Resource: {finding['resource_id']}",
            f"Description: {finding['description']}",
            f"Recommendation: {finding['recommendation']}",
            "",
        ])
    return "\n".join(lines)


def lambda_handler(event, context):
    region = os.environ.get("SCANNER_REGION") or os.environ.get("AWS_REGION", "eu-north-1")
    table_name = os.environ.get("FINDINGS_TABLE", "security-findings")

    report = run_scan(region)
    if report["scan_status"] != "complete":
        raise RuntimeError(json.dumps({
            "message": "Compliance scan incomplete",
            "errors": report["errors"],
        }, default=str))

    table = boto3.resource("dynamodb", region_name=region).Table(table_name)
    stored = store_report(table, report)
    dashboard_updated = publish_dashboard(report)
    new_alert_findings = [
        finding for finding in stored["new_findings"]
        if finding["severity"] in ALERT_SEVERITIES
    ]
    alerts_sent = 0
    if new_alert_findings:
        topic_arn = os.environ.get("ALERT_TOPIC_ARN")
        if not topic_arn:
            raise RuntimeError("ALERT_TOPIC_ARN is required when alertable findings exist")
        boto3.client("sns", region_name=region).publish(
            TopicArn=topic_arn,
            Subject=f"AWS security alert: {len(new_alert_findings)} new finding(s)",
            Message=build_alert_message(new_alert_findings, report),
        )
        alerts_sent = 1

    result = {
        "scan_status": report["scan_status"],
        "resources_scanned": sum(report["resources_scanned"].values()),
        "findings": len(report["findings"]),
        "scan_records_stored": stored["scan_records"],
        "finding_records_stored": stored["finding_records"],
        "new_alert_findings": len(new_alert_findings),
        "alerts_sent": alerts_sent,
        "dashboard_updated": dashboard_updated,
        "table": table_name,
    }
    print(json.dumps(result))
    return result
