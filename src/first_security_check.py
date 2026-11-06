"""First project milestone: inspect security groups without changing AWS resources.

Run in AWS CloudShell: python3 first_security_check.py --region ap-south-1
Requires boto3 (available in CloudShell): python3 -m pip install boto3
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def inspect_group(group, account_id, region, timestamp):
    """Flag world-accessible TCP SSH/RDP rules, including IPv6 and all protocols.

    A permissive security group is a configuration risk; actual reachability also
    depends on routing, public addresses, network ACLs, and attached resources.
    """
    findings = []
    permissions = group.get("IpPermissions", [])
    for port, label in ((22, "SSH"), (3389, "RDP")):
        exposed_cidrs = set()
        for rule in permissions:
            protocol = str(rule.get("IpProtocol", ""))
            if protocol not in ("-1", "tcp", "6"):
                continue
            if protocol != "-1":
                if not (rule.get("FromPort", -1) <= port <= rule.get("ToPort", -1)):
                    continue
            exposed_cidrs.update(
                item["CidrIp"] for item in rule.get("IpRanges", [])
                if item.get("CidrIp") == "0.0.0.0/0"
            )
            exposed_cidrs.update(
                item["CidrIpv6"] for item in rule.get("Ipv6Ranges", [])
                if item.get("CidrIpv6") == "::/0"
            )
        if exposed_cidrs:
            rule_id = f"SG_UNRESTRICTED_{label}"
            identity = f"{account_id}:{region}:{group['GroupId']}:{rule_id}"
            findings.append({
                "finding_id": hashlib.sha256(identity.encode()).hexdigest()[:24],
                "account_id": account_id,
                "region": region,
                "service": "EC2",
                "resource_id": group["GroupId"],
                "resource_name": group.get("GroupName", ""),
                "rule_id": rule_id,
                "severity": "High",
                "description": f"Inbound rules allow {label} (TCP {port}) from anywhere.",
                "evidence": {"port": port, "cidrs": sorted(exposed_cidrs)},
                "recommendation": "Restrict access to approved IP ranges, or use AWS Systems Manager Session Manager where appropriate.",
                "timestamp": timestamp,
                "status": "open",
            })
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", required=True, help="Region to inspect, e.g. ap-south-1")
    parser.add_argument("--output", default="findings.json")
    args = parser.parse_args()
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        parser.exit(1, "Install the AWS SDK first: python3 -m pip install boto3\n")

    timestamp = datetime.now(timezone.utc).isoformat()
    report = {"scan_time": timestamp, "region": args.region,
              "scan_status": "complete", "groups_scanned": 0,
              "findings": [], "errors": []}
    config = Config(retries={"max_attempts": 3, "mode": "standard"},
                    connect_timeout=10, read_timeout=30)
    try:
        session = boto3.Session(region_name=args.region)
        account_id = session.client("sts", config=config).get_caller_identity()["Account"]
        report["account_id"] = account_id
        ec2 = session.client("ec2", config=config)
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for group in page.get("SecurityGroups", []):
                report["findings"].extend(inspect_group(group, account_id, args.region, timestamp))
                report["groups_scanned"] += 1
    except (BotoCoreError, ClientError) as exc:
        report["scan_status"] = "incomplete"
        report["errors"].append(str(exc))

    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Scan status: {report['scan_status']}")
    print(f"Security groups inspected: {report['groups_scanned']}")
    print(f"High-severity findings: {len(report['findings'])}")
    print(f"Report saved to {args.output}")
    if report["errors"]:
        print("Scan incomplete. Check the report's errors; zero findings does not mean secure.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
