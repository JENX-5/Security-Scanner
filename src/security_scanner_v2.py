"""Milestone 2 AWS security scanner.

Checks one AWS Region for risky security groups, unencrypted EBS volumes,
and public or unencrypted RDS instances. It also checks account S3 buckets
for public bucket policies. The scanner never modifies AWS resources.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def make_finding(account_id, region, service, resource_id, rule_id, severity,
                 description, evidence, recommendation, timestamp):
    identity = f"{account_id}:{region}:{service}:{resource_id}:{rule_id}"
    return {
        "finding_id": hashlib.sha256(identity.encode()).hexdigest()[:24],
        "account_id": account_id,
        "region": region,
        "service": service,
        "resource_id": resource_id,
        "rule_id": rule_id,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "timestamp": timestamp,
        "status": "open",
    }


def check_security_group(group, account_id, region, timestamp):
    findings = []
    for port, label in ((22, "SSH"), (3389, "RDP")):
        exposed = set()
        for rule in group.get("IpPermissions", []):
            protocol = str(rule.get("IpProtocol", ""))
            if protocol not in ("-1", "tcp", "6"):
                continue
            if protocol != "-1" and not (
                rule.get("FromPort", -1) <= port <= rule.get("ToPort", -1)
            ):
                continue
            exposed.update(
                item["CidrIp"] for item in rule.get("IpRanges", [])
                if item.get("CidrIp") == "0.0.0.0/0"
            )
            exposed.update(
                item["CidrIpv6"] for item in rule.get("Ipv6Ranges", [])
                if item.get("CidrIpv6") == "::/0"
            )
        if exposed:
            findings.append(make_finding(
                account_id, region, "EC2", group["GroupId"],
                f"SG_UNRESTRICTED_{label}", "High",
                f"Security group allows {label} (TCP {port}) from anywhere.",
                {"port": port, "cidrs": sorted(exposed)},
                "Restrict the rule to approved IP ranges or use Systems Manager Session Manager.",
                timestamp,
            ))
    return findings


def check_volume(volume, account_id, region, timestamp):
    if volume.get("Encrypted", False):
        return []
    return [make_finding(
        account_id, region, "EBS", volume["VolumeId"],
        "EBS_VOLUME_UNENCRYPTED", "High",
        "EBS volume is not encrypted at rest.",
        {"size_gib": volume.get("Size"), "state": volume.get("State")},
        "Create an encrypted snapshot copy and replace the volume using an approved change process.",
        timestamp,
    )]


def check_db_instance(instance, account_id, region, timestamp):
    findings = []
    resource_id = instance["DBInstanceIdentifier"]
    if instance.get("PubliclyAccessible", False):
        findings.append(make_finding(
            account_id, region, "RDS", resource_id,
            "RDS_PUBLICLY_ACCESSIBLE", "High",
            "RDS instance is configured with a public endpoint.",
            {"engine": instance.get("Engine"), "publicly_accessible": True},
            "Set PubliclyAccessible to false and connect through private networking.",
            timestamp,
        ))
    if not instance.get("StorageEncrypted", False):
        findings.append(make_finding(
            account_id, region, "RDS", resource_id,
            "RDS_STORAGE_UNENCRYPTED", "High",
            "RDS instance storage is not encrypted at rest.",
            {"engine": instance.get("Engine"), "storage_encrypted": False},
            "Migrate to a new encrypted instance using an encrypted snapshot or service-supported migration.",
            timestamp,
        ))
    return findings


def check_s3_bucket(bucket_name, policy_public, public_access_block,
                    account_id, timestamp):
    if not policy_public:
        return []
    restrict_public = public_access_block.get("RestrictPublicBuckets")
    if restrict_public is True:
        return []
    return [make_finding(
        account_id, "global", "S3", bucket_name,
        "S3_PUBLIC_BUCKET_POLICY", "Critical",
        "S3 bucket policy is classified as public by AWS.",
        {
            "policy_is_public": True,
            "restrict_public_buckets": restrict_public,
        },
        "Remove public statements and enable all S3 Block Public Access settings.",
        timestamp,
    )]


def add_error(report, check_name, resource, error):
    report["errors"].append({
        "check": check_name,
        "resource": resource,
        "message": str(error),
    })


def scan_regional_services(session, report, account_id, region, timestamp,
                           client_error, boto_error, config):
    ec2 = session.client("ec2", config=config)
    try:
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for group in page.get("SecurityGroups", []):
                report["resources_scanned"]["security_groups"] += 1
                report["findings"].extend(
                    check_security_group(group, account_id, region, timestamp)
                )
    except (client_error, boto_error) as error:
        add_error(report, "security_groups", region, error)

    try:
        for page in ec2.get_paginator("describe_volumes").paginate():
            for volume in page.get("Volumes", []):
                report["resources_scanned"]["ebs_volumes"] += 1
                report["findings"].extend(
                    check_volume(volume, account_id, region, timestamp)
                )
    except (client_error, boto_error) as error:
        add_error(report, "ebs_volumes", region, error)

    rds = session.client("rds", config=config)
    try:
        for page in rds.get_paginator("describe_db_instances").paginate():
            for instance in page.get("DBInstances", []):
                report["resources_scanned"]["rds_instances"] += 1
                report["findings"].extend(
                    check_db_instance(instance, account_id, region, timestamp)
                )
    except (client_error, boto_error) as error:
        add_error(report, "rds_instances", region, error)


def scan_s3(session, report, account_id, timestamp, client_error, boto_error,
            config):
    s3 = session.client("s3", config=config)
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (client_error, boto_error) as error:
        add_error(report, "s3_list_buckets", "account", error)
        return

    for bucket in buckets:
        name = bucket["Name"]
        report["resources_scanned"]["s3_buckets"] += 1
        policy_public = False
        block = {}
        try:
            policy_public = s3.get_bucket_policy_status(
                Bucket=name, ExpectedBucketOwner=account_id
            ).get("PolicyStatus", {}).get("IsPublic", False)
        except client_error as error:
            code = error.response.get("Error", {}).get("Code", "")
            if code not in ("NoSuchBucketPolicy", "NoSuchBucket"):
                add_error(report, "s3_policy_status", name, error)
                continue
        except boto_error as error:
            add_error(report, "s3_policy_status", name, error)
            continue

        try:
            block = s3.get_public_access_block(
                Bucket=name, ExpectedBucketOwner=account_id
            ).get("PublicAccessBlockConfiguration", {})
        except client_error as error:
            code = error.response.get("Error", {}).get("Code", "")
            if code not in ("NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"):
                add_error(report, "s3_public_access_block", name, error)
                continue
        except boto_error as error:
            add_error(report, "s3_public_access_block", name, error)
            continue

        report["findings"].extend(
            check_s3_bucket(name, policy_public, block, account_id, timestamp)
        )


def run_scan(region, session=None):
    """Run all checks and return a structured report."""
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError

    timestamp = datetime.now(timezone.utc).isoformat()
    report = {
        "scan_time": timestamp,
        "region": region,
        "scan_status": "complete",
        "resources_scanned": {
            "security_groups": 0,
            "ebs_volumes": 0,
            "rds_instances": 0,
            "s3_buckets": 0,
        },
        "findings": [],
        "errors": [],
    }
    config = Config(
        retries={"max_attempts": 3, "mode": "standard"},
        connect_timeout=10,
        read_timeout=30,
    )
    try:
        session = session or boto3.Session(region_name=region)
        account_id = session.client("sts", config=config).get_caller_identity()["Account"]
        report["account_id"] = account_id
        scan_regional_services(
            session, report, account_id, region, timestamp,
            ClientError, BotoCoreError, config,
        )
        scan_s3(
            session, report, account_id, timestamp,
            ClientError, BotoCoreError, config,
        )
    except (ClientError, BotoCoreError) as error:
        add_error(report, "account_identity", "account", error)

    if report["errors"]:
        report["scan_status"] = "incomplete"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", required=True, help="Region such as eu-north-1")
    parser.add_argument("--output", default="findings-v2.json")
    args = parser.parse_args()

    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        parser.exit(1, "Install Boto3 first: python3 -m pip install --user boto3\n")

    report = run_scan(args.region)
    Path(args.output).write_text(
        json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8"
    )

    counts = {}
    for finding in report["findings"]:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    print(f"Scan status: {report['scan_status']}")
    print(f"Resources scanned: {sum(report['resources_scanned'].values())}")
    print(f"Findings: {len(report['findings'])} {counts}")
    print(f"Errors: {len(report['errors'])}")
    print(f"Report saved to {args.output}")
    if report["errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
