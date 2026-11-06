# Validation results

Validation date: 27 October 2026

## Automated tests

Command:

```bash
python3 -m unittest discover -s tests -v
```

Result: **23 tests passed**.

Covered behavior:

- IPv4 and IPv6 unrestricted security-group detection
- TCP ranges and all-protocol rules
- Stable finding identity and duplicate handling
- EBS and RDS encryption checks
- RDS public-access checks
- S3 public-policy checks
- Rejection of incomplete scan reports
- DynamoDB scan-record creation and finding storage
- Lambda success and failure behavior
- Alert message content
- Optional dashboard publication behavior

## Terraform

- `terraform fmt -check`: passed after formatting
- Configuration parse errors found in the first pass: corrected
- Provider-backed `terraform validate`: could not complete in the authoring workspace because outbound access to `registry.terraform.io` was unavailable

The included GitHub Actions workflow performs `terraform init` and `terraform validate` in an online runner.

## Report

- Format: A4 PDF
- Pages: 6
- Rendered to PNG for visual inspection
- Result: no clipped text, overlaps, or broken tables observed
