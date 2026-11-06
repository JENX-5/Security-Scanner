# Deployment guide

## 1. Prerequisites

- An AWS account with account verification completed
- AWS CLI credentials for an IAM administrator used only for deployment
- Terraform 1.6 or newer
- Python 3.11 or newer

Use an IAM user or role for routine work. Avoid using the root user except for account-level tasks that require it.

## 2. Deploy

From the project root:

```bash
cd terraform
terraform init
terraform fmt -check
terraform validate
terraform apply
```

Enter the email address that should receive alerts when Terraform asks for `alert_email`. Review the plan, then type `yes`.

## 3. Confirm notifications

AWS sends an SNS confirmation email. Open it and choose **Confirm subscription**. Alerts cannot arrive until this is confirmed.

## 4. Run the first scan

In the AWS console:

1. Open Lambda.
2. Select the function whose name ends in `scanner`.
3. Open **Test**, create an event containing `{}`, and run it.
4. Confirm the result reports `scan_status: complete`.
5. Open DynamoDB and inspect the `security-findings` table.

EventBridge runs the function automatically every day after deployment.

## 5. Open the dashboard

Run:

```bash
terraform output -raw dashboard_url
```

Open the printed HTTPS address. CloudFront deployment can take several minutes.

## 6. Update the application

Edit the source or dashboard files, then run `terraform apply` again. Terraform rebuilds the Lambda archive and uploads dashboard assets.

## 7. Remove the demonstration environment

```bash
terraform destroy
```

Review the destruction plan and approve it. This removes the Lambda function, schedule, DynamoDB table, SNS topic, dashboard bucket, and CloudFront distribution created by this project.

## Troubleshooting

- **Access denied:** deploy with an IAM principal permitted to manage Lambda, IAM roles, EventBridge, DynamoDB, SNS, S3, CloudFront, and CloudWatch Logs.
- **No email:** confirm the SNS subscription and check the Lambda result for `alerts_sent`.
- **Dashboard unavailable:** wait for CloudFront deployment to finish and verify `dashboard-data.json` exists in the private S3 bucket.
- **Incomplete scan:** inspect the Lambda CloudWatch log. The scanner deliberately marks a scan incomplete when any required API call fails.
