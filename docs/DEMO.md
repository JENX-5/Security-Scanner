# Five-minute demonstration

1. Open the CloudFront dashboard and show the security score, resource coverage, and latest scan status.
2. Open the Lambda function and run a test event containing `{}`.
3. Show the successful Lambda result: resources scanned, finding count, DynamoDB records, and alert count.
4. Open the DynamoDB table and show the latest `SCAN#...` record.
5. Explain one rule: a security group allowing TCP 22 from `0.0.0.0/0` creates a High finding with a remediation recommendation.
6. Show the EventBridge schedule and explain that it triggers Lambda daily.
7. Show the confirmed SNS email subscription.
8. Show the Terraform files and GitHub Actions workflow to demonstrate infrastructure as code and continuous validation.

## Key explanation

The scanner reads AWS configuration through Boto3. Each rule produces a deterministic finding ID, so repeated scans update the same finding instead of creating duplicates. DynamoDB stores scan history and current findings. SNS alerts only for newly observed High or Critical findings. The dashboard is stored in a private S3 bucket and delivered through CloudFront.
