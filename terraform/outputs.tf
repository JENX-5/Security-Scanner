output "dashboard_url" {
  description = "CloudFront URL for the private S3 dashboard."
  value       = "https://${aws_cloudfront_distribution.dashboard.domain_name}"
}

output "lambda_function_name" {
  value = aws_lambda_function.scanner.function_name
}

output "findings_table" {
  value = aws_dynamodb_table.findings.name
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
