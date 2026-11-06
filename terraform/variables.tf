variable "aws_region" {
  description = "AWS region for regional resources and scanning."
  type        = string
  default     = "eu-north-1"
}

variable "project_name" {
  description = "Prefix for project resources."
  type        = string
  default     = "cloud-compliance"
}

variable "alert_email" {
  description = "Email address that receives High and Critical finding alerts."
  type        = string
}

variable "schedule_expression" {
  description = "EventBridge schedule for automatic scans."
  type        = string
  default     = "rate(1 day)"
}
