variable "region" {
  description = "Home region. Must be us-east-1: IAM and root events only reach EventBridge there."
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Address that receives CloudSentinel alerts."
  type        = string
}

variable "log_retention_days" {
  description = "Days to keep CloudTrail logs in S3 before they expire."
  type        = number
  default     = 30
}
