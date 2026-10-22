output "trail_name" {
  value = aws_cloudtrail.main.name
}

output "log_bucket" {
  value = aws_s3_bucket.trail.id
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "detection_rules" {
  value = [for r in aws_cloudwatch_event_rule.detection : r.name]
}
