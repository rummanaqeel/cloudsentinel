# ---------- CloudTrail restart (T1562.008) ----------

data "archive_file" "trail_remediate" {
  type        = "zip"
  source_file = "${path.module}/../lambdas/trail_remediate.py"
  output_path = "${path.module}/build/trail_remediate.zip"
}

resource "aws_iam_role" "trail_remediate" {
  name = "cloudsentinel-trail-remediate"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "trail_remediate" {
  name = "least-privilege"
  role = aws_iam_role.trail_remediate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "RestartThisTrailOnly"
        Effect   = "Allow"
        Action   = ["cloudtrail:StartLogging", "cloudtrail:GetTrailStatus"]
        Resource = aws_cloudtrail.main.arn
      },
      {
        Sid      = "SendResult"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = data.aws_sns_topic.alerts.arn
      },
      {
        Sid      = "WriteLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.trail_remediate.arn}:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "trail_remediate" {
  name              = "/aws/lambda/cloudsentinel-trail-remediate"
  retention_in_days = 7
}

resource "aws_lambda_function" "trail_remediate" {
  function_name    = "cloudsentinel-trail-remediate"
  role             = aws_iam_role.trail_remediate.arn
  runtime          = "python3.12"
  handler          = "trail_remediate.handler"
  filename         = data.archive_file.trail_remediate.output_path
  source_code_hash = data.archive_file.trail_remediate.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      TOPIC_ARN = data.aws_sns_topic.alerts.arn
      TRAIL_ARN = aws_cloudtrail.main.arn
      DRY_RUN   = var.remediation_dry_run ? "true" : "false"
    }
  }

  depends_on = [aws_cloudwatch_log_group.trail_remediate]
}

resource "aws_cloudwatch_event_target" "trail_remediate" {
  rule      = aws_cloudwatch_event_rule.detection["cloudtrail-tampering"].name
  target_id = "trail-remediate"
  arn       = aws_lambda_function.trail_remediate.arn
}

resource "aws_lambda_permission" "trail_remediate" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.trail_remediate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detection["cloudtrail-tampering"].arn
}
