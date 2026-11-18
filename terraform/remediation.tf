# Phase 2: auto-remediation Lambdas

variable "remediation_dry_run" {
  description = "When true, remediation Lambdas only report what they would change"
  type        = bool
  default     = true
}

data "aws_caller_identity" "remediation" {}

data "aws_sns_topic" "alerts" {
  name = "cloudsentinel-alerts"
}

# ---------- Security group auto-fix (T1562.007) ----------

data "archive_file" "sg_remediate" {
  type        = "zip"
  source_file = "${path.module}/../lambdas/sg_remediate.py"
  output_path = "${path.module}/build/sg_remediate.zip"
}

resource "aws_iam_role" "sg_remediate" {
  name = "cloudsentinel-sg-remediate"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "sg_remediate" {
  name = "least-privilege"
  role = aws_iam_role.sg_remediate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadGroups"
        Effect   = "Allow"
        Action   = "ec2:DescribeSecurityGroups"
        Resource = "*"
      },
      {
        Sid      = "CloseOpenRules"
        Effect   = "Allow"
        Action   = "ec2:RevokeSecurityGroupIngress"
        Resource = "arn:aws:ec2:${var.region}:${data.aws_caller_identity.remediation.account_id}:security-group/*"
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
        Resource = "${aws_cloudwatch_log_group.sg_remediate.arn}:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "sg_remediate" {
  name              = "/aws/lambda/cloudsentinel-sg-remediate"
  retention_in_days = 7
}

resource "aws_lambda_function" "sg_remediate" {
  function_name    = "cloudsentinel-sg-remediate"
  role             = aws_iam_role.sg_remediate.arn
  runtime          = "python3.12"
  handler          = "sg_remediate.handler"
  filename         = data.archive_file.sg_remediate.output_path
  source_code_hash = data.archive_file.sg_remediate.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      TOPIC_ARN = data.aws_sns_topic.alerts.arn
      DRY_RUN   = var.remediation_dry_run ? "true" : "false"
    }
  }

  depends_on = [aws_cloudwatch_log_group.sg_remediate]
}

resource "aws_cloudwatch_event_target" "sg_remediate" {
  rule      = aws_cloudwatch_event_rule.detection["sg-open-to-world"].name
  target_id = "sg-remediate"
  arn       = aws_lambda_function.sg_remediate.arn
}

resource "aws_lambda_permission" "sg_remediate" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sg_remediate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.detection["sg-open-to-world"].arn
}
