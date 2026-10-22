locals {
  detections = {
    "cloudtrail-tampering" = {
      title    = "CloudTrail logging tampered"
      severity = "CRITICAL"
      mitre    = "T1562.008"
      pattern = {
        source        = ["aws.cloudtrail"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["cloudtrail.amazonaws.com"]
          eventName   = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
        }
      }
    }

    "root-activity" = {
      title    = "Root account used"
      severity = "HIGH"
      mitre    = "T1078.004"
      pattern = {
        "detail-type" = ["AWS Console Sign In via CloudTrail", "AWS API Call via CloudTrail"]
        detail = {
          userIdentity = { type = ["Root"] }
        }
      }
    }

    "sg-open-to-world" = {
      title    = "Security group opened to the internet"
      severity = "HIGH"
      mitre    = "T1562.007"
      pattern = {
        source        = ["aws.ec2"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["ec2.amazonaws.com"]
          eventName   = ["AuthorizeSecurityGroupIngress"]
          "$or" = [
            { requestParameters = { ipPermissions = { items = { ipRanges = { items = { cidrIp = ["0.0.0.0/0"] } } } } } },
            { requestParameters = { ipPermissions = { items = { ipv6Ranges = { items = { cidrIpv6 = ["::/0"] } } } } } },
          ]
        }
      }
    }

    "iam-persistence" = {
      title    = "IAM persistence activity"
      severity = "HIGH"
      mitre    = "T1098.001/T1136.003"
      pattern = {
        source        = ["aws.iam"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["iam.amazonaws.com"]
          eventName   = ["CreateUser", "CreateAccessKey", "CreateLoginProfile", "AttachUserPolicy", "PutUserPolicy", "AddUserToGroup"]
        }
      }
    }

    "s3-access-change" = {
      title    = "S3 bucket access configuration changed"
      severity = "MEDIUM"
      mitre    = "T1537"
      pattern = {
        source        = ["aws.s3"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail = {
          eventSource = ["s3.amazonaws.com"]
          eventName = [
            "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl",
            "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
          ]
        }
      }
    }
  }
}

resource "aws_cloudwatch_event_rule" "detection" {
  for_each = local.detections

  name          = "cloudsentinel-${each.key}"
  description   = "${each.value.title} (${each.value.mitre})"
  event_pattern = jsonencode(each.value.pattern)
}

resource "aws_cloudwatch_event_target" "to_sns" {
  for_each = local.detections

  rule      = aws_cloudwatch_event_rule.detection[each.key].name
  target_id = "sns-alert"
  arn       = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths = {
      api    = "$.detail.eventName"
      actor  = "$.detail.userIdentity.arn"
      ip     = "$.detail.sourceIPAddress"
      region = "$.detail.awsRegion"
      time   = "$.detail.eventTime"
    }
    input_template = "\"[CloudSentinel][${each.value.severity}] ${each.value.title} (${each.value.mitre}) | API: <api> | Actor: <actor> | Source IP: <ip> | Region: <region> | Time (UTC): <time>\""
  }
}
