data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "cloudsentinel-trail"
  trail_arn  = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
}
