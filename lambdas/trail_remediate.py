"""Auto-remediation: turn CloudTrail logging back on after StopLogging.

Triggered by the cloudtrail-tampering EventBridge rule. Acts only on
StopLogging against the CloudSentinel trail and calls StartLogging.
DeleteTrail, UpdateTrail and PutEventSelectors stay alert-only.
"""
import os
import boto3

cloudtrail = boto3.client("cloudtrail")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"]
TRAIL_ARN = os.environ["TRAIL_ARN"]
TRAIL_NAME = TRAIL_ARN.split("/")[-1]
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"


def notify(subject, lines):
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message="\n".join(lines))


def handler(event, context):
    detail = event["detail"]
    if detail.get("eventName") != "StopLogging":
        return {"status": "ignored", "event": detail.get("eventName")}

    target = (detail.get("requestParameters") or {}).get("name", "")
    if target not in (TRAIL_NAME, TRAIL_ARN):
        return {"status": "other-trail", "trail": target}

    actor = detail.get("userIdentity", {}).get("arn", "unknown")

    if DRY_RUN:
        notify(f"[CloudSentinel][DRY-RUN] Would restart {TRAIL_NAME}",
               [f"Would call StartLogging on {TRAIL_NAME}.", f"Actor who stopped it: {actor}"])
        return {"status": "dry-run", "trail": TRAIL_NAME}

    cloudtrail.start_logging(Name=TRAIL_ARN)
    logging_on = cloudtrail.get_trail_status(Name=TRAIL_ARN)["IsLogging"]
    notify(f"[CloudSentinel][AUTO-FIXED] Restarted {TRAIL_NAME}",
           [f"Logging was stopped on {TRAIL_NAME} and has been turned back on (IsLogging={logging_on}).",
            f"Actor who stopped it: {actor}",
            "Fixed automatically by cloudsentinel-trail-remediate (T1562.008)."])
    return {"status": "fixed", "trail": TRAIL_NAME, "is_logging": logging_on}
