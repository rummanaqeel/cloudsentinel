"""Auto-remediation: deactivate newly created IAM access keys.

Triggered by the iam-persistence EventBridge rule. Acts only on CreateAccessKey.
Sets the new key to Inactive (not deleted, so it can be re-enabled).
Users listed in ALLOWED_USERS (comma-separated) are skipped.
"""
import os
import boto3

iam = boto3.client("iam")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"]
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
ALLOWED = {u.strip() for u in os.environ.get("ALLOWED_USERS", "").split(",") if u.strip()}


def notify(subject, lines):
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message="\n".join(lines))


def handler(event, context):
    detail = event["detail"]
    if detail.get("eventName") != "CreateAccessKey":
        return {"status": "ignored", "event": detail.get("eventName")}

    key = (detail.get("responseElements") or {}).get("accessKey") or {}
    key_id = key.get("accessKeyId")
    user = key.get("userName")
    actor = detail.get("userIdentity", {}).get("arn", "unknown")

    if not key_id or not user:
        return {"status": "no-key-in-event"}

    if user in ALLOWED:
        notify(f"[CloudSentinel][SKIPPED] Key for {user} is allowlisted",
               [f"New key {key_id} for {user} was left active (allowlisted).", f"Actor: {actor}"])
        return {"status": "skipped", "user": user}

    if DRY_RUN:
        notify(f"[CloudSentinel][DRY-RUN] Would deactivate key for {user}",
               [f"Would set {key_id} for {user} to Inactive.", f"Actor: {actor}"])
        return {"status": "dry-run", "user": user}

    iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
    notify(f"[CloudSentinel][AUTO-FIXED] Deactivated new key for {user}",
           [f"Set access key {key_id} for {user} to Inactive.",
            f"Actor who created it: {actor}",
            "Fixed automatically by cloudsentinel-key-remediate (T1098.001)."])
    return {"status": "fixed", "user": user, "key": key_id}
