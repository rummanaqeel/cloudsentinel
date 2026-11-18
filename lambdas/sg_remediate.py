"""Auto-remediation: remove world-open ingress rules from a security group.

Triggered by the sg-open-to-world EventBridge rule. Removes any ingress rule
open to 0.0.0.0/0 or ::/0 on the affected group, unless the group is tagged
cloudsentinel:allow-public=true. Set DRY_RUN=true to report without changing.
"""
import os
import boto3

ec2 = boto3.client("ec2")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"]
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"
ALLOW_TAG = "cloudsentinel:allow-public"


def notify(subject, lines):
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message="\n".join(lines))


def handler(event, context):
    detail = event["detail"]
    params = detail.get("requestParameters") or {}
    group_id = params.get("groupId")
    actor = detail.get("userIdentity", {}).get("arn", "unknown")

    if group_id:
        groups = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    else:
        groups = ec2.describe_security_groups(GroupNames=[params["groupName"]])["SecurityGroups"]
    sg = groups[0]
    group_id = sg["GroupId"]

    tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
    if tags.get(ALLOW_TAG) == "true":
        notify(f"[CloudSentinel][SKIPPED] {group_id} is allowlisted",
               [f"Group {group_id} has tag {ALLOW_TAG}=true, so no change was made.",
                f"Actor: {actor}"])
        return {"status": "skipped", "group": group_id}

    to_revoke = []
    for perm in sg.get("IpPermissions", []):
        v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
        v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
        if not (v4 or v6):
            continue
        if perm.get("FromPort") == 443:
            continue
        rule = {k: perm[k] for k in ("IpProtocol", "FromPort", "ToPort") if k in perm}
        if v4:
            rule["IpRanges"] = [{"CidrIp": "0.0.0.0/0"}]
        if v6:
            rule["Ipv6Ranges"] = [{"CidrIpv6": "::/0"}]
        to_revoke.append(rule)

    if not to_revoke:
        return {"status": "nothing-open", "group": group_id}

    ports = ", ".join(
        f"{r['IpProtocol']}:{r.get('FromPort', 'all')}-{r.get('ToPort', 'all')}" for r in to_revoke
    )

    if DRY_RUN:
        notify(f"[CloudSentinel][DRY-RUN] Would close {group_id}",
               [f"Would remove world-open rules on {group_id}: {ports}", f"Actor: {actor}"])
        return {"status": "dry-run", "group": group_id}

    ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=to_revoke)
    notify(f"[CloudSentinel][AUTO-FIXED] Closed {group_id}",
           [f"Removed world-open ingress on {group_id}: {ports}",
            f"Actor who opened it: {actor}",
            "Fixed automatically by cloudsentinel-sg-remediate (T1562.007)."])
    return {"status": "fixed", "group": group_id, "removed": ports}
