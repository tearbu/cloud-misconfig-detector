"""Evaluation core for the misconfiguration detector.

This module holds the rules and nothing else. It takes one
EventBridge event in the "AWS API Call via CloudTrail" shape and
returns a list of findings. It makes no AWS calls, reads no files,
and keeps no state, so the demo and the tests can run it anywhere
and the Lambda handler stays a thin shell around it.

A finding is a plain dict:

    rule_id     short stable id, e.g. "S3_PUBLIC_POLICY"
    severity    "critical", "high", or "medium"
    title       one line naming the problem
    account     AWS account id from the event envelope
    region      region the API call happened in
    resource    the bucket, group, policy, trail, or user involved
    actor       who made the call, from userIdentity
    event_name  the CloudTrail event name that triggered the rule
    event_time  when the call happened, from the envelope
    explanation plain language on why this is a problem
    remediation the concrete step that fixes it

Rules are written defensively. CloudTrail request shapes vary
between services and have changed over the years, so every rule
pulls its fields through helpers that accept the shapes I have
seen, and a rule that cannot read its event returns no finding
instead of raising. evaluate_event also guards each rule call, so
one bad event shape cannot take down the whole evaluation.
"""

import json
import urllib.parse

PUBLIC_PRINCIPAL_GROUPS = ("AllUsers", "AuthenticatedUsers")
OPEN_CIDRS = ("0.0.0.0/0", "::/0")
ADMIN_POLICY_ARN_SUFFIX = "policy/AdministratorAccess"
SENSITIVE_PORTS = (22, 3389)


# ------------------------------------------------------------------
# Shape helpers. CloudTrail wraps many lists as {"items": [...]} and
# policy documents arrive as JSON strings, sometimes URL encoded.
# ------------------------------------------------------------------

def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _items(node):
    """Return the list inside a CloudTrail {"items": [...]} wrapper,
    or the node itself when it is already a list."""
    if isinstance(node, dict) and "items" in node:
        return _as_list(node.get("items"))
    return _as_list(node)


def _parse_policy_document(raw):
    """Parse an IAM policy document from whatever shape it arrived
    in: dict, JSON string, or URL-encoded JSON string. Returns None
    when it cannot be read."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        return None
    for candidate in (raw, urllib.parse.unquote(raw)):
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _statements(document):
    if not isinstance(document, dict):
        return []
    return [s for s in _as_list(document.get("Statement")) if isinstance(s, dict)]


def _is_wildcard(value):
    return any(entry == "*" for entry in _as_list(value))


# ------------------------------------------------------------------
# Event field extraction
# ------------------------------------------------------------------

def _detail(event):
    if not isinstance(event, dict):
        return {}
    detail = event.get("detail")
    return detail if isinstance(detail, dict) else {}


def _request(detail):
    params = detail.get("requestParameters")
    return params if isinstance(params, dict) else {}


def _actor(detail):
    identity = detail.get("userIdentity")
    if not isinstance(identity, dict):
        return "unknown"
    return identity.get("arn") or identity.get("userName") or "unknown"


def _finding(event, detail, rule_id, severity, title, resource,
             explanation, remediation):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "account": event.get("account", "unknown"),
        "region": detail.get("awsRegion") or event.get("region", "unknown"),
        "resource": resource or "unknown",
        "actor": _actor(detail),
        "event_name": detail.get("eventName", "unknown"),
        "event_time": event.get("time") or detail.get("eventTime", "unknown"),
        "explanation": explanation,
        "remediation": remediation,
    }


# ------------------------------------------------------------------
# Rules
# ------------------------------------------------------------------

def _principal_is_public(principal):
    if principal == "*":
        return True
    if isinstance(principal, str):
        return any(group in principal for group in PUBLIC_PRINCIPAL_GROUPS)
    if isinstance(principal, dict):
        return any(_principal_is_public(value) for value in principal.values())
    if isinstance(principal, list):
        return any(_principal_is_public(value) for value in principal)
    return False


def rule_s3_public_policy(event, detail):
    """PutBucketPolicy that grants access to everyone."""
    if detail.get("eventName") != "PutBucketPolicy":
        return []
    request = _request(detail)
    document = _parse_policy_document(request.get("bucketPolicy"))
    for statement in _statements(document):
        if statement.get("Effect") != "Allow":
            continue
        if _principal_is_public(statement.get("Principal")):
            return [_finding(
                event, detail, "S3_PUBLIC_POLICY", "critical",
                "S3 bucket policy grants public access",
                request.get("bucketName"),
                "The new bucket policy allows access from any principal, "
                "which means anyone on the internet can use the permissions "
                "it grants on this bucket, no AWS account needed.",
                "Remove the public principal from the bucket policy, turn on "
                "S3 Block Public Access for the bucket, and grant access to "
                "named principals only.",
            )]
    return []


def _grantee_uris(node, found):
    """Walk an ACL structure collecting grantee URI and id strings."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key.lower() in ("uri", "id") and isinstance(value, str):
                found.append(value)
            else:
                _grantee_uris(value, found)
    elif isinstance(node, list):
        for entry in node:
            _grantee_uris(entry, found)


def rule_s3_public_acl(event, detail):
    """PutBucketAcl that grants a public group access to a bucket."""
    if detail.get("eventName") != "PutBucketAcl":
        return []
    request = _request(detail)
    uris = []
    _grantee_uris(request.get("accessControlPolicy"), uris)
    public = [uri for uri in uris
              if any(group in uri for group in PUBLIC_PRINCIPAL_GROUPS)]
    if not public:
        return []
    group = "AllUsers" if any("AllUsers" in uri for uri in public) \
        else "AuthenticatedUsers"
    return [_finding(
        event, detail, "S3_PUBLIC_ACL", "critical",
        "S3 bucket ACL grants public access",
        request.get("bucketName"),
        f"The bucket ACL grants the {group} group access. AllUsers means "
        "anyone on the internet; AuthenticatedUsers means anyone with any "
        "AWS account. Either way the bucket is no longer private.",
        "Remove the public group grant from the ACL, turn on S3 Block "
        "Public Access, and use a bucket policy with named principals for "
        "any access that is genuinely needed.",
    )]


def rule_sg_open_ingress(event, detail):
    """AuthorizeSecurityGroupIngress open to the whole internet."""
    if detail.get("eventName") != "AuthorizeSecurityGroupIngress":
        return []
    request = _request(detail)
    findings = []
    for permission in _items(request.get("ipPermissions")):
        if not isinstance(permission, dict):
            continue
        cidrs = [entry.get("cidrIp") for entry in
                 _items(permission.get("ipRanges")) if isinstance(entry, dict)]
        cidrs += [entry.get("cidrIpv6") for entry in
                  _items(permission.get("ipv6Ranges")) if isinstance(entry, dict)]
        open_cidrs = [cidr for cidr in cidrs if cidr in OPEN_CIDRS]
        if not open_cidrs:
            continue
        protocol = str(permission.get("ipProtocol", ""))
        from_port = permission.get("fromPort")
        to_port = permission.get("toPort")
        sensitive = protocol == "-1" or any(
            isinstance(from_port, int) and isinstance(to_port, int)
            and from_port <= port <= to_port for port in SENSITIVE_PORTS)
        if sensitive:
            severity = "critical"
            reach = "including SSH or RDP ports" if protocol != "-1" \
                else "on every port, because the rule allows all traffic"
        else:
            severity = "high"
            reach = f"on port {from_port}" if from_port is not None \
                else "for that protocol"
        findings.append(_finding(
            event, detail, "SG_OPEN_INGRESS", severity,
            "Security group ingress opened to the internet",
            request.get("groupId"),
            f"This rule lets any address on the internet reach the group, "
            f"{reach}. The sources are {', '.join(open_cidrs)}, which is "
            "every IPv4 or IPv6 address there is.",
            "Replace the open range with the specific source addresses "
            "that need access, and use a VPN, a bastion, or Systems "
            "Manager Session Manager instead of exposing admin ports.",
        ))
    return findings


def _document_is_wildcard_admin(document):
    for statement in _statements(document):
        if statement.get("Effect") != "Allow":
            continue
        if _is_wildcard(statement.get("Action")) and \
                _is_wildcard(statement.get("Resource")):
            return True
    return False


def rule_iam_wildcard_admin(event, detail):
    """An IAM policy granting every action on every resource, either
    written inline, created as a managed policy, or attached by
    pointing at the AWS AdministratorAccess policy."""
    event_name = detail.get("eventName")
    request = _request(detail)
    if event_name in ("CreatePolicy", "PutUserPolicy", "PutRolePolicy",
                      "PutGroupPolicy"):
        raw = request.get("policyDocument")
        if raw is None and event_name == "CreatePolicy":
            raw = request.get("policyDocument")
        if _document_is_wildcard_admin(_parse_policy_document(raw)):
            resource = (request.get("policyName") or request.get("userName")
                        or request.get("roleName") or request.get("groupName"))
            return [_finding(
                event, detail, "IAM_WILDCARD_ADMIN", "critical",
                "IAM policy grants full administrator access",
                resource,
                "The policy allows every action on every resource. Whoever "
                "holds it can read, change, or delete anything in the "
                "account, and can grant themselves any other permission.",
                "Rewrite the policy with only the actions and resources "
                "the work needs, and split broad permissions across "
                "separate policies so each one stays reviewable.",
            )]
        return []
    if event_name in ("AttachUserPolicy", "AttachRolePolicy",
                      "AttachGroupPolicy"):
        arn = request.get("policyArn") or ""
        if isinstance(arn, str) and arn.endswith(ADMIN_POLICY_ARN_SUFFIX):
            resource = (request.get("userName") or request.get("roleName")
                        or request.get("groupName"))
            return [_finding(
                event, detail, "IAM_WILDCARD_ADMIN", "critical",
                "AdministratorAccess policy attached",
                resource,
                "The AWS managed AdministratorAccess policy was attached. "
                "It allows every action on every resource, so the holder "
                "now has full control of the account.",
                "Detach AdministratorAccess and attach a policy scoped to "
                "the actions and resources the work actually needs.",
            )]
    return []


def _login_succeeded(detail):
    response = detail.get("responseElements")
    if not isinstance(response, dict):
        return False
    return response.get("ConsoleLogin") == "Success"


def rule_root_console_login(event, detail):
    """A successful console sign-in with the root user."""
    if detail.get("eventName") != "ConsoleLogin":
        return []
    identity = detail.get("userIdentity")
    if not isinstance(identity, dict) or identity.get("type") != "Root":
        return []
    if not _login_succeeded(detail):
        return []
    return [_finding(
        event, detail, "ROOT_CONSOLE_LOGIN", "high",
        "Root user signed in to the console",
        identity.get("arn"),
        "The account root user signed in. Root can do anything in the "
        "account, including closing it, and its actions cannot be limited "
        "by IAM policies. Day to day work should never need it.",
        "Confirm this sign-in was expected. Do daily work with an IAM "
        "identity instead, keep root credentials locked away with MFA on, "
        "and set a standing alert on any root use.",
    )]


def rule_console_login_no_mfa(event, detail):
    """A successful console sign-in by an IAM user without MFA. Root
    sign-ins are left to the root rule so one event makes one alert."""
    if detail.get("eventName") != "ConsoleLogin":
        return []
    identity = detail.get("userIdentity")
    if not isinstance(identity, dict) or identity.get("type") == "Root":
        return []
    if not _login_succeeded(detail):
        return []
    extra = detail.get("additionalEventData")
    if not isinstance(extra, dict) or extra.get("MFAUsed") != "No":
        return []
    return [_finding(
        event, detail, "CONSOLE_LOGIN_NO_MFA", "medium",
        "Console sign-in without MFA",
        identity.get("arn") or identity.get("userName"),
        "A console sign-in succeeded with no multi-factor authentication. "
        "That means the password alone was enough, and a stolen or "
        "guessed password is all an attacker needs.",
        "Require MFA for console access with an IAM policy condition on "
        "aws:MultiFactorAuthPresent, and register a second factor for "
        "this user before their next sign-in.",
    )]


def rule_trail_stopped(event, detail):
    """CloudTrail logging stopped or a trail deleted."""
    event_name = detail.get("eventName")
    if event_name not in ("StopLogging", "DeleteTrail"):
        return []
    request = _request(detail)
    action = "stopped" if event_name == "StopLogging" else "deleted"
    return [_finding(
        event, detail, "TRAIL_LOGGING_OFF", "high",
        f"CloudTrail logging {action}",
        request.get("name"),
        f"A CloudTrail trail was {action}. From this point the account "
        "stops recording API activity for that trail, which blinds "
        "incident investigation and any detection built on the log.",
        "Restart logging on the trail, or recreate it if it was "
        "deleted, and check what happened in the account while the "
        "trail was off. Restrict cloudtrail:StopLogging and "
        "cloudtrail:DeleteTrail to a break-glass role.",
    )]


def rule_snapshot_public(event, detail):
    """ModifySnapshotAttribute sharing a snapshot with everyone."""
    if detail.get("eventName") != "ModifySnapshotAttribute":
        return []
    request = _request(detail)
    groups = []
    attribute = request.get("createVolumePermission")
    if isinstance(attribute, dict):
        for entry in _items(attribute.get("add")):
            if isinstance(entry, dict) and entry.get("group"):
                groups.append(entry["group"])
    if "all" not in groups:
        return []
    return [_finding(
        event, detail, "SNAPSHOT_PUBLIC", "high",
        "EBS snapshot shared publicly",
        request.get("snapshotId"),
        "The snapshot was shared with the 'all' group, which makes it "
        "public. Anyone with an AWS account can copy it and read every "
        "byte of data on the volume it came from.",
        "Remove the public share from the snapshot, share only with "
        "named account ids when sharing is needed, and review what "
        "data the source volume held.",
    )]


def rule_unencrypted_volume(event, detail):
    """CreateVolume for a volume without encryption."""
    if detail.get("eventName") != "CreateVolume":
        return []
    request = _request(detail)
    if request.get("encrypted") is not False:
        return []
    response = detail.get("responseElements")
    volume_id = response.get("volumeId") if isinstance(response, dict) \
        else None
    return [_finding(
        event, detail, "EBS_VOLUME_UNENCRYPTED", "medium",
        "EBS volume created without encryption",
        volume_id,
        "A new EBS volume was created with encryption off. Data written "
        "to it sits unencrypted on the underlying storage, and the "
        "volume cannot be encrypted later without recreating it.",
        "Enable EBS encryption by default for the account so new "
        "volumes are encrypted automatically, and migrate data off "
        "this volume onto an encrypted replacement.",
    )]


RULES = (
    rule_s3_public_policy,
    rule_s3_public_acl,
    rule_sg_open_ingress,
    rule_iam_wildcard_admin,
    rule_root_console_login,
    rule_console_login_no_mfa,
    rule_trail_stopped,
    rule_snapshot_public,
    rule_unencrypted_volume,
)


def evaluate_event(event):
    """Evaluate one EventBridge CloudTrail event against every rule.
    Returns a list of findings; an unreadable event returns an empty
    list rather than raising."""
    if not isinstance(event, dict):
        return []
    detail = _detail(event)
    if not detail.get("eventName"):
        return []
    findings = []
    for rule in RULES:
        try:
            findings.extend(rule(event, detail))
        except Exception:
            continue
    return findings
