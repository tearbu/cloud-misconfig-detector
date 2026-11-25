"""Lambda handler: EventBridge event in, SNS alerts out.

EventBridge delivers the "AWS API Call via CloudTrail" event as the
Lambda event itself. The handler hands it to the evaluation core in
rules.py, then publishes one SNS message per finding to the topic
named by the SNS_TOPIC_ARN environment variable, which the SAM
template sets.

boto3 is imported lazily inside the publish step and the client can
be injected, so the handler can be unit tested with a fake client
and no AWS anywhere in sight. When SNS_TOPIC_ARN is not set the
handler still evaluates and reports its findings in the return
value; it just publishes nothing. That is the local and test path,
and in the deployed stack the variable is always set.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rules


def _get_sns_client(injected):
    if injected is not None:
        return injected
    import boto3

    return boto3.client("sns")


def format_alert(finding):
    """Render one finding as an SNS subject and message body."""
    subject = (
        f"[{finding['severity'].upper()}] {finding['rule_id']}: "
        f"{finding['title']}"
    )[:100]
    body = "\n".join([
        finding["title"],
        "",
        f"Rule:        {finding['rule_id']}",
        f"Severity:    {finding['severity']}",
        f"Account:     {finding['account']}",
        f"Region:      {finding['region']}",
        f"Resource:    {finding['resource']}",
        f"Actor:       {finding['actor']}",
        f"Event:       {finding['event_name']} at {finding['event_time']}",
        "",
        "What happened:",
        finding["explanation"],
        "",
        "Fix:",
        finding["remediation"],
    ])
    return subject, body


def handle_event(event, sns_client=None, topic_arn=None):
    """Evaluate one event and publish its findings. Returns a
    summary dict; safe to call on malformed input."""
    findings = rules.evaluate_event(event)
    topic = topic_arn or os.environ.get("SNS_TOPIC_ARN")
    published = 0
    if findings and topic:
        client = _get_sns_client(sns_client)
        for finding in findings:
            subject, body = format_alert(finding)
            client.publish(TopicArn=topic, Subject=subject, Message=body)
            published += 1
    return {
        "findings": len(findings),
        "published": published,
        "rules_fired": [finding["rule_id"] for finding in findings],
    }


def lambda_handler(event, context):
    summary = handle_event(event)
    print(json.dumps(summary))
    return summary
