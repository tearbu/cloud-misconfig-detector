#!/usr/bin/env python3
"""Structural check of template.yaml, runnable without AWS.

Parses the SAM template with PyYAML (using a loader that tolerates
the !Ref, !Sub, and !GetAtt intrinsic tags) and asserts the shape
this project depends on: an SNS topic; one Lambda function on
Python 3.12 with the right handler; an EventBridge rule event whose
pattern matches the "AWS API Call via CloudTrail" detail type and
covers the event names the rules read; the SNS_TOPIC_ARN
environment variable wired to the topic; and an IAM action list of
exactly sns:Publish scoped to that topic. Nothing else.

What this check cannot prove: it does not run the SAM transform and
it is not a deployment, so it cannot see transform errors,
dependency cycles, or event pattern mistakes that only show up when
EventBridge and CloudTrail meet in a real account. The template is
kept small partly so there is less for a deploy to trip over, but
only a real deployment settles it.

Usage: python3 validate_template.py
"""

import os
import sys

import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))

EXPECTED_EVENTS = {
    "PutBucketPolicy", "PutBucketAcl", "AuthorizeSecurityGroupIngress",
    "CreatePolicy", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
    "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
    "ConsoleLogin", "StopLogging", "DeleteTrail", "CreateVolume",
    "ModifySnapshotAttribute",
}


class SamLoader(yaml.SafeLoader):
    pass


def _unknown_tag(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return {tag_suffix: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {tag_suffix: loader.construct_sequence(node)}
    return {tag_suffix: loader.construct_mapping(node)}


SamLoader.add_multi_constructor("!", _unknown_tag)


def main():
    with open(os.path.join(ROOT, "template.yaml"), encoding="utf-8") as handle:
        template = yaml.load(handle, Loader=SamLoader)

    assert template["Transform"] == "AWS::Serverless-2016-10-31"
    resources = template["Resources"]
    assert set(resources) == {"AlertsTopic", "DetectorFunction"}, (
        f"expected the topic and the function, found {sorted(resources)}"
    )
    print("resources ok: AlertsTopic, DetectorFunction")

    topic = resources["AlertsTopic"]
    assert topic["Type"] == "AWS::SNS::Topic"
    print("topic ok: AlertsTopic (AWS::SNS::Topic)")

    detector = resources["DetectorFunction"]
    assert detector["Type"] == "AWS::Serverless::Function"
    props = detector["Properties"]
    assert props["Handler"] == "handler.lambda_handler"
    runtime = template["Globals"]["Function"]["Runtime"]
    assert runtime == "python3.12", runtime
    print(f"function ok: handler.lambda_handler on {runtime}")

    event = props["Events"]["MisconfigEvents"]
    assert event["Type"] == "EventBridgeRule"
    pattern = event["Properties"]["Pattern"]
    assert pattern["detail-type"] == ["AWS API Call via CloudTrail"]
    covered = set(pattern["detail"]["eventName"])
    assert covered == EXPECTED_EVENTS, (
        f"event pattern mismatch: missing {EXPECTED_EVENTS - covered}, "
        f"extra {covered - EXPECTED_EVENTS}"
    )
    print(f"event ok: EventBridgeRule covering {len(covered)} event names")

    env = props["Environment"]["Variables"]
    assert env["SNS_TOPIC_ARN"] == {"Ref": "AlertsTopic"}, env
    print("environment ok: SNS_TOPIC_ARN points at AlertsTopic")

    actions = []
    resources_seen = []
    for policy in props["Policies"]:
        for statement in policy["Statement"]:
            actions.extend(statement["Action"])
            resources_seen.append(statement["Resource"])
    assert actions == ["sns:Publish"], (
        f"detector function must hold exactly one permission, found {actions}"
    )
    assert resources_seen == [{"Ref": "AlertsTopic"}], resources_seen
    print(f"iam ok: DetectorFunction: {actions} on AlertsTopic only")

    assert "AlertsTopicArn" in template["Outputs"]
    print("TEMPLATE VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
