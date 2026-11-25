"""Tests for the Lambda handler with an injected fake SNS client."""

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import handler

SAMPLE_DIR = os.path.join(ROOT, "sample-events")
TOPIC = "arn:aws:sns:us-east-1:123456789012:fictional-alerts"


class FakeSnsClient:
    def __init__(self):
        self.calls = []

    def publish(self, TopicArn, Subject, Message):
        self.calls.append({"TopicArn": TopicArn, "Subject": Subject,
                           "Message": Message})
        return {"MessageId": "fictional-message-id"}


def load_sample(name):
    with open(os.path.join(SAMPLE_DIR, name), encoding="utf-8") as handle:
        return json.load(handle)


class HandlerTests(unittest.TestCase):
    def setUp(self):
        os.environ.pop("SNS_TOPIC_ARN", None)

    def test_finding_event_publishes_one_alert(self):
        client = FakeSnsClient()
        summary = handler.handle_event(
            load_sample("003-sg-open-ssh.json"),
            sns_client=client, topic_arn=TOPIC)
        self.assertEqual(summary["findings"], 1)
        self.assertEqual(summary["published"], 1)
        self.assertEqual(summary["rules_fired"], ["SG_OPEN_INGRESS"])
        call = client.calls[0]
        self.assertEqual(call["TopicArn"], TOPIC)
        self.assertIn("SG_OPEN_INGRESS", call["Subject"])
        self.assertIn("sg-0123456789abcdef0", call["Message"])
        self.assertIn("Fix:", call["Message"])

    def test_benign_event_publishes_nothing(self):
        client = FakeSnsClient()
        summary = handler.handle_event(
            load_sample("014-benign-signin-with-mfa.json"),
            sns_client=client, topic_arn=TOPIC)
        self.assertEqual(summary, {"findings": 0, "published": 0,
                                   "rules_fired": []})
        self.assertEqual(client.calls, [])

    def test_no_topic_means_no_publish_but_still_reports(self):
        summary = handler.handle_event(load_sample("001-s3-public-policy.json"))
        self.assertEqual(summary["findings"], 1)
        self.assertEqual(summary["published"], 0)

    def test_topic_from_environment(self):
        os.environ["SNS_TOPIC_ARN"] = TOPIC
        client = FakeSnsClient()
        summary = handler.handle_event(
            load_sample("009-trail-logging-stopped.json"), sns_client=client)
        self.assertEqual(summary["published"], 1)
        self.assertEqual(client.calls[0]["TopicArn"], TOPIC)

    def test_malformed_event_does_not_crash(self):
        client = FakeSnsClient()
        for bad in (None, {}, {"detail": None}, "junk"):
            with self.subTest(bad=repr(bad)):
                summary = handler.handle_event(
                    bad, sns_client=client, topic_arn=TOPIC)
                self.assertEqual(summary["findings"], 0)
        self.assertEqual(client.calls, [])

    def test_subject_stays_within_sns_limit(self):
        finding_event = load_sample("005-iam-wildcard-policy.json")
        client = FakeSnsClient()
        handler.handle_event(finding_event, sns_client=client,
                             topic_arn=TOPIC)
        self.assertLessEqual(len(client.calls[0]["Subject"]), 100)


if __name__ == "__main__":
    unittest.main()
