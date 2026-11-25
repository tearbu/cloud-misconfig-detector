"""Tests for the evaluation core, driven by the fictional sample
events in sample-events/ plus inline variants for the shapes the
samples do not cover."""

import glob
import json
import os
import sys
import unittest
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import rules

SAMPLE_DIR = os.path.join(ROOT, "sample-events")


def load_sample(name):
    with open(os.path.join(SAMPLE_DIR, name), encoding="utf-8") as handle:
        return json.load(handle)


def rule_ids(findings):
    return [finding["rule_id"] for finding in findings]


class SampleEventTests(unittest.TestCase):
    """Every shipped sample fires (or stays silent) as designed."""

    def test_s3_public_policy_fires(self):
        findings = rules.evaluate_event(load_sample("001-s3-public-policy.json"))
        self.assertEqual(rule_ids(findings), ["S3_PUBLIC_POLICY"])
        finding = findings[0]
        self.assertEqual(finding["severity"], "critical")
        self.assertEqual(finding["resource"], "fictional-reports-bucket")
        self.assertEqual(finding["account"], "123456789012")
        self.assertEqual(finding["region"], "us-east-1")

    def test_s3_public_acl_fires(self):
        findings = rules.evaluate_event(load_sample("002-s3-public-acl.json"))
        self.assertEqual(rule_ids(findings), ["S3_PUBLIC_ACL"])
        self.assertEqual(findings[0]["severity"], "critical")

    def test_sg_open_ssh_is_critical(self):
        findings = rules.evaluate_event(load_sample("003-sg-open-ssh.json"))
        self.assertEqual(rule_ids(findings), ["SG_OPEN_INGRESS"])
        self.assertEqual(findings[0]["severity"], "critical")
        self.assertEqual(findings[0]["resource"], "sg-0123456789abcdef0")

    def test_sg_open_ipv6_web_is_high(self):
        findings = rules.evaluate_event(load_sample("004-sg-open-ipv6-web.json"))
        self.assertEqual(rule_ids(findings), ["SG_OPEN_INGRESS"])
        self.assertEqual(findings[0]["severity"], "high")

    def test_iam_wildcard_policy_fires(self):
        findings = rules.evaluate_event(
            load_sample("005-iam-wildcard-policy.json"))
        self.assertEqual(rule_ids(findings), ["IAM_WILDCARD_ADMIN"])
        self.assertEqual(findings[0]["resource"], "fictional-helper-policy")

    def test_iam_attach_admin_fires(self):
        findings = rules.evaluate_event(load_sample("006-iam-attach-admin.json"))
        self.assertEqual(rule_ids(findings), ["IAM_WILDCARD_ADMIN"])

    def test_root_login_fires_root_rule_only(self):
        findings = rules.evaluate_event(
            load_sample("007-root-console-login.json"))
        self.assertEqual(rule_ids(findings), ["ROOT_CONSOLE_LOGIN"])
        self.assertEqual(findings[0]["severity"], "high")

    def test_console_login_no_mfa_fires(self):
        findings = rules.evaluate_event(
            load_sample("008-console-login-no-mfa.json"))
        self.assertEqual(rule_ids(findings), ["CONSOLE_LOGIN_NO_MFA"])
        self.assertEqual(findings[0]["severity"], "medium")

    def test_trail_stopped_fires(self):
        findings = rules.evaluate_event(
            load_sample("009-trail-logging-stopped.json"))
        self.assertEqual(rule_ids(findings), ["TRAIL_LOGGING_OFF"])
        self.assertEqual(findings[0]["resource"], "fictional-main-trail")

    def test_snapshot_public_fires(self):
        findings = rules.evaluate_event(
            load_sample("010-snapshot-made-public.json"))
        self.assertEqual(rule_ids(findings), ["SNAPSHOT_PUBLIC"])

    def test_unencrypted_volume_fires(self):
        findings = rules.evaluate_event(
            load_sample("011-unencrypted-volume.json"))
        self.assertEqual(rule_ids(findings), ["EBS_VOLUME_UNENCRYPTED"])
        self.assertEqual(findings[0]["resource"], "vol-0123456789abcdef0")

    def test_benign_samples_stay_silent(self):
        for name in ("012-benign-sg-scoped.json",
                     "013-benign-iam-scoped-policy.json",
                     "014-benign-signin-with-mfa.json",
                     "015-benign-s3-private-policy.json",
                     "016-benign-encrypted-volume.json"):
            with self.subTest(sample=name):
                findings = rules.evaluate_event(load_sample(name))
                self.assertEqual(findings, [])

    def test_every_sample_file_loads_and_evaluates(self):
        paths = glob.glob(os.path.join(SAMPLE_DIR, "*.json"))
        self.assertEqual(len(paths), 16)
        for path in paths:
            with open(path, encoding="utf-8") as handle:
                event = json.load(handle)
            self.assertIsInstance(rules.evaluate_event(event), list)


def base_event(event_name, params, identity=None, response=None, extra=None):
    detail = {
        "userIdentity": identity or {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/alex.admin",
            "userName": "alex.admin",
        },
        "eventSource": "ec2.amazonaws.com",
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "requestParameters": params,
        "responseElements": response or {},
    }
    if extra:
        detail["additionalEventData"] = extra
    return {"account": "123456789012", "region": "us-east-1",
            "time": "2026-11-25T12:00:00Z", "detail": detail}


class VariantTests(unittest.TestCase):
    """Shapes the shipped samples do not cover."""

    def test_url_encoded_policy_document_fires(self):
        document = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*",
                           "Resource": "*"}],
        })
        event = base_event("PutUserPolicy", {
            "userName": "jordan.dev",
            "policyName": "inline-admin",
            "policyDocument": urllib.parse.quote(document),
        })
        self.assertEqual(rule_ids(rules.evaluate_event(event)),
                         ["IAM_WILDCARD_ADMIN"])

    def test_policy_document_as_dict_fires(self):
        event = base_event("PutRolePolicy", {
            "roleName": "fictional-role",
            "policyName": "inline-admin",
            "policyDocument": {
                "Statement": [{"Effect": "Allow",
                               "Action": ["*"], "Resource": ["*"]}],
            },
        })
        self.assertEqual(rule_ids(rules.evaluate_event(event)),
                         ["IAM_WILDCARD_ADMIN"])

    def test_wildcard_action_scoped_resource_stays_silent(self):
        document = json.dumps({
            "Statement": [{"Effect": "Allow", "Action": "*",
                           "Resource": "arn:aws:s3:::fictional-reports-bucket/*"}],
        })
        event = base_event("CreatePolicy", {
            "policyName": "one-bucket-admin", "policyDocument": document})
        self.assertEqual(rules.evaluate_event(event), [])

    def test_attach_role_admin_fires(self):
        event = base_event("AttachRolePolicy", {
            "roleName": "fictional-role",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
        self.assertEqual(rule_ids(rules.evaluate_event(event)),
                         ["IAM_WILDCARD_ADMIN"])

    def test_attach_scoped_policy_stays_silent(self):
        event = base_event("AttachUserPolicy", {
            "userName": "jordan.dev",
            "policyArn": "arn:aws:iam::123456789012:policy/fictional-reports-reader"})
        self.assertEqual(rules.evaluate_event(event), [])

    def test_all_traffic_ingress_is_critical(self):
        event = base_event("AuthorizeSecurityGroupIngress", {
            "groupId": "sg-0123456789abcdef2",
            "ipPermissions": {"items": [{
                "ipProtocol": "-1",
                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
            }]},
        })
        findings = rules.evaluate_event(event)
        self.assertEqual(rule_ids(findings), ["SG_OPEN_INGRESS"])
        self.assertEqual(findings[0]["severity"], "critical")

    def test_rdp_range_covering_3389_is_critical(self):
        event = base_event("AuthorizeSecurityGroupIngress", {
            "groupId": "sg-0123456789abcdef3",
            "ipPermissions": {"items": [{
                "ipProtocol": "tcp", "fromPort": 3380, "toPort": 3390,
                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
            }]},
        })
        findings = rules.evaluate_event(event)
        self.assertEqual(findings[0]["severity"], "critical")

    def test_authenticated_users_acl_fires(self):
        event = base_event("PutBucketAcl", {
            "bucketName": "fictional-assets-bucket",
            "accessControlPolicy": {"grants": [
                {"grantee": {
                    "uri": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                    "type": "Group"},
                 "permission": "READ"},
            ]},
        })
        findings = rules.evaluate_event(event)
        self.assertEqual(rule_ids(findings), ["S3_PUBLIC_ACL"])
        self.assertIn("AuthenticatedUsers", findings[0]["explanation"])

    def test_failed_root_login_stays_silent(self):
        event = base_event(
            "ConsoleLogin", {},
            identity={"type": "Root",
                      "arn": "arn:aws:iam::123456789012:root"},
            response={"ConsoleLogin": "Failure"},
            extra={"MFAUsed": "No"})
        self.assertEqual(rules.evaluate_event(event), [])

    def test_root_login_without_mfa_fires_root_rule_only(self):
        event = base_event(
            "ConsoleLogin", {},
            identity={"type": "Root",
                      "arn": "arn:aws:iam::123456789012:root"},
            response={"ConsoleLogin": "Success"},
            extra={"MFAUsed": "No"})
        self.assertEqual(rule_ids(rules.evaluate_event(event)),
                         ["ROOT_CONSOLE_LOGIN"])

    def test_delete_trail_fires(self):
        event = base_event("DeleteTrail", {"name": "fictional-main-trail"})
        findings = rules.evaluate_event(event)
        self.assertEqual(rule_ids(findings), ["TRAIL_LOGGING_OFF"])
        self.assertIn("deleted", findings[0]["title"])

    def test_snapshot_shared_with_named_account_stays_silent(self):
        event = base_event("ModifySnapshotAttribute", {
            "snapshotId": "snap-0123456789abcdef0",
            "createVolumePermission": {
                "add": {"items": [{"userId": "210987654321"}]}},
        })
        self.assertEqual(rules.evaluate_event(event), [])


class MalformedEventTests(unittest.TestCase):
    """Bad input returns no findings and never raises."""

    def test_empty_dict(self):
        self.assertEqual(rules.evaluate_event({}), [])

    def test_non_dict_inputs(self):
        for bad in (None, "not an event", 42, ["detail"]):
            with self.subTest(bad=repr(bad)):
                self.assertEqual(rules.evaluate_event(bad), [])

    def test_detail_not_a_dict(self):
        self.assertEqual(rules.evaluate_event({"detail": "oops"}), [])
        self.assertEqual(rules.evaluate_event({"detail": None}), [])

    def test_missing_event_name(self):
        self.assertEqual(
            rules.evaluate_event({"detail": {"eventSource": "s3.amazonaws.com"}}),
            [])

    def test_missing_request_parameters(self):
        event = base_event("PutBucketPolicy", None)
        event["detail"]["requestParameters"] = None
        self.assertEqual(rules.evaluate_event(event), [])

    def test_garbage_policy_document(self):
        event = base_event("CreatePolicy", {
            "policyName": "broken", "policyDocument": "{not json"})
        self.assertEqual(rules.evaluate_event(event), [])

    def test_weird_permission_shapes(self):
        event = base_event("AuthorizeSecurityGroupIngress", {
            "groupId": "sg-0123456789abcdef0",
            "ipPermissions": {"items": ["junk", {"ipRanges": "junk"}, None]},
        })
        self.assertEqual(rules.evaluate_event(event), [])


if __name__ == "__main__":
    unittest.main()
