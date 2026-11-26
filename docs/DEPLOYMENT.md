# Deployment record: cloud-misconfig-detector

I deployed this project live on 25 November 2026 and verified
the function in the real account. This file is the record of
what I did, what came back, and the one limitation the
deployment exposed.

## Where it went

- Account: 762103021017
- Region: us-east-1
- Stack: cloud-misconfig-detector
- Final stack status: CREATE_COMPLETE
- Tooling: AWS SAM, run from CloudShell

The commands I used:

```bash
sam build --template-file template.yaml
sam deploy --stack-name cloud-misconfig-detector --resolve-s3
```

## Stack outputs

- AlertsTopicArn: arn:aws:sns:us-east-1:762103021017:cloud-misconfig-detector-alerts
- DetectorFunctionName: cloud-misconfig-detector-detector

## Live verification

I invoked the deployed function directly with three of this
repo's own sample events. The results, verbatim:

```
001-s3-public-policy.json
{"findings": 1, "published": 1, "rules_fired": ["S3_PUBLIC_POLICY"]}

003-sg-open-ssh.json
{"findings": 1, "published": 1, "rules_fired": ["SG_OPEN_INGRESS"]}

012-benign-sg-scoped.json
{"findings": 0, "published": 0, "rules_fired": []}
```

"Published" means the function sent a message to the SNS topic.
The topic has no subscription yet, so the alerts reached no
inbox. Adding an email or chat subscription is still a manual
step I have not taken.

One small real-world note: the AWS CLI rejected my first
invocation payload when I passed it as text, with an Invalid
base64 error. Passing the payload as binary with fileb://
worked.

## The limitation the deployment exposed

The account has no CloudTrail trail. I checked with
aws cloudtrail describe-trails and the list came back empty.

That matters because the detector's EventBridge rule only
receives "AWS API Call via CloudTrail" events when a trail is
logging management events. So the honest status is: the stack
is deployed and the function is verified, but the live event
feed is dormant until a trail exists. Nothing has yet flowed
from a real change in the account through EventBridge to the
function.

I did not create a trail during the deployment. A trail needs
an S3 bucket to hold its logs, and I left that as a decision to
make on purpose rather than something a detector deployment
does quietly in the background.
