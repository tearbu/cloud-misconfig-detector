# Deployment record: cloud-misconfig-detector

I deployed this project live on 25 November 2026 and verified
the function in the real account. This file is the record of
what I did, what came back, and the limitation the first
deployment exposed. A finishing run later the same day closed
that limitation, and the end of this file records it.

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
At that point in the deployment the topic had no subscription,
so those alerts reached no inbox. The finishing run below
covers the subscription I added afterwards.

One small real-world note: the AWS CLI rejected my first
invocation payload when I passed it as text, with an Invalid
base64 error. Passing the payload as binary with fileb://
worked.

## The limitation the first deployment exposed

At deployment time the account had no CloudTrail trail. I
checked with aws cloudtrail describe-trails and the list came
back empty.

That mattered because the detector's EventBridge rule only
receives "AWS API Call via CloudTrail" events when a trail is
logging management events. So the honest status at that point
was: the stack was deployed and the function was verified, but
the live event feed was dormant until a trail existed. Nothing
had yet flowed from a real change in the account through
EventBridge to the function.

I did not create a trail during the deployment itself. A trail
needs an S3 bucket to hold its logs, and I left that as a
decision to make on purpose rather than something a detector
deployment does quietly in the background. I made that decision
later the same day, and the next section is the record.

## The finishing run

Later on 25 November 2026 I finished the setup:

- I created a CloudTrail trail named misconfig-detector-trail,
  logging management events to a bucket named
  cloudtrail-logs-762103021017. The trail reports IsLogging
  true, and log delivery to the bucket is confirmed.
- I subscribed my own email address to the alerts topic and
  confirmed the subscription, so findings are now emailed to
  me instead of landing on a topic nobody reads.

Then I ran the end-to-end test the deployment section of the
README had called for. At 19:11:48 EST I opened TCP port 22 to
0.0.0.0/0 on a scratch security group named detector-live-test.
The detector function was invoked at 19:11:53 EST, about five
seconds later, and returned:

```
{"findings": 1, "published": 1, "rules_fired": ["SG_OPEN_INGRESS"]}
```

The invocation ran for about three seconds and used 87 MB of
its 256 MB of memory. I then revoked the rule and deleted the
scratch group, so the account was left clean.

One honest caveat: whether the alert email for that single
test finding reached my inbox is uncertain. The subscription
confirmation and the publish happened minutes apart, and SNS
only delivers to subscriptions that are confirmed at publish
time. The publish itself is confirmed by the function's own
return value. Findings from now on go to a confirmed
subscription and will be emailed.

## Findings from the live run

- The full path works in a real account: CloudTrail recorded
  the change, EventBridge routed it, the function judged it,
  and SNS published the finding, with a confirmed email
  subscription on the topic.
- Event delivery took about five seconds in this test. That is
  one observation, not a guarantee, but it was far faster than
  the "within minutes" I had written in the README before the
  run.
- The function is small in practice: about three seconds of
  runtime and 87 MB of memory on a 256 MB allocation for a
  single event.

## Lessons learned

- Local tests proved the rules. Only the live run proved the
  wiring. Thirty-eight passing tests and a clean demo said
  nothing about whether a real event would ever reach the
  function, and for the first deployment it would not have.
- The detector was blind until a trail existed. That is not a
  defect in this project; it is a property of any detection
  built on CloudTrail. The audit log has to be switched on
  before anything listening to it can hear.
- Event delivery can be seconds, not minutes. I had documented
  the slower expectation because it is the safe one to plan
  around. The observed run beat it, and the docs now record
  both the observation and the caution.
- An SNS topic without a confirmed subscription is a silent
  dead end. The function can publish perfectly and nobody hears
  anything. Subscription state is part of the deployment, not
  an afterthought, and it belongs on the checklist next to the
  stack itself.
