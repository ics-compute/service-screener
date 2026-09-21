# GuardDuty Simulation Testing

**No fixtures, by design.** `create_test_resources.sh` is a read-only posture
report; `cleanup_test_resources.sh` is a no-op.

## Why nothing is created

The `gd*` feature checks read whether GuardDuty and its protection features
(Runtime Monitoring, S3 Protection, Malware Protection, RDS/Lambda/EKS
protection, AI Protection) are enabled on the account's detector. Toggling any of
them is an **account-level change to the account's live threat-detection
posture** — disabling Runtime Monitoring genuinely stops GuardDuty detecting
container runtime threats for as long as a fixture exists, and enabling a paid
feature starts billing. There is nothing safe to create or toggle, so the checks
are validated against the real detector.

This mirrors the read-only pattern used for `config`, `securityhub`, `inspector`
and `accessanalyzer`.

## How the checks were verified

Against the account's live detector `b6c337ba6115507baf62cd630529d574`, which
happens to be a useful mix: six features enabled (PASS) and two disabled —
`RUNTIME_MONITORING` and `AI_PROTECTION` — both correctly reporting FAIL. So both
branches of the feature checks are exercised by real state. The posture report
predicts exactly what the scan finds.

## Usage

```bash
cd services/guardduty/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh --region ap-southeast-1   # read-only prediction
cd ../../..
python3 main.py --regions ap-southeast-1 --services guardduty --beta 1 --sequential 1
```

## Cost

Zero. The report uses only the read-only `get_detector` call the scanner itself
makes.
