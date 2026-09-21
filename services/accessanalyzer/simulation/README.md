# accessanalyzer Simulation Testing

**No fixtures, by design.** `create_test_resources.sh` is a read-only posture
report and `cleanup_test_resources.sh` is a no-op.

Every check in this service reads **account/region-level** state, not
per-resource state. Enabling the service or its features is an account-level
action with recurring cost, and disabling one removes a live security control —
so there is nothing safe to create as a fixture. The subject of every check
always already exists, which makes a scan of the real account a complete test
rather than a partial one. This mirrors `services/config/simulation/`.

## Usage

```bash
cd services/accessanalyzer/simulation
chmod +x create_test_resources.sh cleanup_test_resources.sh
./create_test_resources.sh --region ap-southeast-1   # read-only prediction
cd ../../..
python3 main.py --regions ap-southeast-1 --services accessanalyzer --beta 1 --sequential 1
```

## Cost

Zero. Only read APIs are used.
