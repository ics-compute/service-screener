#!/bin/bash
# No-op: this service is account/region-level and creates no fixtures.
# See create_test_resources.sh for why.
REGION="${AWS_REGION:-ap-southeast-1}"
while [[ $# -gt 0 ]]; do case $1 in --region) REGION="$2"; shift 2;; *) shift;; esac; done
echo "=== Cleanup: nothing to remove (no fixtures created) ==="
echo "=== Cleanup Complete: 0 deleted, 0 skipped ==="
exit 0
