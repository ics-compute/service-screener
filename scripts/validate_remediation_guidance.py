"""Validate remediation-guidance coverage for reporter rules and framework mappings.

Every reporter rule must yield a non-empty summary (the text that leads the
``Notes`` column of ``waf-pillars.xlsx``). A specific instruction is optional;
the script reports how many rules have one so regressions in catalog matching
are visible. Every check referenced by a framework map must exist as a
reporter rule.
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from utils.RemediationCatalog import RemediationCatalog

SERVICES_DIR = ROOT / 'services'
FRAMEWORKS_DIR = ROOT / 'frameworks'


def load_reporter_rules():
    rules = {}
    for reporter_path in SERVICES_DIR.glob('**/*.reporter.json'):
        service = reporter_path.name.removesuffix('.reporter.json')
        with reporter_path.open(encoding='utf-8') as reporter_file:
            for check, detail in json.load(reporter_file).items():
                rules[f'{service}.{check}'] = detail
    return rules


def framework_references(value):
    if isinstance(value, dict):
        for nested_value in value.values():
            yield from framework_references(nested_value)
    elif isinstance(value, list):
        for nested_value in value:
            yield from framework_references(nested_value)
    elif isinstance(value, str) and re.fullmatch(r'[a-z0-9_]+\.[A-Za-z0-9_$]+', value):
        yield value


def main():
    rules = load_reporter_rules()
    guidance_errors = []
    families = Counter()
    with_context = 0

    for finding_key, detail in rules.items():
        service, check = finding_key.split('.', 1)
        guidance = RemediationCatalog.get_guidance(service, check, detail)
        if not guidance['summary']:
            guidance_errors.append(finding_key)
        families[guidance['family']] += 1
        if guidance['context']:
            with_context += 1

    stale_exact = sorted(
        key for key in RemediationCatalog._EXACT_GUIDANCE if key not in rules
    )

    framework_errors = []
    framework_references_seen = 0
    for map_path in FRAMEWORKS_DIR.glob('*/map.json'):
        with map_path.open(encoding='utf-8') as map_file:
            for reference in framework_references(json.load(map_file)):
                if reference.endswith('.$length'):
                    continue
                framework_references_seen += 1
                if reference not in rules:
                    framework_errors.append(f'{map_path.parent.name}: {reference}')

    if guidance_errors or framework_errors or stale_exact:
        if guidance_errors:
            print('Rules without a remediation summary:')
            print('\n'.join(sorted(guidance_errors)))
        if stale_exact:
            print('Exact guidance entries that match no reporter rule:')
            print('\n'.join(stale_exact))
        if framework_errors:
            print('Framework references without reporter rules:')
            print('\n'.join(sorted(framework_errors)))
        return 1

    with_hint = len(rules) - families['none']
    print(
        f'Remediation guidance covers {len(rules)} reporter rules '
        f'({with_hint} with a specific hint, {families["exact"]} exact, '
        f'{with_context} with a why-line) and '
        f'{framework_references_seen} framework references.'
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
