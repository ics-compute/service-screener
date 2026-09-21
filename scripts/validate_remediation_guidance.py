"""Validate remediation-guidance coverage for reporter rules and framework mappings."""

import json
import re
import sys
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

    for finding_key, detail in rules.items():
        service, check = finding_key.split('.', 1)
        guidance = RemediationCatalog.get_guidance(service, check, detail)
        if not guidance['summary'] or not guidance['instruction']:
            guidance_errors.append(finding_key)

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

    if guidance_errors or framework_errors:
        if guidance_errors:
            print('Rules without remediation guidance:')
            print('\n'.join(sorted(guidance_errors)))
        if framework_errors:
            print('Framework references without reporter rules:')
            print('\n'.join(sorted(framework_errors)))
        return 1

    print(
        f'Remediation guidance covers {len(rules)} reporter rules and '
        f'{framework_references_seen} framework references.'
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
