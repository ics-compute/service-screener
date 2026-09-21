import ast
import sys
import json
from pathlib import Path
import argparse

REMEDIATION_FIELDS = ('remediation', 'remediation_risk', 'remediation_doc')
VALID_REMEDIATION_RISK = ('low', 'medium', 'high')
AWS_DOCS_PREFIX = 'https://docs.aws.amazon.com/'

def is_valid_category(category_str):
    """
    Validate if the category string contains only valid characters (S,R,O,P,C,T)
    and each character appears at most once.
    """
    valid_chars = set('SROPCT')
    category_set = set(category_str.upper())

    if not category_set.issubset(valid_chars):
        return False, f"Category contains invalid characters. Only S,R,O,P,C,T are allowed."

    if len(category_set) != len(category_str):
        return False, f"Category contains duplicate characters."

    return True, "Valid category"

def validate_remediation(check_name, check_data):
    """
    Validate the remediation fields. All three keys must be present on every
    check, but their values are allowed to be null when no single-command fix
    exists for the finding.
    """
    for field in REMEDIATION_FIELDS:
        if field not in check_data:
            return False, f"Missing required field '{field}' in check '{check_name}'"

    remediation = check_data['remediation']
    risk = check_data['remediation_risk']
    doc = check_data['remediation_doc']

    if remediation is not None and not isinstance(remediation, str):
        return False, f"Field 'remediation' must be a string or null in check '{check_name}'"

    if remediation is None:
        if risk is not None:
            return False, (
                f"Field 'remediation_risk' must be null when 'remediation' is null "
                f"in check '{check_name}'"
            )
    else:
        if risk not in VALID_REMEDIATION_RISK:
            return False, (
                f"Invalid remediation_risk value '{risk}' in check '{check_name}'. "
                f"Must be one of: {', '.join(VALID_REMEDIATION_RISK)}"
            )

    if doc is not None:
        if not isinstance(doc, str) or not doc.startswith(AWS_DOCS_PREFIX):
            return False, (
                f"Field 'remediation_doc' must be null or a {AWS_DOCS_PREFIX} URL "
                f"in check '{check_name}'"
            )

    return True, "Valid remediation"

def validate_reporter_structure(content):
    """Validate the structure of a reporter file"""
    try:
        # Check if it's valid Python code
        ast.parse(content)

        # Convert string content to dict
        data = json.loads(content)

        # Required fields
        required_fields = ['category', '^description', 'shortDesc', 'criticality']
        for check_name, check_data in data.items():
            for field in required_fields:
                if field not in check_data:
                    return False, f"Missing required field '{field}' in check '{check_name}'"

        # Validate categories
        for check_name, check_data in data.items():
            if 'category' in check_data:
                is_valid, message = is_valid_category(check_data['category'])
                if not is_valid:
                    return False, f"Invalid category value '{check_data['category']}' in check '{check_name}': {message}"

        # Check for empty fields. The remediation fields are exempt: they are
        # intentionally null when a finding has no single-command fix.
        for check_name, check_data in data.items():
            for field, value in check_data.items():
                if field in REMEDIATION_FIELDS:
                    continue
                if value is None or (isinstance(value, str) and not value.strip()):
                    return False, f"Empty field '{field}' in check '{check_name}'"

        # Validate criticality values
        valid_criticality = ['H', 'M', 'L', 'I']
        for check_name, check_data in data.items():
            if 'criticality' in check_data:
                if check_data['criticality'] not in valid_criticality:
                    return False, f"Invalid criticality value '{check_data['criticality']}' in check '{check_name}'. Must be one of: {', '.join(valid_criticality)}"

        # Validate remediation fields
        for check_name, check_data in data.items():
            is_valid, message = validate_remediation(check_name, check_data)
            if not is_valid:
                return False, message

        return True, "Validation passed"

    except SyntaxError as e:
        return False, f"Invalid Python syntax: {str(e)}"
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON structure: {str(e)}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def validate_file(file_path):
    """Validate a single reporter file"""
    try:
        print(f"\nValidating {file_path}...")
        with open(file_path, 'r') as f:
            content = f.read()

        is_valid, message = validate_reporter_structure(content)

        if not is_valid:
            print(f"❌ Validation failed: {message}")
            return False
        else:
            print("✅ Validation passed")
            return True

    except Exception as e:
        print(f"❌ Error processing file: {str(e)}")
        return False

def is_template(file_path):
    """
    utils/services-template/service.reporter.json is a scaffold for
    scripts/CreateService.py, not a real reporter file: it holds `<PLACEHOLDER>`
    values and // comments, so it is intentionally not parseable JSON. Skip it,
    otherwise it fails validation both in a no-argument run and in CI, whose
    changed-file filter matches any *.reporter.json path.
    """
    return Path(file_path).as_posix().endswith(
        'utils/services-template/service.reporter.json')


def main():
    parser = argparse.ArgumentParser(description='Validate reporter files')
    parser.add_argument('files', nargs='*', help='Specific files to validate')
    args = parser.parse_args()

    exit_code = 0

    if args.files:
        # Validate specific files
        reporter_files = args.files
    else:
        # Validate all reporter files if no specific files provided
        reporter_files = sorted(Path('.').rglob('*.reporter.json'))

    for file_path in reporter_files:
        if is_template(file_path):
            print(f"\nSkipping template {file_path}")
            continue
        if not validate_file(file_path):
            exit_code = 1

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
