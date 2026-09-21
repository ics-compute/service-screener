#!/usr/bin/env python3
"""
Validate every framework map.json against the checks that actually exist.

WHY THIS EXISTS
---------------
frameworks/Framework.py.getContent() falls through to `return {"c": check}` when
a mapped check key is not found in the scan data, and formatCheckAndLinks()
treats any entry without an "r" field as COMPLIANT. So a mapping that points at
a check which does not exist renders as a green tick:

    <dt class='text-success'><i class='fas fa-check'></i> [isEnabled]</dt>

A typo in a compliance mapping therefore reports as a PASSED CONTROL rather than
as an error. That is the worst possible failure mode for a compliance report:
silent, and biased toward saying "you comply".

This script fails when a map entry references a service or a check that does not
exist, so the mistake is caught in CI instead of in an audit.

WHAT IT CHECKS
--------------
1. Every "<service>.<check>" entry resolves to a real key in
   services/<service>/<service>.reporter.json.
2. The special "<service>.$length" form (a resource-count assertion handled by
   Framework.getContent) resolves to a real service directory.
3. map.json is structurally sound: 'metadata' and 'mapping' present, sections
   are dicts of lists of strings.
4. No duplicate entries within a single best-practice section.

USAGE
-----
    python3 scripts/validate_frameworks.py                    # all frameworks
    python3 scripts/validate_frameworks.py frameworks/SOC2/map.json ...
    python3 scripts/validate_frameworks.py --list-unmapped    # coverage report

Exit status is 1 when any dangling entry is found, so it is CI-usable.
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVICES_DIR = ROOT / 'services'
FRAMEWORKS_DIR = ROOT / 'frameworks'

## Service directory name -> the prefix used in framework maps. The scanner
## appends '_' to directory names that collide with a Python keyword
## (utils/Config.py KEYWORD_SERVICES), but the maps use the bare service name.
DIRECTORY_TO_MAP_NAME = {'lambda_': 'lambda'}

## Handled specially by Framework.getContent: asserts a resource count rather
## than naming a check.
LENGTH_SENTINEL = '$length'

## Not a framework, and has no map.json.
NON_FRAMEWORK_DIRS = {'helper', '__pycache__'}


def loadCheckUniverse():
    """Return {mapName: set(checkKeys)} for every service, plus 'general'."""
    universe = {}

    for path in sorted(SERVICES_DIR.glob('*/*.reporter.json')):
        directory = path.parent.name
        mapName = DIRECTORY_TO_MAP_NAME.get(directory, directory)
        try:
            universe[mapName] = set(json.loads(path.read_text()))
        except json.JSONDecodeError as e:
            print(f"  ERROR: {path} is not valid JSON: {e}")
            universe[mapName] = set()

    ## services/general.reporter.json sits at the top level rather than in a
    ## service directory, and is referenced as 'general.<check>'.
    generalPath = SERVICES_DIR / 'general.reporter.json'
    if generalPath.exists():
        try:
            universe['general'] = set(json.loads(generalPath.read_text()))
        except json.JSONDecodeError:
            universe['general'] = set()

    return universe


def frameworkMapPaths():
    paths = []
    for child in sorted(FRAMEWORKS_DIR.iterdir()):
        if not child.is_dir() or child.name in NON_FRAMEWORK_DIRS:
            continue
        mapPath = child / 'map.json'
        if mapPath.exists():
            paths.append(mapPath)
    return paths


def validateOne(mapPath, universe):
    """Validate a single map.json. Returns (errors, warnings, entryCount)."""
    errors, warnings = [], []

    try:
        data = json.loads(mapPath.read_text())
    except json.JSONDecodeError as e:
        return [f"invalid JSON: {e}"], [], 0

    if 'metadata' not in data:
        errors.append("missing top-level 'metadata'")
    if 'mapping' not in data:
        return errors + ["missing top-level 'mapping'"], warnings, 0

    mapping = data['mapping']
    if not isinstance(mapping, dict):
        return errors + ["'mapping' is not an object"], warnings, 0

    entryCount = 0

    for title, sections in mapping.items():
        if not isinstance(sections, dict):
            errors.append(f"{title}: expected an object of best practices")
            continue

        for section, entries in sections.items():
            location = f"{title}.{section}"

            if not isinstance(entries, list):
                errors.append(f"{location}: expected a list, got "
                              f"{type(entries).__name__}")
                continue

            seen = set()
            for entry in entries:
                if not isinstance(entry, str):
                    errors.append(f"{location}: non-string entry {entry!r}")
                    continue
                if not entry:
                    ## Framework.getContent returns None for '' and the caller
                    ## then crashes on it, so an empty entry is a real error.
                    errors.append(f"{location}: empty entry")
                    continue

                entryCount += 1

                if entry in seen:
                    warnings.append(f"{location}: duplicate entry '{entry}'")
                seen.add(entry)

                if '.' not in entry:
                    errors.append(
                        f"{location}: '{entry}' is not in <service>.<check> form")
                    continue

                service, check = entry.split('.', 1)

                if service not in universe:
                    errors.append(
                        f"{location}: '{entry}' -> no such service '{service}'")
                    continue

                if check == LENGTH_SENTINEL:
                    ## Valid: asserts the service has >= 1 discovered resource.
                    continue

                if check not in universe[service]:
                    suggestion = suggest(check, universe[service])
                    hint = f" (did you mean '{service}.{suggestion}'?)" if suggestion else ""
                    errors.append(
                        f"{location}: '{entry}' -> no such check in "
                        f"{service}.reporter.json{hint}")

    return errors, warnings, entryCount


def suggest(check, candidates):
    """
    Cheapest useful suggestion: the candidate sharing the longest
    case-insensitive substring with the dangling name. Good enough to point a
    maintainer at a rename without pulling in a dependency.
    """
    lowered = check.lower()
    best, bestScore = None, 0
    for candidate in candidates:
        c = candidate.lower()
        ## Longest common substring length, bounded by the shorter string.
        score = 0
        for size in range(min(len(c), len(lowered)), 3, -1):
            if any(c[i:i + size] in lowered for i in range(len(c) - size + 1)):
                score = size
                break
        if score > bestScore:
            best, bestScore = candidate, score
    ## Require a reasonably long shared run before offering a guess.
    return best if bestScore >= 6 else None


def reportUnmapped(universe):
    """Print which services appear in which frameworks — a coverage matrix."""
    coverage = defaultdict(set)
    for mapPath in frameworkMapPaths():
        framework = mapPath.parent.name
        try:
            mapping = json.loads(mapPath.read_text()).get('mapping', {})
        except json.JSONDecodeError:
            continue
        for sections in mapping.values():
            if not isinstance(sections, dict):
                continue
            for entries in sections.values():
                if not isinstance(entries, list):
                    continue
                for entry in entries:
                    if isinstance(entry, str) and '.' in entry:
                        coverage[entry.split('.', 1)[0]].add(framework)

    frameworks = sorted(p.parent.name for p in frameworkMapPaths())
    header = 'service'.ljust(16) + ''.join(f[:5].rjust(6) for f in frameworks)
    print(header)
    print('-' * len(header))
    for service in sorted(universe):
        row = ''.join(('  yes ' if f in coverage[service] else '   .  ')
                      for f in frameworks)
        print(service.ljust(16) + row)
    print()
    for service in sorted(universe):
        missing = [f for f in frameworks if f not in coverage[service]]
        if missing:
            print(f"{service}: absent from {', '.join(missing)}")


def main():
    parser = argparse.ArgumentParser(
        description='Validate framework map.json files against real checks')
    parser.add_argument('files', nargs='*',
                        help='Specific map.json files (default: all)')
    parser.add_argument('--list-unmapped', action='store_true',
                        help='Print a service-vs-framework coverage matrix')
    parser.add_argument('--strict', action='store_true',
                        help='Treat warnings (duplicates) as failures too')
    args = parser.parse_args()

    universe = loadCheckUniverse()
    if not universe:
        print("ERROR: found no *.reporter.json files — wrong working directory?")
        return 1

    if args.list_unmapped:
        reportUnmapped(universe)
        return 0

    if args.files:
        paths = [Path(f) for f in args.files]
    else:
        paths = frameworkMapPaths()

    exitCode = 0
    totalErrors = totalWarnings = 0

    for mapPath in paths:
        ## A caller (or CI) may pass a path that is not a framework map, e.g.
        ## when globbing changed files. Skip quietly rather than failing.
        if mapPath.name != 'map.json':
            continue
        if not mapPath.exists():
            print(f"\n{mapPath}: does not exist")
            exitCode = 1
            continue

        framework = mapPath.parent.name
        errors, warnings, entryCount = validateOne(mapPath, universe)

        if errors:
            print(f"\n❌ {framework}: {len(errors)} error(s) "
                  f"in {entryCount} mapping entries")
            for message in errors:
                print(f"     {message}")
            exitCode = 1
        elif warnings:
            print(f"\n⚠️  {framework}: {entryCount} entries, "
                  f"{len(warnings)} warning(s)")
        else:
            print(f"✅ {framework}: {entryCount} entries, all resolve")

        for message in warnings:
            print(f"     warning: {message}")

        totalErrors += len(errors)
        totalWarnings += len(warnings)

    print()
    if totalErrors:
        print(f"FAILED: {totalErrors} dangling or malformed mapping entry(ies).")
        print("A dangling entry renders as a GREEN COMPLIANT tick in the report "
              "(see the module docstring), so these are silent false passes.")
    else:
        print(f"All framework mappings resolve to real checks."
              + (f" ({totalWarnings} warning(s))" if totalWarnings else ""))

    if args.strict and totalWarnings:
        exitCode = 1

    return exitCode


if __name__ == '__main__':
    sys.exit(main())
