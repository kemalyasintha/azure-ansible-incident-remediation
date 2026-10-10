#!/usr/bin/env python3
"""Local compliance demonstration. No cloud, directory, or scanner access."""
import argparse
import csv
import hashlib
import json
from datetime import date, datetime, timezone
from pathlib import Path

REQUIRED = {'access-review.csv', 'revocations.csv', 'access-after.json',
            'vulnerability-register.csv', 'change.json', 'incident.json',
            'config-before.txt', 'config-after.txt', 'events.jsonl', 'summary.md'}

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timestamps must include a timezone')
    return result

def require(value, message):
    if not value:
        raise ValueError(message)

def validate_input(data, as_of):
    require(data['scope'] == 'synthetic-local-demo', 'Only synthetic local data is supported')
    change = data['change']
    require(change['status'] == 'approved', 'Change must be approved before execution')
    require(change['approver'] and change['approver'] != change['requester'],
            'Change requires a separate approver')
    require(timestamp(change['approved_at']) <= timestamp(change['execution_at']),
            'Approval must precede execution')
    require(timestamp(change['execution_at']).date() <= as_of, 'Execution date is in the future')
    for field in ('id', 'reason', 'risk', 'rollback', 'expected_configuration', 'observed_configuration'):
        require(change.get(field), f'Missing change field: {field}')
    require(change['expected_configuration'] != change['observed_configuration'],
            'Demonstration requires configuration drift')
    incident = data['incident']
    for field in ('id', 'root_cause', 'impact', 'mitigation', 'preventive_action', 'owner'):
        require(incident.get(field), f'Missing incident field: {field}')
    require(incident['change_id'] == change['id'], 'Incident must reference this change')
    grants = data['access']
    keys = [(g['user'], g['role']) for g in grants]
    require(len(keys) == len(set(keys)), 'Duplicate access grants')
    for grant in grants:
        for field in ('user', 'role', 'manager', 'reviewer', 'justification', 'reviewed_at'):
            require(grant.get(field), f'Missing access-review field: {field}')
        require(grant['reviewer'] == grant['manager'], 'Access decision requires the listed manager')
        require(grant['user'] != grant['reviewer'], 'Self-review is not allowed')
        require(timestamp(grant['reviewed_at']).date() <= as_of, 'Access review is in the future')
        require(grant['decision'] in ('retain', 'revoke'), 'Invalid access decision')
    ids = [f['id'] for f in data['findings']]
    require(len(ids) == len(set(ids)), 'Duplicate finding IDs')
    for finding in data['findings']:
        for field in ('id', 'asset', 'severity', 'owner', 'description', 'remediation', 'due_date'):
            require(finding.get(field), f'Missing finding field: {field}')
        require(finding['severity'] in ('critical', 'high', 'medium', 'low'), 'Invalid severity')
        require(finding['status'] in ('open', 'closed', 'exception'), 'Invalid finding status')
        date.fromisoformat(finding['due_date'])
        if finding['status'] == 'closed':
            require(finding.get('verification'), 'Closed finding requires verification')
        if finding['status'] == 'exception':
            exception = finding['exception']
            for field in ('approver', 'reason', 'expires'):
                require(exception.get(field), f'Missing exception field: {field}')
            require(exception['approver'] != finding['owner'], 'Exception requires a separate approver')
            date.fromisoformat(exception['expires'])

def policy_issues(findings, as_of):
    issues = []
    for finding in findings:
        if finding['status'] == 'open' and date.fromisoformat(finding['due_date']) < as_of:
            issues.append(f"Overdue unresolved finding: {finding['id']}")
        if finding['status'] == 'exception' and date.fromisoformat(finding['exception']['expires']) <= as_of:
            issues.append(f"Expired exception: {finding['id']}")
    return issues

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')

def write_csv(path, rows, fields):
    with path.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

def run(data, output, as_of):
    validate_input(data, as_of)
    require(not output.exists(), 'Output already exists; use a new directory to preserve evidence')
    output.mkdir(parents=True)
    change = dict(data['change'])
    before = change.pop('observed_configuration')
    expected = change.pop('expected_configuration')
    # This is an actual local file repair, not an Azure remediation run.
    (output / 'config-before.txt').write_text(before, encoding='utf-8')
    (output / 'config-after.txt').write_text(before, encoding='utf-8')
    (output / 'config-after.txt').write_text(expected, encoding='utf-8')
    restored = (output / 'config-after.txt').read_text(encoding='utf-8') == expected
    require(restored, 'Local configuration verification failed')
    change.update({'scope': data['scope'], 'verification': 'local file equals declared configuration',
                   'verification_passed': restored, 'before_sha256': digest(output / 'config-before.txt'),
                   'after_sha256': digest(output / 'config-after.txt')})
    write_json(output / 'change.json', change)
    incident = dict(data['incident'], scope=data['scope'], status='resolved-in-local-demo',
                    verification=change['verification'], verification_passed=restored)
    write_json(output / 'incident.json', incident)
    retained, revocations, reviews = [], [], []
    events = [{'action': 'configuration-restored', 'change_id': change['id'],
               'scope': data['scope'], 'scenario_at': change['execution_at']}]
    for grant in data['access']:
        reviews.append(grant)
        if grant['decision'] == 'retain':
            retained.append({'user': grant['user'], 'role': grant['role']})
        else:
            record = {'user': grant['user'], 'role': grant['role'], 'approved_by': grant['reviewer'],
                      'approved_at': grant['reviewed_at'], 'action': 'removed-from-local-grants',
                      'scope': data['scope']}
            revocations.append(record)
            events.append(dict(record, action='access-revoked-in-local-demo'))
    write_json(output / 'access-after.json', retained)
    write_csv(output / 'access-review.csv', reviews,
              ['user', 'role', 'manager', 'reviewer', 'decision', 'justification', 'reviewed_at'])
    write_csv(output / 'revocations.csv', revocations,
              ['user', 'role', 'approved_by', 'approved_at', 'action', 'scope'])
    register = []
    for finding in data['findings']:
        row = {k: finding.get(k, '') for k in ('id', 'asset', 'severity', 'owner', 'description',
                                              'status', 'due_date', 'remediation', 'verification')}
        row['exception'] = json.dumps(finding.get('exception', {}), sort_keys=True)
        register.append(row)
    write_csv(output / 'vulnerability-register.csv', register,
              ['id', 'asset', 'severity', 'owner', 'description', 'status', 'due_date',
               'remediation', 'verification', 'exception'])
    (output / 'events.jsonl').write_text(''.join(json.dumps(e, sort_keys=True) + '\n' for e in events), encoding='utf-8')
    issues = policy_issues(data['findings'], as_of)
    (output / 'summary.md').write_text(
        '# Synthetic compliance demonstration\n\n'
        'Local configuration and access changes only. No live Azure, directory or scanner actions.\n\n'
        f'Policy evaluation date: {as_of}\n\n'
        f'Change: {change["id"]}; incident: {incident["id"]}\n\n'
        f'Access reviewed: {len(reviews)}; local grants revoked: {len(revocations)}\n\n'
        f'Findings tracked: {len(register)}; policy issues: {len(issues)}\n\n'
        + ('\n'.join('- ' + issue for issue in issues) if issues else 'All demonstrated policy checks passed.') + '\n',
        encoding='utf-8')
    files = [{'path': name, 'sha256': digest(output / name)} for name in sorted(REQUIRED)]
    manifest = {'scope': data['scope'], 'generated_at': datetime.now(timezone.utc).isoformat(),
                'as_of': str(as_of), 'source_sha256': hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest(),
                'change_id': change['id'], 'incident_id': incident['id'], 'files': files}
    write_json(output / 'manifest.json', manifest)
    return verify(output, as_of)

def verify(output, as_of=None):
    manifest = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
    require(manifest['scope'] == 'synthetic-local-demo', 'Invalid evidence scope')
    as_of = as_of or date.fromisoformat(manifest['as_of'])
    paths = [entry['path'] for entry in manifest['files']]
    require(len(paths) == len(set(paths)), 'Duplicate evidence paths')
    require(set(paths) == REQUIRED, 'Missing or unexpected evidence entries')
    for entry in manifest['files']:
        path = output / entry['path']
        require(path.is_file() and not path.is_symlink(), f'Missing or unsafe evidence: {entry["path"]}')
        require(digest(path) == entry['sha256'], f'Evidence hash mismatch: {entry["path"]}')
    change = json.loads((output / 'change.json').read_text(encoding='utf-8'))
    incident = json.loads((output / 'incident.json').read_text(encoding='utf-8'))
    require(change['id'] == manifest['change_id'] == incident['change_id'], 'Change linkage mismatch')
    require(incident['id'] == manifest['incident_id'], 'Incident linkage mismatch')
    require(change['status'] == 'approved' and change['approver'] != change['requester'] and change['approver'],
            'Invalid change approval')
    require(timestamp(change['approved_at']) <= timestamp(change['execution_at']), 'Late change approval')
    require(change['verification_passed'] is True and incident['verification_passed'] is True,
            'Recovery verification failed')
    require(change['before_sha256'] == digest(output / 'config-before.txt') and
            change['after_sha256'] == digest(output / 'config-after.txt'), 'Configuration evidence mismatch')
    with (output / 'vulnerability-register.csv').open(encoding='utf-8', newline='') as stream:
        findings = list(csv.DictReader(stream))
    for finding in findings:
        finding['exception'] = json.loads(finding['exception'])
    with (output / 'access-review.csv').open(encoding='utf-8', newline='') as stream:
        reviews = list(csv.DictReader(stream))
    with (output / 'revocations.csv').open(encoding='utf-8', newline='') as stream:
        revocations = list(csv.DictReader(stream))
    # Recheck the records even if someone regenerates their manifest hashes.
    reconstructed_change = dict(change, observed_configuration=(output / 'config-before.txt').read_text(encoding='utf-8'),
                                expected_configuration=(output / 'config-after.txt').read_text(encoding='utf-8'))
    validate_input({'scope': manifest['scope'], 'change': reconstructed_change,
                    'incident': incident, 'access': reviews, 'findings': findings}, as_of)
    expected_grants = [{'user': g['user'], 'role': g['role']} for g in reviews if g['decision'] == 'retain']
    actual_grants = json.loads((output / 'access-after.json').read_text(encoding='utf-8'))
    require(actual_grants == expected_grants, 'Remaining access does not match review decisions')
    expected_revocations = [{'user': g['user'], 'role': g['role'], 'approved_by': g['reviewer'],
                             'approved_at': g['reviewed_at'], 'action': 'removed-from-local-grants',
                             'scope': manifest['scope']} for g in reviews if g['decision'] == 'revoke']
    require(revocations == expected_revocations, 'Revocation evidence does not match approved decisions')
    events = [json.loads(line) for line in (output / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
    expected_events = [{'action': 'configuration-restored', 'change_id': change['id'],
                        'scope': manifest['scope'], 'scenario_at': change['execution_at']}]
    expected_events.extend(dict(r, action='access-revoked-in-local-demo') for r in expected_revocations)
    require(events == expected_events, 'Event evidence does not match recorded actions')
    return policy_issues(findings, as_of)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    demo = commands.add_parser('run')
    demo.add_argument('--input', type=Path, required=True)
    demo.add_argument('--output', type=Path, required=True)
    demo.add_argument('--as-of', type=date.fromisoformat, default=date.today())
    check = commands.add_parser('verify')
    check.add_argument('--output', type=Path, required=True)
    check.add_argument('--as-of', type=date.fromisoformat)
    args = parser.parse_args()
    try:
        if args.command == 'run':
            issues = run(json.loads(args.input.read_text(encoding='utf-8')), args.output, args.as_of)
        else:
            issues = verify(args.output, args.as_of)
        for issue in issues:
            print(issue)
        print('FAIL' if issues else 'PASS: evidence and demonstrated policy checks')
        return 1 if issues else 0
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'FAIL: {error}')
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
