import copy
import importlib.util
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('workflow', ROOT / 'scripts/compliance_workflow.py')
workflow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workflow)

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / 'examples/compliance/scenario.json').read_text())
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name) / 'evidence'
        self.as_of = date(2026, 10, 10)

    def run_demo(self):
        return workflow.run(self.data, self.output, self.as_of)

    def test_repair_and_revoke_are_verified(self):
        self.assertEqual(self.run_demo(), [])
        self.assertEqual((self.output / 'config-after.txt').read_text(),
                         self.data['change']['expected_configuration'])
        grants = json.loads((self.output / 'access-after.json').read_text())
        self.assertEqual(grants, [{'user': 'demo-support-user', 'role': 'Reader'}])
        self.assertIn('demo-former-contractor', (self.output / 'revocations.csv').read_text())
        self.assertEqual(workflow.verify(self.output), [])

    def test_unapproved_change_is_rejected_before_writes(self):
        self.data['change']['status'] = 'pending'
        with self.assertRaisesRegex(ValueError, 'approved'):
            self.run_demo()
        self.assertFalse(self.output.exists())

    def test_self_approval_is_rejected(self):
        self.data['change']['approver'] = self.data['change']['requester']
        with self.assertRaisesRegex(ValueError, 'separate approver'):
            self.run_demo()

    def test_late_approval_is_rejected(self):
        self.data['change']['approved_at'] = '2026-10-10T10:00:00Z'
        with self.assertRaisesRegex(ValueError, 'precede'):
            self.run_demo()

    def test_wrong_access_reviewer_is_rejected(self):
        self.data['access'][1]['reviewer'] = 'someone-else'
        with self.assertRaisesRegex(ValueError, 'listed manager'):
            self.run_demo()

    def test_missing_business_justification_is_rejected(self):
        self.data['access'][0]['justification'] = ''
        with self.assertRaisesRegex(ValueError, 'justification'):
            self.run_demo()

    def test_duplicate_access_grant_is_rejected(self):
        self.data['access'].append(copy.deepcopy(self.data['access'][0]))
        with self.assertRaisesRegex(ValueError, 'Duplicate access'):
            self.run_demo()

    def test_closed_finding_needs_verification(self):
        self.data['findings'][0]['verification'] = ''
        with self.assertRaisesRegex(ValueError, 'verification'):
            self.run_demo()

    def test_overdue_finding_fails_gate_and_keeps_evidence(self):
        self.data['findings'][1]['due_date'] = '2026-10-09'
        self.assertIn('Overdue unresolved finding: FIND-DEMO-002', self.run_demo())
        self.assertTrue((self.output / 'manifest.json').is_file())

    def test_exception_expiring_today_fails_gate(self):
        self.data['findings'][2]['exception']['expires'] = '2026-10-10'
        self.assertIn('Expired exception: FIND-DEMO-003', self.run_demo())

    def test_reverification_uses_supplied_date(self):
        self.run_demo()
        self.assertIn('Expired exception: FIND-DEMO-003',
                      workflow.verify(self.output, date(2026, 10, 20)))

    def test_tampered_evidence_is_rejected(self):
        self.run_demo()
        (self.output / 'change.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            workflow.verify(self.output)

    def test_deleted_evidence_is_rejected(self):
        self.run_demo()
        (self.output / 'revocations.csv').unlink()
        with self.assertRaisesRegex(ValueError, 'Missing or unsafe'):
            workflow.verify(self.output)

    def test_missing_manifest_entry_is_rejected(self):
        self.run_demo()
        path = self.output / 'manifest.json'
        manifest = json.loads(path.read_text())
        manifest['files'].pop()
        workflow.write_json(path, manifest)
        with self.assertRaisesRegex(ValueError, 'evidence entries'):
            workflow.verify(self.output)

    def test_path_traversal_is_rejected(self):
        self.run_demo()
        path = self.output / 'manifest.json'
        manifest = json.loads(path.read_text())
        manifest['files'][0]['path'] = '../outside'
        workflow.write_json(path, manifest)
        with self.assertRaisesRegex(ValueError, 'evidence entries'):
            workflow.verify(self.output)

    def test_existing_evidence_is_never_overwritten(self):
        self.run_demo()
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.run_demo()

    def test_non_synthetic_scope_is_rejected(self):
        self.data['scope'] = 'production'
        with self.assertRaisesRegex(ValueError, 'synthetic'):
            self.run_demo()

    def test_forged_remaining_grants_fail_even_with_updated_hash(self):
        self.run_demo()
        path = self.output / 'access-after.json'
        workflow.write_json(path, [{'user': 'demo-former-contractor', 'role': 'Contributor'}])
        manifest_path = self.output / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        for entry in manifest['files']:
            if entry['path'] == path.name:
                entry['sha256'] = workflow.digest(path)
        workflow.write_json(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, 'Remaining access'):
            workflow.verify(self.output)

    def test_missing_revocation_record_fails_with_updated_hash(self):
        self.run_demo()
        path = self.output / 'revocations.csv'
        workflow.write_csv(path, [], ['user', 'role', 'approved_by', 'approved_at', 'action', 'scope'])
        manifest_path = self.output / 'manifest.json'
        manifest = json.loads(manifest_path.read_text())
        for entry in manifest['files']:
            if entry['path'] == path.name:
                entry['sha256'] = workflow.digest(path)
        workflow.write_json(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, 'Revocation evidence'):
            workflow.verify(self.output)

if __name__ == '__main__':
    unittest.main()
