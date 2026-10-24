import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from main import Auditor


class RequestIntentTests(unittest.TestCase):
    def test_marketing_opt_out_is_not_account_deletion(self):
        self.assertFalse(
            Auditor.deletion_requested(
                "Please remove me from marketing lists only. I still want receipts."
            )
        )

    def test_explicit_account_deletion_denial_is_not_authorized(self):
        self.assertFalse(
            Auditor.deletion_requested(
                "I cannot access my profile. Do not close the account."
            )
        )

    def test_information_request_that_denies_erasure_is_not_authorized(self):
        self.assertFalse(
            Auditor.deletion_requested(
                "This is an information request, not a request to erase it."
            )
        )

    def test_non_english_account_deletion_is_authorized(self):
        self.assertTrue(
            Auditor.deletion_requested(
                "Solicito a exclusão permanente da conta associada a este e-mail."
            )
        )

    def test_deletion_verification_request_is_in_scope(self):
        self.assertTrue(
            Auditor.deletion_requested("Can you verify that my account was deleted?")
        )

    def test_german_account_deletion_is_authorized(self):
        self.assertTrue(
            Auditor.deletion_requested(
                "Ich beantrage die vollständige Löschung meines Kontos und aller damit verknüpften Daten."
            )
        )


class PolicyAndEvidenceTests(unittest.TestCase):
    def test_account_tombstone_pii_redaction_status(self):
        from main import EvidenceRecord
        tombstone = EvidenceRecord(
            evidence_id="evidence_99",
            system_id="identity_service",
            resource_id="tombstone_101",
            observed_at="2026-09-01T12:00:00Z",
            category="ACCOUNT_TOMBSTONE",
            data={
                "resource_id": "tombstone_101",
                "subject_reference": "user_42",
                "name": None,
                "email": None,
                "phone": None,
                "email_hash": None,
            },
        )
        self.assertEqual(Auditor._status_for(tombstone), "REDACTED")

    def test_inadmissible_future_evidence_cutoff(self):
        from main import EvidenceRecord
        auditor = Auditor.__new__(Auditor)
        auditor.manifest_captured_at = {
            "evidence_early": "2026-09-10T12:00:00Z",
            "evidence_late": "2026-09-20T12:00:00Z",
        }
        early_record = EvidenceRecord("evidence_early", "account_service", "account_1", "2026-09-10T12:00:00Z", "USER_PROFILE", {})
        late_record = EvidenceRecord("evidence_late", "account_service", "account_2", "2026-09-20T12:00:00Z", "USER_PROFILE", {})
        
        cutoff = "2026-09-15T12:00:00Z"
        self.assertTrue(auditor._is_admissible(early_record, cutoff))
        self.assertFalse(auditor._is_admissible(late_record, cutoff))


class IdentityCutoffTests(unittest.TestCase):
    def test_future_email_change_does_not_resolve_before_its_event_time(self):
        auditor = Auditor.__new__(Auditor)
        auditor.users = [
            {
                "user_id": "user_1",
                "name": "Taylor Example",
                "email": "new@example.test",
                "phone": "+1 202 555 0100",
                "email_hash": "0" * 64,
                "updated_at": "2026-10-01T00:00:00Z",
            }
        ]
        auditor.user_rows = {row["user_id"]: row for row in auditor.users}
        auditor.audit_log = [
            {
                "user_id": "user_1",
                "event_time": "2026-10-01T00:00:00Z",
                "field_name": "email",
                "old_value": "old@example.test",
                "new_value": "new@example.test",
            }
        ]
        auditor.links = {}
        user_ids, _ = auditor._subject(
            {
                "email": "new@example.test",
                "audit_at": "2026-09-30T23:59:59Z",
            }
        )
        self.assertEqual(user_ids, set())

    def test_historical_email_resolves_when_known_by_audit_time(self):
        auditor = Auditor.__new__(Auditor)
        auditor.users = [
            {
                "user_id": "user_1",
                "name": "Taylor Example",
                "email": "new@example.test",
                "phone": "+1 202 555 0100",
                "email_hash": "0" * 64,
                "updated_at": "2026-10-01T00:00:00Z",
            }
        ]
        auditor.user_rows = {row["user_id"]: row for row in auditor.users}
        auditor.audit_log = [
            {
                "user_id": "user_1",
                "event_time": "2026-09-01T00:00:00Z",
                "field_name": "email",
                "old_value": "old@example.test",
                "new_value": "new@example.test",
            }
        ]
        auditor.links = {}
        user_ids, identifiers = auditor._subject(
            {
                "email": "old@example.test",
                "audit_at": "2026-09-30T23:59:59Z",
            }
        )
        self.assertEqual(user_ids, {"user_1"})
        self.assertIn("old@example.test", identifiers)


if __name__ == "__main__":
    unittest.main()
