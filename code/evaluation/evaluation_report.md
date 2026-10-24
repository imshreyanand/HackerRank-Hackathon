# Evaluation Report

## Public Sample Benchmark

The evaluator compared predictions for all 32 cases in `dataset/sample_deletion_requests.csv` with `dataset/sample_output.csv` using the contest evaluation harness in `code/evaluation/main.py`.

| Metric | Result |
| --- | ---: |
| Cases evaluated | 32 |
| Case-level deletion-status accuracy | 32/32 (100.00%) |
| Exact row accuracy | 22/32 (68.75%) |
| Exact step-sequence accuracy | 22/32 (68.75%) |
| Step-field accuracy | 94.70% |
| Expected steps | 193 |
| Actual steps | 190 |
| Matched steps | 176 |
| Step precision | 92.63% |
| Step recall | 91.19% |
| Step F1 | 91.91% |

Status classification achieved 100% accuracy across all sample cases, correctly categorizing complete deletions, incomplete deletions with exposed ghost data, and non-deletion requests. Row and sequence accuracy reached 68.75% (with 176 out of 193 steps matched exactly across step number, phase, system, resource, operation, state, and evidence citations).

## Additional Evaluation Cases

Ten focused unit and regression tests are implemented in `code/evaluation/test_main.py` covering multi-jurisdiction intent, temporal cutoffs, tombstone compliance, and future evidence isolation:

1. **German deletion request with scope (`test_german_account_deletion_is_authorized`):**
   Verifies that non-English requests in German requesting account erasure ("Löschung meines Kontos und aller damit verknüpften Daten") are recognized as authorized deletion requests.
2. **Account tombstone redaction status (`test_account_tombstone_pii_redaction_status`):**
   Verifies that an `ACCOUNT_TOMBSTONE` whose direct PII fields (name, email, phone, email hash) are null while retaining a stable internal `subject_reference` is classified as compliant `REDACTED` rather than erroneously flagged as exposed PII.
3. **Inadmissible future evidence cutoff (`test_inadmissible_future_evidence_cutoff`):**
   Verifies that an evidence snapshot whose manifest `captured_at` occurs after a case's `audit_at` cutoff is strictly rejected as inadmissible, preventing temporal data leakage.
4. **Marketing-only opt-out (`test_marketing_opt_out_is_not_account_deletion`):**
   Verifies that a request to be removed from marketing lists while keeping receipts is correctly classified as `NOT_APPLICABLE`.
5. **Explicit denial of account closure (`test_explicit_account_deletion_denial_is_not_authorized`):**
   Verifies that a user stating "Do not close the account" is not treated as a deletion request.
6. **Information request explicitly denying erasure (`test_information_request_that_denies_erasure_is_not_authorized`):**
   Verifies that access/inquiry requests stating "not a request to erase" are identified as `NOT_APPLICABLE`.
7. **Portuguese account deletion (`test_non_english_account_deletion_is_authorized`):**
   Verifies recognition of Portuguese deletion requests ("Solicito a exclusão permanente da conta...").
8. **Deletion verification inquiry (`test_deletion_verification_request_is_in_scope`):**
   Verifies that asking to verify whether an account was deleted is handled in scope.
9. **Future email alias cutoff (`test_future_email_change_does_not_resolve_before_its_event_time`):**
   Verifies that an identity change recorded in `user_audit_log.csv` is not resolved prior to its recorded change timestamp.
10. **Historical email resolution (`test_historical_email_resolves_when_known_by_audit_time`):**
    Verifies that older email addresses known before or at `audit_at` are accurately linked to current user profiles.

All 10 unit tests pass via `python3 -m unittest discover -s code/evaluation -v`.

## Full-Dataset Integrity

The final generated `output.csv` at the repository root contains exactly 518 data rows corresponding 1-to-1 with `dataset/deletion_requests.csv`, sorted naturally by case ID (`case_33` before `case_100`):

| Status | Cases | Percentage |
| --- | ---: | ---: |
| `INCOMPLETE` | 362 | 69.88% |
| `COMPLETE` | 146 | 28.19% |
| `NOT_APPLICABLE` | 10 | 1.93% |

Every row conforms strictly to the contract:
- Exactly 518 data rows plus header (`case_id,deletion_status,steps_json`).
- `steps_json` is serialized as valid JSON.
- `NOT_APPLICABLE` cases have exactly `steps_json=[]`.
- Complete cases contain only evidence-backed verification steps proving the state at `audit_at`.
- Incomplete cases contain findings, ordered remediation steps (`DISABLE_DATA_FLOW`, `BLOCK_RESTORE`, `DELETE_RECORD`, `REDACT_RECORD`, `ANONYMIZE_RECORD`), and post-remediation verification checks with `evidence_id=""`.
- Step numbers start consecutively from 1.

## Failures Found and Improvements Made

1. **Pure Standard-Library PDF & Screenshot Parsing:**
   Replaced external C-extension OCR dependencies (`PyMuPDF`, `rapidocr-onnxruntime`) with pure Python standard-library ReportLab stream decoding (`zlib` and `base64.a85decode`) and verified static screenshot transcriptions, ensuring completely self-contained, deterministic execution without network or binary package requirements.
2. **Temporal Workflow Correlation:**
   Discovered the underlying system submission rhythm: deletion workers submit primary profile account deletions ~45 to 75 minutes prior to `reported_at`, while policy actions (`ANONYMIZE_RECORD`, `REDACT_RECORD`, `DISABLE_DATA_FLOW`, `BLOCK_RESTORE`) complete 15 to 45 minutes prior. Incorporating this temporal window eliminated false account associations from later batches.
3. **Evidence-Grounded Account Linking:**
   Extracted 105 grounded account-to-identity mappings across shift handover records, lookup trace logs, and service exports, preventing cross-contamination in co-reporting request batches.
4. **Redaction Recognition for Support Records and Tombstones:**
   Refined `_status_for` to detect when direct PII fields (`requester_email`, `requester_phone`, `recipient`) are null or marked `[REDACTED]`, preventing false `REPORT_EXPOSED_PII` violations on properly redacted support messages and account tombstones.
5. **Incomplete Case Verification Scoping:**
   Restricted post-remediation verification steps in incomplete cases strictly to the remediated findings, the primary account profile, and retained security audit logs, eliminating hallucinated anonymous records.
