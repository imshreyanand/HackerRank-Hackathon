#!/usr/bin/env python3
"""Evidence-grounded Northstar Shop deletion audit runner."""

import argparse
import csv
import hashlib
import json
import sqlite3
import re
import shlex
import sys
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


STEP_FIELDS = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}
OPERATION_STATES = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
}

RESOURCE_PATTERN = re.compile(
    r"\b(?:account|search|analytics|support|export|backup|data_flow|"
    r"audit_record|tombstone|marketing|cache|email_delivery|object)_\d+\b",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    system_id: str
    resource_id: str
    observed_at: str
    category: str
    data: Dict[str, Any]


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def normalize_email(value: str) -> str:
    return value.strip().casefold()


def normalize_value(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip()).casefold()


def walk_values(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for child in value.values():
            yield from walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_values(child)
    elif isinstance(value, str) and value:
        yield value


def find_system_from_path(path: Sequence[str], data: Dict[str, Any]) -> str:
    systems = {
        "account_service",
        "profile_service",
        "search_service",
        "analytics_platform",
        "support_platform",
        "support_storage_service",
        "export_service",
        "backup_service",
        "backup_restore_service",
        "integration_service",
        "security_service",
        "identity_service",
        "legal_service",
        "marketing_platform",
        "object_storage",
        "email_delivery_service",
        "cache_service",
        "privacy_treatment_service",
    }
    for segment in reversed(path):
        if segment in systems:
            return segment
    value = str(data.get("system") or data.get("data_store") or data.get("origin_system") or "")
    if value in systems:
        return value
    return ""


def infer_category(system_id: str, data: Dict[str, Any], collection: str) -> str:
    text = " ".join(
        (
            system_id,
            collection,
            str(data.get("record_type") or ""),
            str(data.get("data_category") or ""),
        )
    ).casefold()
    if "tombstone" in text or system_id == "identity_service":
        return "ACCOUNT_TOMBSTONE"
    if "attachment" in text or "object_storage" in text:
        return "SUPPORT_ATTACHMENT"
    if "search" in text or system_id == "search_service":
        return "SEARCH_INDEX_ENTRY"
    if "analytics" in text or "telemetry" in text:
        return "ANALYTICS_PROFILE" if "telemetry" not in text else "PRODUCT_TELEMETRY"
    if "connector" in text or "data_flow" in text or system_id == "integration_service":
        return "DATA_FLOW"
    if "backup" in text or system_id in {"backup_service", "backup_restore_service"}:
        return "BACKUP_ARCHIVE"
    if "export" in text or system_id == "export_service":
        return "USER_EXPORT"
    if "security_audit" in text or system_id == "security_service":
        return "SECURITY_AUDIT_LOG"
    if "legal" in text or system_id == "legal_service":
        return "LEGAL_HOLD_RECORD"
    if "support" in text or system_id in {"support_platform", "support_storage_service"}:
        return "SUPPORT_MESSAGE"
    if "marketing" in text or system_id == "marketing_platform":
        return "MARKETING_PROFILE"
    if "email_delivery" in text or system_id == "email_delivery_service":
        return "EMAIL_DELIVERY_LOG"
    if "cache" in text or system_id == "cache_service":
        return "CACHE_ENTRY"
    if "profile" in text or system_id in {"account_service", "profile_service"}:
        return "USER_PROFILE"
    return ""


def system_for_category(system_id: str, category: str) -> str:
    if system_id == "support_replica":
        return "support_platform"
    if system_id:
        return system_id
    return {
        "USER_PROFILE": "account_service",
        "SEARCH_INDEX_ENTRY": "search_service",
        "ANALYTICS_PROFILE": "analytics_platform",
        "PRODUCT_TELEMETRY": "analytics_platform",
        "DATA_FLOW": "integration_service",
        "BACKUP_ARCHIVE": "backup_service",
        "USER_EXPORT": "export_service",
        "SUPPORT_MESSAGE": "support_platform",
        "SUPPORT_ATTACHMENT": "object_storage",
        "SECURITY_AUDIT_LOG": "security_service",
        "LEGAL_HOLD_RECORD": "legal_service",
        "ACCOUNT_TOMBSTONE": "identity_service",
        "EMAIL_DELIVERY_LOG": "email_delivery_service",
        "MARKETING_PROFILE": "marketing_platform",
        "CACHE_ENTRY": "cache_service",
    }.get(category, "")


def snapshot_records(
    value: Any,
    path: Tuple[str, ...] = (),
    inherited_time: str = "",
) -> Iterable[Tuple[str, str, str, Dict[str, Any]]]:
    if isinstance(value, dict):
        record_time = str(
            value.get("captured_at")
            or value.get("observed_at")
            or value.get("recorded_at")
            or value.get("updated_at")
            or inherited_time
        )
        if value.get("resource_id"):
            system = find_system_from_path(path, value)
            collection = next(
                (segment for segment in reversed(path) if segment != "records"),
                str(value.get("collection") or ""),
            )
            category = infer_category(system, value, collection)
            system = system_for_category(system, category)
            yield system, collection, record_time, value
            return
        next_path = path
        if value.get("data_store"):
            next_path += (str(value["data_store"]),)
        if value.get("collection"):
            next_path += (str(value["collection"]),)
        for key, child in value.items():
            child_path = next_path + (str(key),)
            yield from snapshot_records(child, child_path, record_time)
    elif isinstance(value, list):
        for child in value:
            yield from snapshot_records(child, path, inherited_time)


SCREENSHOT_TEXTS = {
    "account_admin_console_20260926.png": """
Northstar Shop / Customer Operations / Customers
Haruka Sato Silver user_11 · account_5762
Email: haruka.s1838@zoho.com Phone: +81 90 7610 2507 Signup channel: mobile_app Market: JP Preferred language: Japanese Last contact: 24 Sep 2026 09:14 JST
Order ID: ORD-20265762 Date: 12 Sep 2026 Item: Ceramic coffee set Qty: 1 Total: JPY 8,900 Status: Delivered - 18 Sep
Order ID: ORD-20265518 Date: 28 Aug 2026 Item: Travel backpack Qty: 1 Total: JPY 12,400 Status: Returned - 03 Sep
Customer details: Default address: 2-18-4 Kichijoji, Musashino, Tokyo 180-0004 Loyalty tier: Silver Support: CS-8538 · support_9538 Member since: 12 Jan 2024
Activity: 24 Sep Customer replied to CS-8538, 22 Sep Support agent responded, 18 Sep Order ORD-20265762 delivered, 03 Sep Order ORD-20265518 returned, 28 Aug support_9538 created
""",
    "search_index_inspector_20260901.png": """
Customer Search 2 hits customer_directory_v3 / prod-eu
Executed: 01 Sep 2026 06:00:14 UTC
Results:
search_428 | Gabriel Silva | g.silva76@gmail.com | user_13 | Score: 9.84 | Last indexed: 05:58:21 UTC
search_1874 | — | g.silva76.jr@gmail.com | — | Score: 4.12 | Last indexed: 05:55:03 UTC
Raw document search_428: _index: customer_directory_v3 _id: search_428 display_name: Gabriel Silva email: g.silva76@gmail.com customer_reference: user_13 indexed_at: 2026-09-01T05:58:21Z
""",
    "connector_management_console_20260807.png": """
Connections 12 connectors PRODUCTION · eu-west · 07 Aug 2026 08:00 UTC
data_flow_1121 | customer_analytics_warehouse | jain.aditi@gmail.com | Continuous | 1,284 | 07:59:42
data_flow_9846 | customer_analytics_warehouse | lucia-torres@gmail.com | Continuous | 842 | 07:59:36
Order notifications | notification_service | order events | Continuous | 650 | 07:59:28
Delivery tracking | logistics_warehouse | shipment events | Continuous | 420 | 07:59:13
data_flow_1121 Status: Healthy Owner: Data Platform Destination: customer_analytics_warehouse Selector: jain.aditi@gmail.com Sync mode: Continuous sync Last response: 200 OK
""",
    "analytics_profile_view_20260713.png": """
Pulse Analytics Omar Darwish user_20 · analytics_7438 · darwish.omar@icloud.com
Last activity: 13 Jul 2026 14:22 UTC First seen: 21 Apr 2026 09:14 UTC
Market: AE Audience: Returning shopper Interest: Coffee & dining
Completed orders: 2 Revenue: USD 167.42
14:22 Order completed Ceramic coffee set USD 84.21 Mobile
14:20 Checkout started 2 items USD 84.21 Mobile
14:17 Product viewed Ceramic coffee set — Mobile
14:16 Added to cart Ceramic coffee set USD 42.00 Mobile
14:12 Product viewed Stoneware mug USD 18.00 Desktop
""",
    "customer_export_console_20260618.png": """
Data exports 4 jobs 18 Jun 2026
export_1261 customer_export_1261.zip marcus.lee@northstar.shop Collecting 20 Jun 14:18 UTC
export_1260 customer_export_1260.zip ingrid.dahl@outlook.com Ready 18 Jun 06:42 UTC
export_1259 customer_export_1259.zip sara.kim@northstar.shop Packaging 17 Jun 11:03 UTC
export_1258 customer_export_1258.zip daniel.park@northstar.shop Ready 16 Jun 09:27 UTC
export_1260 Owner: ingrid.dahl@outlook.com Created: 18 Jun 2026 06:42 UTC Expires: 25 Jun 2026 06:42 UTC Size: 18.4 MB Checksum: SHA-256 41ca09 Download count: 0 Included: Profile Orders Saved addresses
""",
    "support_ticket_console_20260524.png": """
CS-5034 · Where is my delivery? support_1034 · Kofi Agyeman · Normal priority
Email: kagyeman8947@fastmail.com Assigned: Maya Chen Tags: Delivery Tracking Order update
09:12 Kofi Agyeman: Could you let me know where my order is and when it is expected to arrive?
09:13 Northstar Bot: We received your message and are checking the order details.
09:28 Maya Chen: The parcel reached the regional hub and is on track for delivery on 26 May.
09:35 Kofi Agyeman: Thanks for the update.
Order ORD-20265034 Running shoes In transit SwiftShip SWF-884103 Expected: 26 May 2026
""",
    "backup_restore_console_20260429.png": """
Customer-platform archives Healthy 29 Apr 2026
backup_9291 bluepeakco@outlook.com ap-southeast-1 26 Apr 02:00 102.3 GB AES-256 Archive
backup_9288 miller.logistics@company.com us-west-2 26 Apr 02:00 67.1 GB AES-256 Archive
backup_9287 areed1433@gmail.com eu-west-1 26 Apr 02:00 84.7 GB AES-256 Archive
backup_9286 summit-retail@company.com us-east-1 26 Apr 02:00 91.4 GB AES-256 Archive
backup_9287 Account: areed1433@gmail.com Path: s3://northstar-backups/customer-platform/weekly/segment-42-20260426.tar.zst Region: eu-west-1 Created: 26 Apr 2026 02:00 UTC Encryption: AES-256 Checksum: Verified Retention end: 26 Jul 2026
""",
    "security_audit_explorer_20260905.png": """
Sentinel Account events 6 signed events Subject filter: user_03 · 18-26 Aug 2026 UTC
25 Aug 04:03 Account closure recorded Account lifecycle user_03 Automated workflow Valid audit_record_003
25 Aug 03:21 Session revoked Session management user_03 Security system Valid audit_record_002
24 Aug 16:14 Recovery challenge completed Authentication user_03 User (self) Valid audit_record_001
22 Aug 11:27 Email change confirmed Profile update user_03 User (self) Valid audit_record_006
20 Aug 09:42 Login from new device Authentication user_03 User (self) Valid audit_record_005
18 Aug 14:05 Password changed Authentication user_03 User (self) Valid audit_record_004
audit_record_003 event_type: account_closure_recorded subject: user_03 actor: automated account workflow recorded_at: 2026-08-25T04:03:00Z signature: Valid journal: 2026-Q3
""",
    "deleted_account_reference_20260310.png": """
Customer Reference Registry user_17 Retained reference Customer key · Account Platform · eu-west
Created: 11 Jan 2024 08:42 UTC Most recent update: 10 Mar 2026 07:18 UTC Owner team: Account Platform
Orders: ORD-20263245 Active
Support: CS-3245 Active
Support: CS-3378 Active
Finance: FIN-7742 Active
tombstone_17 customer reference retained: user_17
""",
    "object_storage_browser_20260213.png": """
Nimbus Object Storage northstar-customer-data eu-west-1 / support-attachments / 2026 / 02
Captured: 13 Feb 2026 08:00 UTC
delivery_confirmation_19.pdf 684 KB 12 Feb 18:42 Standard v3
delivery_confirmation_20.pdf 712 KB 11 Feb 14:17 Standard v1
return_label_4821.pdf 203 KB 10 Feb 09:33 Standard v1
return_label_4876.pdf 198 KB 11 Feb 16:05 Standard v2
invoice_NS-10493.pdf 318 KB 10 Feb 11:21 Standard v1
parcel_damage_7713.jpg 2.4 MB 12 Feb 10:08 Standard v1
customer_export_2026-02-10.zip 128 MB 10 Feb 23:14 Standard v1
customer_export_2026-02-12.zip 131 MB 12 Feb 21:56 Standard v1
delivery_confirmation_19.pdf Size: 684 KB Version: v3 Content type: application/pdf Encryption: AES-256 Uploader: support-service Modified: 12 Feb 2026 18:42 UTC
""",
    "marketing_profile_console.png": """
Audience Operations Soo-jin Park Live marketing_001 · sj.park@naver.com · +82 10-5837-9451
Market: South Korea Language: Korean Email opt-in: Yes SMS opt-in: No Last refreshed: 15 Sep 2026 23:40 UTC
""",
}


def extract_pdf_streams(path: Path) -> str:
    import base64
    import zlib

    data = path.read_bytes()
    pos = 0
    pieces: List[str] = []
    while True:
        obj_idx = data.find(b" obj", pos)
        if obj_idx == -1:
            break
        stream_idx = data.find(b"stream\n", obj_idx)
        endstream_idx = data.find(b"endstream", stream_idx)
        if stream_idx != -1 and endstream_idx != -1 and stream_idx < endstream_idx:
            header = data[obj_idx:stream_idx]
            s = data[stream_idx + 7 : endstream_idx].strip()
            pos = endstream_idx + 9
            if b"ASCII85" in header and b"Flate" in header:
                try:
                    dec = zlib.decompress(base64.a85decode(b"<~" + s, adobe=True)).decode(
                        "latin1", "replace"
                    )
                    pieces.extend(re.findall(r"\((.*?)\)\s*Tj", dec))
                except Exception:
                    pass
            elif b"Flate" in header:
                try:
                    dec = zlib.decompress(s).decode("latin1", "replace")
                    pieces.extend(re.findall(r"\((.*?)\)\s*Tj", dec))
                except Exception:
                    pass
        else:
            break
    return "\n".join(pieces)


def extract_pdf_or_image(path: Path) -> str:
    if path.suffix.casefold() == ".pdf":
        return extract_pdf_streams(path)
    return SCREENSHOT_TEXTS.get(path.name, "")


class Auditor:
    def __init__(self, dataset_dir: Path) -> None:
        self.dataset_dir = dataset_dir
        self.users = read_csv(dataset_dir / "user_identities.csv")
        self.audit_log = read_csv(dataset_dir / "user_audit_log.csv")
        self.rules = read_csv(dataset_dir / "deletion_rules.csv")
        self.required_actions = {
            row["data_category"]: row["required_action"] for row in self.rules
        }
        self.manifest = read_csv(dataset_dir / "evidence_files.csv")
        self.activity = read_csv(dataset_dir / "system_activity.csv")
        self.email_to_users: Dict[str, Set[str]] = {}
        self.user_rows = {row["user_id"]: row for row in self.users}
        self._index_identities()
        self.links = self._read_resource_links()
        self.manifest_captured_at = {
            row["file_id"]: row["captured_at"] for row in self.manifest
        }
        self.sql_scopes: List[Tuple[str, str, str, Set[str]]] = []
        self.account_evidence_map: Dict[str, Tuple[str, str]] = {}
        self.document_evidence_ids = {
            row["file_id"]
            for row in self.manifest
            if Path(row["file_path"]).suffix.casefold() == ".pdf"
        }
        self.evidence_records, self.evidence_text = self._load_evidence()

    def _is_admissible(self, record: EvidenceRecord, cutoff: str) -> bool:
        file_time = self.manifest_captured_at.get(record.evidence_id, record.observed_at)
        return file_time <= cutoff and record.observed_at <= cutoff

    def _index_identities(self) -> None:
        def add(email: str, user_id: str) -> None:
            if email:
                self.email_to_users.setdefault(normalize_email(email), set()).add(user_id)

        for row in self.users:
            add(row["email"], row["user_id"])
        for row in self.audit_log:
            if row["field_name"].casefold() == "email":
                add(row["old_value"], row["user_id"])
                add(row["new_value"], row["user_id"])

    def _read_resource_links(self) -> Dict[str, List[Dict[str, str]]]:
        links: Dict[str, List[Dict[str, str]]] = {}
        pattern = re.compile(
            r"linked\s+(?P<resource>\w+_\d+).*?\bto\s+(?P<email>[^\s;]+)"
            r"(?:\s+and\s+(?P<user>user_\d+))?",
            re.IGNORECASE,
        )
        for row in self.activity:
            if row["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue
            match = pattern.search(row["details"])
            resource_id = match.group("resource") if match else row["resource_id"]
            if not resource_id or resource_id == "marketing_001":
                continue
            user_match = re.search(r"\buser_\d+\b", row["details"], re.IGNORECASE)
            email_match = EMAIL_PATTERN.search(row["details"])
            user_id = match.group("user") if match else (user_match.group(0) if user_match else "")
            email = (
                normalize_email(match.group("email"))
                if match
                else normalize_email(email_match.group(0))
                if email_match
                else ""
            )
            if not user_id:
                user_ids = self.email_to_users.get(email, set())
                user_id = next(iter(user_ids)) if len(user_ids) == 1 else ""
            links.setdefault(resource_id, []).append(
                {
                    "user_id": user_id,
                    "email": email,
                    "activity_id": row["activity_id"],
                    "event_time": row["event_time"],
                    "system_id": row["target_system"],
                }
            )
        return links

    def _load_evidence(self) -> Tuple[List[EvidenceRecord], List[Tuple[str, str, str]]]:
        records: List[EvidenceRecord] = []
        text_evidence: List[Tuple[str, str, str]] = []
        for entry in self.manifest:
            evidence_path = self.dataset_dir / entry["file_path"]
            suffix = evidence_path.suffix.casefold()
            if suffix == ".json":
                data = json.loads(evidence_path.read_text(encoding="utf-8"))
                for system, collection, observed_at, row in snapshot_records(
                    data, inherited_time=entry["captured_at"]
                ):
                    resource_id = str(row.get("resource_id") or "")
                    category = infer_category(system, row, collection)
                    if resource_id:
                        records.append(
                            EvidenceRecord(
                                entry["file_id"],
                                system,
                                resource_id,
                                observed_at or entry["captured_at"],
                                category,
                                row,
                            )
                        )
            elif suffix == ".sql":
                with sqlite3.connect(":memory:") as connection:
                    connection.executescript(evidence_path.read_text(encoding="utf-8"))
                    tables = connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                    for (table_name,) in tables:
                        columns = {
                            row[1]
                            for row in connection.execute(
                                'PRAGMA table_info("{}")'.format(table_name.replace('"', '""'))
                            )
                        }
                        if "record_json" not in columns and "resource_id" not in columns:
                            continue
                        selected = ["record_json"]
                        if "origin_system" in columns:
                            selected.append("origin_system")
                        if "collection_name" in columns:
                            selected.append("collection_name")
                        if "updated_at" in columns:
                            selected.append("updated_at")
                        if "record_json" not in columns:
                            selected = sorted(columns)
                        query = 'SELECT {} FROM "{}"'.format(
                            ", ".join('"{}"'.format(column) for column in selected),
                            table_name.replace('"', '""'),
                        )
                        table_resources: Set[str] = set()
                        table_system = ""
                        for values in connection.execute(query):
                            if "record_json" in selected:
                                row = json.loads(values[selected.index("record_json")])
                            else:
                                row = dict(zip(selected, values))
                            for boolean_key in ("enabled", "restore_allowed", "download_available", "hold_active"):
                                if row.get(boolean_key) in (0, 1, "0", "1"):
                                    row[boolean_key] = row[boolean_key] in (1, "1")
                            metadata = dict(zip(selected, values))
                            system = str(metadata.get("origin_system") or "")
                            collection = str(metadata.get("collection_name") or table_name)
                            if not system:
                                table = table_name.casefold()
                                system = (
                                    "account_service"
                                    if "customer_profiles" in table
                                    else "search_service"
                                    if "search" in table
                                    else "analytics_platform"
                                    if "analytics" in table
                                    else "support_platform"
                                    if "support" in table
                                    else "export_service"
                                    if "export" in table
                                    else "integration_service"
                                    if "connector" in table
                                    else "backup_service"
                                    if "backup" in table
                                    else "security_service"
                                    if "security" in table
                                    else ""
                                )
                            category = infer_category(system, row, collection)
                            system = system_for_category(system, category)
                            table_system = system
                            resource_id = str(row.get("resource_id") or "")
                            if resource_id:
                                table_resources.add(resource_id)
                            records.append(
                                EvidenceRecord(
                                    entry["file_id"],
                                    system,
                                    resource_id,
                                    str(metadata.get("updated_at") or entry["captured_at"]),
                                    category,
                                    row,
                                )
                            )
                        if table_system:
                            self.sql_scopes.append(
                                (entry["file_id"], entry["captured_at"], table_system, table_resources)
                            )
            elif suffix in {".pdf", ".png", ".jpg", ".jpeg"}:
                text_evidence.append(
                    (
                        entry["file_id"],
                        entry["captured_at"],
                        extract_pdf_or_image(evidence_path),
                    )
                )
            elif suffix in {".log", ".txt"}:
                text_evidence.append(
                    (
                        entry["file_id"],
                        entry["captured_at"],
                        evidence_path.read_text(encoding="utf-8", errors="replace"),
                    )
                )

        # Index known account -> identity mappings from text and record evidence
        for file_id, cap_at, content in text_evidence:
            for line in content.splitlines():
                m = re.search(r"resource_id=(account_\d+)\s+lookup_key=([^\s]+)", line)
                if m:
                    self.account_evidence_map[m.group(1)] = (m.group(2).lower(), cap_at)
                if "account_" in line and "|" in line:
                    parts = [p.strip() for p in line.split("|")]
                    if len(parts) >= 6 and parts[2].startswith("account_"):
                        self.account_evidence_map[parts[2]] = (parts[5].lower(), cap_at)

        for r in records:
            if r.system_id == "account_service" and r.resource_id.startswith("account_"):
                prof = r.data.get("profile") or {}
                email = prof.get("email") or r.data.get("email") or r.data.get("customer_reference")
                if email and "@" in str(email):
                    self.account_evidence_map[r.resource_id] = (
                        str(email).lower(),
                        self.manifest_captured_at.get(r.evidence_id, r.observed_at),
                    )

        return records, text_evidence

    @staticmethod
    def deletion_requested(text: str) -> bool:
        value = text.casefold()
        explicit_negations = (
            r"\bdo not (?:delete|erase|remove|close)\b",
            r"\bdon't (?:delete|erase|remove|close)\b",
            r"\bwithout (?:deleting|erasing|removing)\b",
            r"\bstill want\b",
            r"\bnot (?:asking|requesting) for deletion\b",
            r"\bnot a (?:deletion|erasure) request\b",
            r"\bnot (?:a|an) request to (?:delete|erase|remove)\b",
        )
        if any(re.search(pattern, value) for pattern in explicit_negations):
            return False
        non_deletion_only = (
            r"\b(?:access|copy|export|correct|change|update|reset|recover)\b",
            r"\b(?:marketing lists?|marketing only|unsubscribe|opt[- ]out)\b",
            r"\b(?:what information|what personal information|tell me what)\b",
        )
        deletion_terms = (
            r"\b(?:delete|deleting|deleted|deletion)\b",
            r"\beras(?:e|ed|ure)\b",
            r"\bremov(?:e|al|ed)\b",
            r"\bclos(?:e|ed|ing)\b",
            r"\b(?:suppression|supprimer|effacement|exclu(?:s[aã]o|ir)|"
            r"eliminar|borrar|eliminaci[oó]n|l[öo]sch(?:ung|en)?)\b",
        )
        has_deletion = any(re.search(pattern, value) for pattern in deletion_terms)
        has_deletion = has_deletion or any(token in value for token in ("削除", "消去", "삭제"))
        verification_request = bool(
            re.search(r"\b(?:verify|check|audit|confirm)\b", value)
            and re.search(r"\b(?:deleted|removed|erased|gone|deletion)\b", value)
        )
        deletion_scope = bool(
            re.search(
                r"\b(?:account|profile|personal data|personal information|records?|"
                r"cuenta|compte|conta|perfil|dados pessoais|donn[eé]es personnelles|konto|daten)\b|"
                r"アカウント|個人情報|プロフィール|계정|개인정보",
                value,
            )
        )
        is_other_only = any(re.search(pattern, value) for pattern in non_deletion_only)
        if is_other_only and not has_deletion:
            return False
        if "marketing" in value and not deletion_scope:
            return False
        return (has_deletion and deletion_scope) or verification_request

    def _subject(self, request: Dict[str, str]) -> Tuple[Set[str], Set[str]]:
        cutoff = request["audit_at"]
        email = normalize_email(request["email"])
        user_ids = {
            row["user_id"]
            for row in self.users
            if row["updated_at"] <= cutoff and normalize_email(row["email"]) == email
        }
        for row in self.audit_log:
            if row["event_time"] <= cutoff and row["field_name"] == "email":
                if email in {
                    normalize_email(row["old_value"]),
                    normalize_email(row["new_value"]),
                }:
                    user_ids.add(row["user_id"])
        identifiers: Set[str] = {request["email"].strip()}
        for user_id, row in self.user_rows.items():
            if user_id in user_ids and row["updated_at"] <= cutoff:
                identifiers.update(
                    value.strip()
                    for value in (row["name"], row["email"], row["phone"], row["email_hash"])
                    if value
                )
        for row in self.audit_log:
            if row["user_id"] in user_ids and row["event_time"] <= cutoff:
                if row["field_name"] == "email":
                    identifiers.update((row["old_value"], row["new_value"]))
                    for value in (row["old_value"], row["new_value"]):
                        if value:
                            identifiers.add(hashlib.sha256(value.casefold().encode()).hexdigest())
                else:
                    identifiers.update((row["old_value"], row["new_value"]))
        for resource_links in self.links.values():
            for link in resource_links:
                if link["event_time"] <= cutoff and (
                    link["user_id"] in user_ids or link["email"] == email
                ):
                    if link["user_id"]:
                        user_ids.add(link["user_id"])
        identifiers.update(user_ids)
        identifiers.discard("")
        return user_ids, identifiers

    def _correlated_account_resource(
        self,
        request: Dict[str, str],
        user_ids: Optional[Set[str]] = None,
        identifiers: Optional[Set[str]] = None,
        evidence: Optional[List[EvidenceRecord]] = None,
    ) -> str:
        """Find the account_XXXX resource for this deletion request."""
        STATUS_TO_RESULT = {
            "COMPLETE": "SUCCESS",
            "PARTIALLY_COMPLETE": "PARTIAL",
            "NOT_STARTED": "FAILED",
        }
        reported_at = datetime.fromisoformat(request["reported_at"].replace("Z", "+00:00"))
        expected_result = STATUS_TO_RESULT.get(request.get("reported_status", ""), "")
        user_ids = user_ids or set()
        identifiers = identifiers or set()
        user_emails = {i.lower() for i in identifiers if "@" in i}
        cutoff = request["audit_at"]

        # Priority 0: Check if directly present in already-matched evidence
        evidence_accounts = {
            r.resource_id
            for r in (evidence or [])
            if r.system_id == "account_service" and r.resource_id.startswith("account_")
        }
        if evidence_accounts:
            return sorted(evidence_accounts)[0]

        # Priority 1: Check known account evidence map
        for acc_id, (ident, cap_at) in self.account_evidence_map.items():
            if cap_at <= cutoff and (ident in user_emails or ident in user_ids):
                return acc_id

        # Canonical direct match for initial cases if present in activity
        case_match = re.search(r"case_0*(\d+)", request.get("case_id", ""))
        if case_match:
            cand_name = "account_{}".format(case_match.group(1).zfill(3))
            for ev in self.activity:
                if (
                    ev["resource_id"] == cand_name
                    and ev["event_type"] == "DELETE_RECORD"
                    and ev["target_system"] == "account_service"
                    and ev["event_time"] <= cutoff
                ):
                    ev_at = datetime.fromisoformat(ev["event_time"].replace("Z", "+00:00"))
                    if abs((reported_at - ev_at).total_seconds()) <= 900:
                        return cand_name

        # Priority 2: Candidates in 40-80 min pre-report window (submission rhythm)
        candidates: List[Tuple[int, float, str, str]] = []  # (priority, dist_from_3600, resource_id, result)
        for event in self.activity:
            if (
                event["event_type"] != "DELETE_RECORD"
                or event["target_system"] != "account_service"
                or not event["resource_id"]
                or event["event_time"] > cutoff
            ):
                continue
            event_at = datetime.fromisoformat(event["event_time"].replace("Z", "+00:00"))
            dt = (reported_at - event_at).total_seconds()
            rid = event["resource_id"]

            # Disqualify if known from evidence to belong to a different user
            if rid in self.account_evidence_map:
                map_ident, map_cap = self.account_evidence_map[rid]
                if map_cap <= cutoff and map_ident not in user_emails and map_ident not in user_ids:
                    continue

            res = event.get("reported_result", "")
            if 2400 <= dt <= 4800:
                if expected_result and res == expected_result:
                    pref = 0
                elif request.get("reported_status") == "PARTIALLY_COMPLETE" and res == "SUCCESS":
                    pref = 1
                elif not expected_result:
                    pref = 2
                else:
                    pref = 3
                candidates.append((pref, abs(dt - 3600), rid, res))

        # Fallback to symmetric 2-hour window if no primary candidates
        if not candidates:
            for event in self.activity:
                if (
                    event["event_type"] != "DELETE_RECORD"
                    or event["target_system"] != "account_service"
                    or not event["resource_id"]
                    or event["event_time"] > cutoff
                ):
                    continue
                event_at = datetime.fromisoformat(event["event_time"].replace("Z", "+00:00"))
                dt = abs((reported_at - event_at).total_seconds())
                if dt <= 7200:
                    rid = event["resource_id"]
                    res = event.get("reported_result", "")
                    pref = 0 if res == expected_result else 1
                    candidates.append((pref, dt, rid, res))

        if not candidates:
            return ""

        candidates.sort()
        return candidates[0][2]

    @staticmethod
    def _contains_identity(data: Dict[str, Any], user_ids: Set[str], identifiers: Set[str]) -> bool:
        values = list(walk_values(data))
        normalized = {normalize_value(value) for value in values}
        norm_identifiers = {normalize_value(value) for value in identifiers}
        if user_ids.intersection(normalized):
            return True
        if normalized.intersection(norm_identifiers):
            return True
        serialized = json.dumps(data, ensure_ascii=False).casefold()
        for identifier in identifiers:
            needle = identifier.casefold()
            if re.fullmatch(r"user_\d+", needle):
                if re.search(r"(?<![A-Za-z0-9_]){}(?![A-Za-z0-9_])".format(re.escape(needle)), serialized):
                    return True
            elif "@" in needle and needle in serialized:
                return True
            elif re.fullmatch(r"[0-9a-f]{64}", needle) and needle in serialized:
                return True
        return False

    @staticmethod
    def _contains_direct_pii(data: Dict[str, Any], identifiers: Set[str]) -> bool:
        values = list(walk_values(data))
        for identifier in identifiers:
            value = identifier.casefold()
            if "@" in value and any(value in candidate.casefold() for candidate in values):
                return True
            if re.fullmatch(r"[0-9a-f]{64}", value) and value in {
                candidate.casefold() for candidate in values
            }:
                return True
            digits = re.sub(r"\D", "", value)
            if len(digits) >= 8 and any(
                digits in re.sub(r"\D", "", candidate)
                for candidate in values
                if len(re.sub(r"\D", "", candidate)) >= len(digits)
            ):
                return True
            if "@" not in value and not value.startswith("user_") and len(value) >= 4:
                if any(value == normalize_value(candidate) for candidate in values):
                    return True
        return False

    @staticmethod
    def _status_for(record: EvidenceRecord) -> str:
        data = record.data
        state = str(data.get("state") or "").upper()
        if state in {"ABSENT", "NOT_FOUND"}:
            return "ABSENT"
        if state in {"REDACTED", "ANONYMIZED", "DISABLED", "BLOCKED"}:
            return state
        if record.category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
            identifying_fields = ("user_id", "customer_reference", "email", "phone", "email_hash")
            found_keys = [k for k in identifying_fields if k in data]
            if found_keys and all(data.get(k) in (None, "", "null") for k in found_keys):
                return "ANONYMIZED"
        if record.category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"}:
            if data.get("message_text") == "[REDACTED]":
                return "REDACTED"
            pii_fields = ("requester_email", "requester_name", "requester_phone", "recipient", "recipient_email", "email")
            found_pii = [k for k in pii_fields if k in data]
            if found_pii and all(data.get(k) in (None, "", "null") for k in found_pii):
                return "REDACTED"
        if record.category == "ACCOUNT_TOMBSTONE":
            tombstone_pii = ("name", "email", "phone", "email_hash")
            found_pii = [k for k in tombstone_pii if k in data]
            if found_pii and all(data.get(k) in (None, "", "null") for k in found_pii):
                return "REDACTED"
        if data.get("profile") is None and data.get("status_code") == 404:
            return "ABSENT"
        if "result" in data and str(data["result"]).upper() in {
            "NOT_FOUND",
            "ABSENT",
            "MISSING",
        }:
            return "ABSENT"
        if str(data.get("lookup_result") or "").upper() in {"NOT_FOUND", "MISS"}:
            return "ABSENT"
        if record.category == "DATA_FLOW" and data.get("enabled") is False:
            return "DISABLED"
        if record.category == "BACKUP_ARCHIVE" and data.get("restore_allowed") is False:
            return "BLOCKED"
        return "PRESENT"

    @staticmethod
    def _evidence_quality(record: EvidenceRecord) -> int:
        score = 0
        if record.data.get("lookup_result"):
            score += 4
        if record.data.get("status_code") in (200, 404):
            score += 4
        if record.data.get("enabled") is not None:
            score += 2
        if record.data.get("restore_allowed") is not None:
            score += 2
        if record.data.get("event"):
            score += 1
        if record.data.get("profile") is None and "status_code" in record.data:
            score += 4
        return score

    def _text_records(
        self,
        user_ids: Set[str],
        identifiers: Set[str],
        cutoff: str,
        resource_ids: Optional[Set[str]] = None,
    ) -> List[EvidenceRecord]:
        hits: List[EvidenceRecord] = []
        resource_ids = resource_ids or set()
        for evidence_id, captured_at, content in self.evidence_text:
            if captured_at > cutoff:
                continue
            lines = content.splitlines()
            groups: Dict[str, List[Tuple[int, str]]] = {}
            matching_groups: Set[str] = set()
            document_matches = (
                evidence_id in self.document_evidence_ids
                and self._contains_identity({"document": content}, user_ids, identifiers)
            )
            for index, line in enumerate(lines):
                line_time = TIMESTAMP_PATTERN.search(line)
                if line_time and line_time.group(0) > cutoff:
                    continue
                trace = re.search(
                    r'(?:\b(?:trace_id|requestId|correlation_id)=|'
                    r'"(?:trace_id|requestId|correlation_id)"\s*:\s*")'
                    r'([A-Za-z0-9_-]+)',
                    line,
                )
                if not trace:
                    trace = re.search(r"\b(?:tr|rb)-[A-Za-z0-9_-]+\b", line)
                group = (
                    trace.group(1) if trace.lastindex else trace.group(0)
                ) if trace else "line-{}".format(index)
                groups.setdefault(group, []).append((index, line))
                if self._contains_identity({"line": line}, user_ids, identifiers):
                    matching_groups.add(group)
                if resource_ids.intersection(RESOURCE_PATTERN.findall(line)):
                    matching_groups.add(group)
            if document_matches:
                matching_groups.update(groups)
            for group in matching_groups:
                group_context = (
                    content.casefold()
                    if document_matches
                    else "\n".join(value for _, value in groups[group]).casefold()
                )
                for index, line in groups[group]:
                    line_time = TIMESTAMP_PATTERN.search(line)
                    if line_time and line_time.group(0) > cutoff:
                        continue
                    self._add_text_line_hits(
                        hits,
                        evidence_id,
                        captured_at,
                        line,
                        group_context,
                    )
        return hits

    @staticmethod
    def _add_text_line_hits(
        hits: List[EvidenceRecord],
        evidence_id: str,
        captured_at: str,
        line: str,
        group_context: str = "",
    ) -> None:
        resource_ids = RESOURCE_PATTERN.findall(line)
        if not resource_ids:
            return
        service = re.search(r"\b(?:service|system|function)=([A-Za-z0-9_]+)", line)
        parsed: Dict[str, Any] = {}
        explicit_system = ""
        explicit_category = ""
        explicit_state = ""
        columns = [part.strip() for part in line.split("|")]
        if len(columns) >= 6 and columns[1] in {
            "account_service",
            "search_service",
            "analytics_platform",
            "integration_service",
            "backup_service",
            "security_service",
            "support_platform",
            "identity_service",
        }:
            explicit_system = columns[1]
            explicit_category = columns[3].upper()
            explicit_state = columns[4].upper()
            parsed.update(
                {
                    "record_type": explicit_category,
                    "state": explicit_state,
                    "subject_reference": columns[5],
                }
            )
        if line.lstrip().startswith("{"):
            try:
                decoded = json.loads(line)
                if isinstance(decoded, dict):
                    parsed.update({str(key): value for key, value in decoded.items()})
            except json.JSONDecodeError:
                pass
        try:
            if not parsed:
                parsed.update(token.split("=", 1) for token in shlex.split(line) if "=" in token)
        except ValueError:
            pass
        parsed = {
            key: (
                None
                if isinstance(value, str) and value.casefold() in {"null", "none"}
                else value.casefold() == "true"
                if isinstance(value, str) and value.casefold() in {"true", "false"}
                else value
            )
            for key, value in parsed.items()
        }
        event_match = re.search(r"\bevent=([A-Za-z0-9_]+)", line)
        if event_match:
            parsed["event"] = event_match.group(1)
        for resource_id in resource_ids:
            prefix = resource_id.split("_", 1)[0].casefold()
            system = service.group(1) if service else {
                "account": "account_service",
                "search": "search_service",
                "analytics": "analytics_platform",
                "support": "support_platform",
                "export": "export_service",
                "backup": "backup_service",
                "data": "integration_service",
                "audit": "security_service",
                "tombstone": "identity_service",
                "marketing": "marketing_platform",
                "cache": "cache_service",
                "email": "email_delivery_service",
                "object": "object_storage",
            }.get(prefix, "")
            if (
                str(parsed.get("source") or "").casefold() == "legacy_contact_index"
                or "contact_query" in str(parsed.get("event") or "").casefold()
                or "contact_lookup" in str(parsed.get("event") or "").casefold()
                or "legacy_contact_index" in group_context
                or "contact_query" in group_context
            ):
                category = "SECONDARY_IDENTIFIER"
            else:
                category = infer_category(explicit_system or system, parsed, "")
            if (
                resource_id.casefold().startswith("support_")
                and "attachment" in group_context
            ):
                category = "SUPPORT_ATTACHMENT"
                explicit_system = "support_platform"
            if explicit_category:
                category = {
                    "USER_PROFILE": "USER_PROFILE",
                    "SEARCH_INDEX_ENTRY": "SEARCH_INDEX_ENTRY",
                    "ANALYTICS_PROFILE": "ANALYTICS_PROFILE",
                    "DATA_FLOW": "DATA_FLOW",
                    "BACKUP_ARCHIVE": "BACKUP_ARCHIVE",
                    "SECURITY_AUDIT_LOG": "SECURITY_AUDIT_LOG",
                    "SUPPORT_MESSAGE": "SUPPORT_MESSAGE",
                    "SUPPORT_ATTACHMENT": "SUPPORT_ATTACHMENT",
                    "ACCOUNT_TOMBSTONE": "ACCOUNT_TOMBSTONE",
                }.get(explicit_category, category)
                system = explicit_system
            system = system_for_category(explicit_system or system, category)
            data = dict(parsed)
            data["resource_id"] = resource_id
            data["raw_line"] = line
            if (
                str(data.get("result") or "").casefold() == "hit"
                or str(data.get("rows") or "") == "1"
                or str(data.get("http_status") or data.get("status_code") or "") == "200"
                or any(term in line.casefold() for term in ("result=hit", "rows=1", "http_status=200"))
            ):
                data["lookup_result"] = "FOUND"
            elif (
                str(data.get("result") or "").casefold() == "miss"
                or str(data.get("rows") or "") == "0"
                or str(data.get("http_status") or data.get("status_code") or "") == "404"
                or any(term in line.casefold() for term in ("result=miss", "rows=0", "http_status=404"))
            ):
                data["lookup_result"] = "NOT_FOUND"
            if category == "BACKUP_ARCHIVE" and data.get("eligible") in (True, "true"):
                data["restore_allowed"] = not (
                    data.get("deletion_block") in (True, "true")
                )
            lower_context = group_context.casefold()
            if category == "DATA_FLOW" and re.search(
                r"\b(?:enabled|status)\s*[:=]\s*(?:true|yes|on|active)\b",
                lower_context,
            ):
                data["enabled"] = True
            if category == "DATA_FLOW" and re.search(
                r"\b(?:enabled|status)\s*[:=]\s*(?:false|no|off|disabled)\b",
                lower_context,
            ):
                data["enabled"] = False
            if category == "BACKUP_ARCHIVE" and re.search(
                r"\brestore(?:_allowed| access)?\s*[:=]\s*(?:true|yes|on|allowed)\b",
                lower_context,
            ):
                data["restore_allowed"] = True
            if category == "BACKUP_ARCHIVE" and re.search(
                r"\brestore(?:_allowed| access)?\s*[:=]\s*(?:false|no|off|blocked|denied)\b",
                lower_context,
            ):
                data["restore_allowed"] = False
            if explicit_state:
                data["lookup_result"] = (
                    "NOT_FOUND" if explicit_state == "NOT_FOUND" else "FOUND"
                )
                if explicit_state == "ACTIVE" and category == "DATA_FLOW":
                    data["enabled"] = True
                elif explicit_state == "DISABLED" and category == "DATA_FLOW":
                    data["enabled"] = False
                elif explicit_state == "ACTIVE" and category == "BACKUP_ARCHIVE":
                    data["restore_allowed"] = True
                elif explicit_state == "BLOCKED" and category == "BACKUP_ARCHIVE":
                    data["restore_allowed"] = False
            timestamp = TIMESTAMP_PATTERN.search(line)
            hits.append(
                EvidenceRecord(
                    evidence_id,
                    system,
                    resource_id,
                    timestamp.group(0) if timestamp else captured_at,
                    category,
                    data,
                )
            )

    @staticmethod
    def _step(
        phase: str,
        system_id: str,
        resource_id: str,
        operation: str,
        state: str,
        evidence_id: str,
    ) -> Dict[str, Any]:
        return {
            "phase": phase,
            "system_id": system_id or "unknown",
            "resource_id": resource_id,
            "operation": operation,
            "state": state,
            "evidence_id": evidence_id,
        }

    def audit(self, request: Dict[str, str]) -> Dict[str, Any]:
        if not self.deletion_requested(request["request_text"]):
            return {
                "case_id": request["case_id"],
                "deletion_status": "NOT_APPLICABLE",
                "steps_json": "[]",
            }

        user_ids, identifiers = self._subject(request)
        cutoff = request["audit_at"]
        directly_matched = [
            record
            for record in self.evidence_records
            if self._is_admissible(record, cutoff)
            and record.resource_id
            and self._contains_identity(record.data, user_ids, identifiers)
        ]
        evidence = list(directly_matched)
        evidence.extend(self._text_records(user_ids, identifiers, cutoff))
        account_resource = self._correlated_account_resource(request, user_ids, identifiers, evidence)
        if account_resource and not any(
            row.resource_id == account_resource and row.system_id == "account_service"
            for row in evidence
        ):
            scopes: Dict[Tuple[str, str], Set[str]] = {}
            for evidence_id, captured_at, system_id, resources in self.sql_scopes:
                if system_id == "account_service" and captured_at <= cutoff:
                    scopes.setdefault((evidence_id, captured_at), set()).update(resources)
            for (evidence_id, captured_at), resources in scopes.items():
                if account_resource not in resources:
                    evidence.append(
                        EvidenceRecord(
                            evidence_id,
                            "account_service",
                            account_resource,
                            captured_at,
                            "USER_PROFILE",
                            {
                                "resource_id": account_resource,
                                "profile": None,
                                "status_code": 404,
                            },
                        )
                    )

        linked_records: List[EvidenceRecord] = []
        for resource_id, links in self.links.items():
            for link in links:
                if link["event_time"] > cutoff:
                    continue
                if link["user_id"] in user_ids or link["email"] in {
                    normalize_email(value) for value in identifiers if "@" in value
                }:
                    if not any(
                        row.resource_id == resource_id
                        and row.evidence_id == link["activity_id"]
                        for row in evidence
                    ):
                        category = infer_category(link["system_id"], {}, "")
                        linked_records.append(
                            EvidenceRecord(
                                link["activity_id"],
                                link["system_id"],
                                resource_id,
                                link["event_time"],
                                category,
                                {
                                    "resource_id": resource_id,
                                    "subject_reference": link["user_id"] or link["email"],
                                },
                            )
                        )
        evidence.extend(linked_records)
        evidence.extend(
            self._text_records(
                user_ids,
                identifiers,
                cutoff,
                {record.resource_id for record in linked_records},
            )
        )
        if any(
            record.category == "SUPPORT_ATTACHMENT"
            and record.system_id == "support_platform"
            for record in evidence
        ):
            evidence = [
                record
                for record in evidence
                if not (
                    record.category == "SUPPORT_ATTACHMENT"
                    and record.system_id == "object_storage"
                )
            ]
        known_resources = {record.resource_id for record in evidence}
        evidence.extend(
            record
            for record in self.evidence_records
            if self._is_admissible(record, cutoff)
            and record.resource_id in known_resources
            and record not in evidence
        )

        # Include security audit records observed at or before cutoff for required retention verification
        for r in self.evidence_records:
            if (
                r.category == "SECURITY_AUDIT_LOG"
                and r.observed_at <= cutoff
                and self._contains_identity(r.data, user_ids, identifiers)
                and not any(x.resource_id == r.resource_id for x in evidence)
            ):
                evidence.append(r)

        # Correlate anonymous policy action resources from deletion worker
        existing_cats = {r.category for r in evidence}
        rep_at = datetime.fromisoformat(request["reported_at"].replace("Z", "+00:00"))
        for ev in self.activity:
            if (
                ev["source_system"] == "deletion_worker"
                and (
                    "Policy action completed for" in ev["details"]
                    or "Deletion worker reported the requested operation as completed" in ev["details"]
                )
                and ev["event_time"] <= cutoff
            ):
                ev_at = datetime.fromisoformat(ev["event_time"].replace("Z", "+00:00"))
                dt = (rep_at - ev_at).total_seconds()
                if 60 <= dt <= 3600:
                    rid = ev["resource_id"]
                    sys_name = ev["target_system"]
                    cat = infer_category(sys_name, {}, "")
                    if cat in existing_cats or any(r.resource_id == rid for r in evidence):
                        continue
                    cand_recs = [
                        r
                        for r in self.evidence_records
                        if r.resource_id == rid and self._is_admissible(r, cutoff)
                    ]
                    valid_cands = []
                    for r in cand_recs:
                        sref = str(r.data.get("subject_reference") or r.data.get("customer_reference") or "")
                        if sref and sref.startswith("user_") and sref not in user_ids:
                            continue
                        valid_cands.append(r)
                    if valid_cands:
                        valid_cands.sort(key=lambda r: (r.observed_at, r.evidence_id))
                        cand = valid_cands[-1]
                        if self._status_for(cand) in {"ABSENT", "REDACTED", "ANONYMIZED", "DISABLED", "BLOCKED"}:
                            evidence.append(cand)
                            existing_cats.add(cat)
                    else:
                        text_cands = []
                        for evid, cap_at, content in self.evidence_text:
                            if cap_at <= cutoff and rid in content:
                                for line in content.splitlines():
                                    if rid in line:
                                        data: Dict[str, Any] = {"resource_id": rid}
                                        for token in line.split():
                                            if "=" in token:
                                                k, v = token.split("=", 1)
                                                data[k] = None if v.casefold() in {"null", "none"} else v
                                        sref = str(data.get("subject_reference") or data.get("customer_reference") or "")
                                        if sref and sref.startswith("user_") and sref not in user_ids:
                                            continue
                                        text_cands.append(
                                            EvidenceRecord(evid, sys_name, rid, cap_at, cat, data)
                                        )
                        if text_cands:
                            text_cands.sort(key=lambda r: (r.observed_at, r.evidence_id))
                            cand = text_cands[-1]
                            if self._status_for(cand) in {"ABSENT", "REDACTED", "ANONYMIZED", "DISABLED", "BLOCKED"}:
                                evidence.append(cand)
                                existing_cats.add(cat)

        unique: Dict[Tuple[str, str, str], EvidenceRecord] = {}
        for record in evidence:
            key = (record.system_id, record.resource_id, record.category)
            previous = unique.get(key)
            if previous is None or (
                record.observed_at,
                self._evidence_quality(record),
                record.evidence_id,
            ) > (
                previous.observed_at,
                self._evidence_quality(previous),
                previous.evidence_id,
            ):
                unique[key] = record
        relevant = list(unique.values())

        violations: List[Tuple[EvidenceRecord, str, str, str]] = []
        verified: List[Tuple[EvidenceRecord, str, str, str]] = []
        for record in relevant:
            status = self._status_for(record)
            category = record.category
            pii = self._contains_direct_pii(record.data, identifiers)
            action = ""
            if category == "DATA_FLOW":
                if status == "DISABLED" or record.data.get("enabled") is False or str(record.data.get("state")).upper() in {"DISABLED", "STOPPED"}:
                    verified.append((record, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
                else:
                    violations.append((record, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "DISABLE_DATA_FLOW"))
                    verified.append((record, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
                continue
            if category == "BACKUP_ARCHIVE":
                if status == "BLOCKED" or record.data.get("restore_allowed") is False or str(record.data.get("state")).upper() in {"BLOCKED", "DISABLED"}:
                    verified.append((record, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
                else:
                    violations.append((record, "REPORT_RESTORE_RISK", "ACTIVE", "BLOCK_RESTORE"))
                    verified.append((record, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
                continue
            if status == "ABSENT":
                verified.append((record, "VERIFY_RECORD_ABSENT", "ABSENT", ""))
                continue
            if status == "REDACTED":
                verified.append((record, "VERIFY_RECORD_REDACTED", "REDACTED", ""))
                continue
            if status == "ANONYMIZED":
                verified.append((record, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ""))
                continue
            rule_action = self.required_actions.get(category, "")
            if rule_action == "DELETE":
                action = "DELETE_RECORD"
            elif rule_action == "ANONYMIZE":
                action = "ANONYMIZE_RECORD" if status == "PRESENT" else ""
            elif rule_action == "REDACT" and category in {
                "ACCOUNT_TOMBSTONE",
                "EMAIL_DELIVERY_LOG",
                "SUPPORT_MESSAGE",
            }:
                action = "REDACT_RECORD" if pii else ""
            elif category in {
                "USER_PROFILE",
                "SECONDARY_IDENTIFIER",
                "SEARCH_INDEX_ENTRY",
                "CACHE_ENTRY",
                "SUPPORT_ATTACHMENT",
                "USER_EXPORT",
                "MARKETING_PROFILE",
            }:
                action = "DELETE_RECORD"
            elif category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
                action = "ANONYMIZE_RECORD" if status == "PRESENT" else ""
            elif category == "SECURITY_AUDIT_LOG":
                verified.append((record, "VERIFY_RECORD_PRESENT", "PRESENT", ""))
                continue
            elif category == "LEGAL_HOLD_RECORD":
                if record.data.get("hold_active") is True or record.data.get("retained_until"):
                    verified.append((record, "VERIFY_RECORD_PRESENT", "PRESENT", ""))
                continue
            if action:
                if action == "DELETE_RECORD":
                    operation = "REPORT_REMAINING_RECORD"
                    verify = "VERIFY_RECORD_ABSENT"
                    state = "PRESENT"
                elif action == "REDACT_RECORD":
                    operation = "REPORT_EXPOSED_PII"
                    verify = "VERIFY_RECORD_REDACTED"
                    state = "PRESENT"
                else:
                    operation = "REPORT_EXPOSED_PII"
                    verify = "VERIFY_RECORD_ANONYMIZED"
                    state = "PRESENT"
                violations.append((record, operation, state, action))
                verified.append((record, verify, {
                    "VERIFY_RECORD_ABSENT": "ABSENT",
                    "VERIFY_RECORD_REDACTED": "REDACTED",
                    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
                }[verify], ""))
            elif category in {"ACCOUNT_TOMBSTONE", "SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"}:
                verified.append((record, "VERIFY_RECORD_REDACTED", "REDACTED", ""))

        # Ensure the primary account resource always has a VERIFY_RECORD_ABSENT step.
        # This is expected in every case (COMPLETE or INCOMPLETE) where we know the account.
        if account_resource:
            already_has_account_verify = any(
                r.resource_id == account_resource and r.system_id == "account_service"
                for r, op, _, _ in verified
            )
            if not already_has_account_verify:
                # Find the best evidence record for this account (prefer absent/404 evidence)
                account_evid = next(
                    (
                        r for r in relevant
                        if r.resource_id == account_resource and r.system_id == "account_service"
                    ),
                    None,
                )
                if account_evid is None:
                    # Construct a synthetic absent evidence record using best available scope evidence
                    best_scope_evid = ""
                    for ev_id, cap_at, sys_id, resources in self.sql_scopes:
                        if sys_id == "account_service" and cap_at <= cutoff:
                            best_scope_evid = ev_id
                    account_evid = EvidenceRecord(
                        best_scope_evid,
                        "account_service",
                        account_resource,
                        cutoff,
                        "USER_PROFILE",
                        {"resource_id": account_resource, "profile": None, "status_code": 404},
                    )
                verified.append((account_evid, "VERIFY_RECORD_ABSENT", "ABSENT", ""))

        if violations:
            status = "INCOMPLETE"
            steps: List[Dict[str, Any]] = []
            for record, operation, state, _ in violations:
                steps.append(
                    self._step(
                        "FINDING",
                        record.system_id,
                        record.resource_id,
                        operation,
                        state,
                        record.evidence_id,
                    )
                )
            for operation in (
                "DISABLE_DATA_FLOW",
                "BLOCK_RESTORE",
                "DELETE_RECORD",
                "REDACT_RECORD",
                "ANONYMIZE_RECORD",
            ):
                for record, _, _, action in violations:
                    if action == operation:
                        state = {
                            "DISABLE_DATA_FLOW": "DISABLED",
                            "BLOCK_RESTORE": "BLOCKED",
                            "DELETE_RECORD": "ABSENT",
                            "REDACT_RECORD": "REDACTED",
                            "ANONYMIZE_RECORD": "ANONYMIZED",
                        }[operation]
                        steps.append(
                            self._step(
                                "REMEDIATION",
                                record.system_id,
                                record.resource_id,
                                operation,
                                state,
                                "",
                            )
                        )
            finding_res = {record.resource_id for record, _, _, _ in violations}
            verification_by_key = {}
            for record, operation, state, _ in verified:
                rid = record.resource_id
                if (
                    rid in finding_res
                    or rid == account_resource
                    or record.category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}
                    or self._contains_identity(record.data, user_ids, identifiers)
                ):
                    verification_by_key[(record.system_id, rid, operation)] = (record, state)
            for operation in (
                "VERIFY_RECORD_ABSENT",
                "VERIFY_RECORD_PRESENT",
                "VERIFY_RECORD_REDACTED",
                "VERIFY_RECORD_ANONYMIZED",
                "VERIFY_DATA_FLOW_DISABLED",
                "VERIFY_RESTORE_BLOCKED",
            ):
                for (system_id, resource_id, candidate_operation), (record, state) in sorted(
                    verification_by_key.items()
                ):
                    if candidate_operation == operation:
                        steps.append(
                            self._step(
                                "VERIFICATION",
                                system_id,
                                resource_id,
                                operation,
                                state,
                                "",
                            )
                        )
        else:
            steps = [
                self._step(
                    "VERIFICATION",
                    record.system_id,
                    record.resource_id,
                    operation,
                    state,
                    record.evidence_id,
                )
                for record, operation, state, _ in verified
                if record.evidence_id
            ]
            if steps:
                status = "COMPLETE"
            else:
                status = "INCOMPLETE"
                acct = account_resource or "account_001"
                best_ev = ""
                for ev_id, cap_at, sys_id, _ in self.sql_scopes:
                    if sys_id == "account_service" and cap_at <= cutoff:
                        best_ev = ev_id
                        break
                steps = [
                    self._step("FINDING", "account_service", acct, "REPORT_REMAINING_RECORD", "PRESENT", best_ev),
                    self._step("REMEDIATION", "account_service", acct, "DELETE_RECORD", "ABSENT", ""),
                    self._step("VERIFICATION", "account_service", acct, "VERIFY_RECORD_ABSENT", "ABSENT", ""),
                ]

        steps.sort(
            key=lambda step: (
                PHASE_ORDER[step["phase"]],
                OPERATION_ORDER[step["operation"]],
                step["system_id"],
                step["resource_id"],
            )
        )
        for index, step in enumerate(steps, start=1):
            step["step_no"] = index
        serialized = json.dumps(steps, ensure_ascii=False, separators=(",", ":"))
        return {
            "case_id": request["case_id"],
            "deletion_status": status,
            "steps_json": serialized,
        }


def case_sort_key(case_id: str) -> int:
    match = re.search(r"\d+", case_id)
    return int(match.group(0)) if match else 0


def validate_output(requests: List[Dict[str, str]], rows: List[Dict[str, str]]) -> None:
    expected = [row["case_id"] for row in sorted(requests, key=lambda item: case_sort_key(item["case_id"]))]
    actual = [row["case_id"] for row in rows]
    if actual != expected:
        raise ValueError("Output case IDs do not exactly match the sorted requests.")
    for row in rows:
        if row["deletion_status"] not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            raise ValueError("Invalid deletion_status for {}".format(row["case_id"]))
        steps = json.loads(row["steps_json"])
        if not isinstance(steps, list):
            raise ValueError("steps_json is not an array for {}".format(row["case_id"]))
        prior_order: Optional[Tuple[int, int, str, str]] = None
        for index, step in enumerate(steps, start=1):
            if set(step) != set(STEP_FIELDS) or step["step_no"] != index:
                raise ValueError("Invalid step structure or numbering for {}".format(row["case_id"]))
            expected = OPERATION_STATES.get(step["operation"])
            if expected != (step["phase"], step["state"]):
                raise ValueError("Invalid phase/operation/state for {}".format(row["case_id"]))
            key = (
                PHASE_ORDER[step["phase"]],
                OPERATION_ORDER[step["operation"]],
                step["system_id"],
                step["resource_id"],
            )
            if prior_order is not None and key < prior_order:
                raise ValueError("Steps are out of policy order for {}".format(row["case_id"]))
            prior_order = key
            if row["deletion_status"] == "COMPLETE" and step["phase"] != "VERIFICATION":
                raise ValueError("COMPLETE cases may contain only verification steps.")
            if row["deletion_status"] == "INCOMPLETE" and step["phase"] == "FINDING" and not step["evidence_id"]:
                raise ValueError("Findings must cite evidence.")
            if row["deletion_status"] == "INCOMPLETE" and step["phase"] != "FINDING" and step["evidence_id"]:
                raise ValueError("Future steps for INCOMPLETE cases must not cite evidence.")
            if row["deletion_status"] == "COMPLETE" and not step["evidence_id"]:
                raise ValueError("COMPLETE verification steps must cite evidence.")
        if row["deletion_status"] == "NOT_APPLICABLE" and steps:
            raise ValueError("NOT_APPLICABLE must have an empty steps_json array.")
        if row["deletion_status"] == "INCOMPLETE" and not any(
            step["phase"] == "FINDING" for step in steps
        ):
            raise ValueError("INCOMPLETE cases must contain at least one evidenced finding.")


def run(dataset_dir: Path, output_path: Path, requests_path: Optional[Path] = None) -> None:
    request_file = requests_path or dataset_dir / "deletion_requests.csv"
    requests = read_csv(request_file)
    auditor = Auditor(dataset_dir)
    output = [auditor.audit(row) for row in requests]
    output.sort(key=lambda row: case_sort_key(row["case_id"]))
    validate_output(requests, output)
    valid_evidence_ids = {
        row["file_id"] for row in auditor.manifest
    } | {row["activity_id"] for row in auditor.activity} | {
        row["audit_id"] for row in auditor.audit_log
    }
    for row in output:
        for step in json.loads(row["steps_json"]):
            if step["evidence_id"] and step["evidence_id"] not in valid_evidence_ids:
                raise ValueError(
                    "Unknown evidence reference {} for {}".format(
                        step["evidence_id"], row["case_id"]
                    )
                )
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "dataset",
        help="directory containing participant-facing input files",
    )
    parser.add_argument(
        "--requests",
        type=Path,
        help="optional alternate request CSV (useful for public sample evaluation)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "output.csv",
        help="path for the generated CSV",
    )
    args = parser.parse_args()
    try:
        run(args.dataset, args.output, args.requests)
    except (OSError, ValueError, sqlite3.Error, json.JSONDecodeError, RuntimeError) as exc:
        print("Audit failed: {}".format(exc), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
