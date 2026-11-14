"""Encrypted offline vault management with atomic commits, monthly archiving, and corruption quarantine."""

from __future__ import annotations

import copy
import json
import os
import re
import time
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Protocol

from .crypto import (
    DEFAULT_PBKDF2_ITERATIONS,
    VaultCryptoError,
    decrypt_json_envelope,
    encrypt_json_envelope,
    hash_password,
    verify_password,
)

VAULT_STORAGE_KEY = "vaultpos_encrypted_vault_v1"
SESSIONS_STORAGE_KEY = "vaultpos_live_sessions_v1"
CONFIG_STORAGE_KEY = "vaultpos_park_config_v2"
SEQ_STORAGE_KEY = "vaultpos_receipt_seq_v1"
PENDING_COMMIT_STORAGE_KEY = "vaultpos_pending_commit_v1"
ARCHIVE_INDEX_KEY = "vaultpos_archive_index_v1"
ARCHIVE_PREFIX = "vaultpos_archive_"
QUARANTINE_PREFIX = "vaultpos_quarantine_v1_"

MIN_OWNER_PASSWORD_LENGTH = 8
SUPPORTED_PAYMENT_MODES = ("CASH", "UPI / DESK", "UPI / QR")

_MONTH_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")


class VaultAuthError(ValueError):
    """Raised when vault initialization or owner password verification fails."""


class VaultReadOnlyError(RuntimeError):
    """Raised when write operations are attempted while the vault is in read-only quarantine fallback."""


class StorageBackend(Protocol):
    """Abstract key-value storage backend for local persistence."""

    def get(self, key: str) -> Any:
        ...

    def set(self, key: str, value: Any) -> None:
        ...

    def delete(self, key: str) -> None:
        ...

    def keys(self) -> list[str]:
        ...


class MemoryStorage:
    """In-memory key-value storage backend (deep-copied for isolation)."""

    def __init__(self, initial: dict[str, Any] | None = None) -> None:
        self._data: dict[str, Any] = copy.deepcopy(initial) if initial else {}

    def get(self, key: str) -> Any:
        return copy.deepcopy(self._data.get(key))

    def set(self, key: str, value: Any) -> None:
        self._data[key] = copy.deepcopy(value)

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def keys(self) -> list[str]:
        return sorted(self._data.keys())


class JsonFileStorage:
    """Atomic single-file JSON key-value store for offline desktop deployments."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultCryptoError(f"Storage file {self.path} is unreadable JSON") from exc
        if not isinstance(data, dict):
            raise VaultCryptoError(f"Storage file {self.path} must contain a JSON object")
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_name(f".{self.path.name}.tmp.{os.getpid()}")
        tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp_path, self.path)

    def get(self, key: str) -> Any:
        return copy.deepcopy(self._load().get(key))

    def set(self, key: str, value: Any) -> None:
        data = self._load()
        data[key] = copy.deepcopy(value)
        self._save(data)

    def delete(self, key: str) -> None:
        data = self._load()
        if key in data:
            del data[key]
            self._save(data)

    def keys(self) -> list[str]:
        return sorted(self._load().keys())


def _to_paise(amount_inr: int | float | str | Decimal) -> int:
    quantized = Decimal(str(amount_inr)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return int(quantized * 100)


def _format_inr(paise: int) -> str:
    return f"{Decimal(paise) / Decimal(100):.2f}"


class VaultStore:
    """Offline encrypted POS vault with crash recovery, quarantine fallback, and monthly archiving."""

    def __init__(
        self,
        storage: StorageBackend | None = None,
        *,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    ) -> None:
        self.storage: StorageBackend = storage if storage is not None else MemoryStorage()
        self.iterations = iterations
        self.read_only = False
        self.quarantine_reason: str | None = None
        self.last_quarantine_key: str | None = None

    def is_initialized(self) -> bool:
        config = self.storage.get(CONFIG_STORAGE_KEY)
        return isinstance(config, dict) and isinstance(config.get("auth"), dict)

    def _require_writable(self) -> None:
        if self.read_only:
            raise VaultReadOnlyError(
                f"Vault is locked in read-only recovery mode ({self.quarantine_reason or 'corrupted state'}). "
                f"Restore from backup first (quarantine: {self.last_quarantine_key})."
            )

    def _require_auth(self, owner_password: str) -> dict[str, Any]:
        config = self.storage.get(CONFIG_STORAGE_KEY)
        if not isinstance(config, dict) or not isinstance(config.get("auth"), dict):
            raise VaultAuthError("Vault has not been initialized")
        if not verify_password(owner_password, config["auth"]):
            raise VaultAuthError("Invalid owner password")
        return config

    def _next_quarantine_key(self) -> str:
        ts_ms = int(time.time() * 1000)
        candidate = f"{QUARANTINE_PREFIX}{ts_ms}"
        existing = set(self.storage.keys())
        while candidate in existing:
            ts_ms += 1
            candidate = f"{QUARANTINE_PREFIX}{ts_ms}"
        return candidate

    def _quarantine(self, reason: str, corrupted_keys: list[str]) -> str:
        snapshot = {key: self.storage.get(key) for key in corrupted_keys}
        q_key = self._next_quarantine_key()
        self.storage.set(
            q_key,
            {
                "schema": "VAULTPOS_QUARANTINE_V1",
                "quarantined_at": datetime.now(timezone.utc).isoformat(),
                "reason": reason,
                "corrupted_keys": corrupted_keys,
                "snapshot": snapshot,
            },
        )
        self.read_only = True
        self.quarantine_reason = reason
        self.last_quarantine_key = q_key
        return q_key

    def _encrypt_slot(self, slot_key: str, payload: Any, password: str) -> None:
        envelope = encrypt_json_envelope(
            payload,
            password,
            aad=slot_key.encode("utf-8"),
            iterations=self.iterations,
        )
        self.storage.set(slot_key, envelope)

    def _decrypt_slot(self, slot_key: str, password: str) -> Any:
        raw = self.storage.get(slot_key)
        if raw is None:
            raise VaultCryptoError(f"Missing required encrypted storage slot: {slot_key}")
        try:
            return decrypt_json_envelope(raw, password, aad=slot_key.encode("utf-8"))
        except VaultCryptoError:
            raise
        except Exception as exc:  # pragma: no cover - defensive guard for arbitrary corrupt blobs
            raise VaultCryptoError(f"Corrupted storage slot {slot_key}: {exc}") from exc

    def initialize(
        self,
        owner_password: str,
        *,
        park_name: str = "VaultPOS Terminal",
        upi_vpa: str = "merchant@upi",
    ) -> dict[str, Any]:
        """Initialize salted owner credentials and empty AES-256-GCM encrypted vaults."""
        if len(owner_password) < MIN_OWNER_PASSWORD_LENGTH:
            raise VaultAuthError(f"Owner password must be at least {MIN_OWNER_PASSWORD_LENGTH} characters")
        config = {
            "schema": "VAULTPOS_CONFIG_V2",
            "park_name": park_name.strip() or "VaultPOS Terminal",
            "upi_vpa": upi_vpa.strip() or "merchant@upi",
            "currency": "INR",
            "auth": hash_password(owner_password, iterations=self.iterations),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.storage.set(CONFIG_STORAGE_KEY, config)
        self.storage.set(SEQ_STORAGE_KEY, {"last_date": "", "seq": 0})
        self.storage.set(ARCHIVE_INDEX_KEY, [])
        self.storage.delete(PENDING_COMMIT_STORAGE_KEY)
        self._encrypt_slot(VAULT_STORAGE_KEY, {"receipts": []}, owner_password)
        self._encrypt_slot(SESSIONS_STORAGE_KEY, {"sessions": []}, owner_password)
        self.read_only = False
        self.quarantine_reason = None
        self.last_quarantine_key = None
        return self.get_public_config()

    def get_public_config(self) -> dict[str, Any]:
        """Return non-secret store configuration without exposing the password hash."""
        config = self.storage.get(CONFIG_STORAGE_KEY)
        if not isinstance(config, dict):
            return {}
        return {k: v for k, v in config.items() if k != "auth"}

    def unlock(self, owner_password: str) -> dict[str, Any]:
        """Verify owner password, replay any valid pending commit, and audit encrypted vaults.

        If either the pending commit journal or an active vault fails GCM authentication or
        structural checks, automatically quarantines corrupted snapshots under
        `vaultpos_quarantine_v1_<unix_ms>` and locks the store in read-only fallback mode.
        """
        self._require_auth(owner_password)
        pending_status = self.recover_pending_commit(owner_password)

        corrupted: list[str] = []
        vault_data: dict[str, Any] | None = None
        sessions_data: dict[str, Any] | None = None

        try:
            vault_data = self._decrypt_slot(VAULT_STORAGE_KEY, owner_password)
            if not isinstance(vault_data, dict) or not isinstance(vault_data.get("receipts"), list):
                raise VaultCryptoError("Ledger structure invalid")
        except VaultCryptoError:
            corrupted.append(VAULT_STORAGE_KEY)

        try:
            sessions_data = self._decrypt_slot(SESSIONS_STORAGE_KEY, owner_password)
            if not isinstance(sessions_data, dict) or not isinstance(sessions_data.get("sessions"), list):
                raise VaultCryptoError("Sessions structure invalid")
        except VaultCryptoError:
            corrupted.append(SESSIONS_STORAGE_KEY)

        if corrupted:
            q_key = self._quarantine("Vault integrity verification failed on startup", corrupted)
            return {
                "status": "quarantined_read_only",
                "read_only": True,
                "quarantine_key": q_key,
                "corrupted_keys": corrupted,
                "pending_recovery": pending_status,
            }

        return {
            "status": "ok",
            "read_only": self.read_only,
            "receipt_count": len(vault_data["receipts"]),
            "active_sessions": len(sessions_data["sessions"]),
            "pending_recovery": pending_status,
        }

    def recover_pending_commit(self, owner_password: str) -> str:
        """Complete an interrupted atomic sale commit or quarantine corrupted journal entries."""
        self._require_auth(owner_password)
        if self.storage.get(PENDING_COMMIT_STORAGE_KEY) is None:
            return "none"

        try:
            pending = self._decrypt_slot(PENDING_COMMIT_STORAGE_KEY, owner_password)
            receipt = pending["receipt"]
            seq_state = pending["seq_state"]
            vault_data = self._decrypt_slot(VAULT_STORAGE_KEY, owner_password)
        except Exception:
            self._quarantine(
                "Corrupted pending commit journal detected during crash recovery",
                [PENDING_COMMIT_STORAGE_KEY],
            )
            self.storage.delete(PENDING_COMMIT_STORAGE_KEY)
            return "quarantined"

        existing_ids = {item.get("receipt_no") for item in vault_data["receipts"]}
        if receipt.get("receipt_no") not in existing_ids:
            vault_data["receipts"].append(receipt)
            self._encrypt_slot(VAULT_STORAGE_KEY, vault_data, owner_password)
        self.storage.set(SEQ_STORAGE_KEY, seq_state)
        self.storage.delete(PENDING_COMMIT_STORAGE_KEY)
        return "replayed"

    def _compute_next_receipt_seq(self, now: datetime) -> tuple[str, dict[str, Any]]:
        date_str = now.strftime("%y%m%d")
        current = self.storage.get(SEQ_STORAGE_KEY) or {"last_date": "", "seq": 0}
        next_num = int(current.get("seq", 0)) + 1 if current.get("last_date") == date_str else 1
        receipt_no = f"VP-{date_str}-{next_num:04d}"
        return receipt_no, {"last_date": date_str, "seq": next_num}

    def record_sale(
        self,
        owner_password: str,
        *,
        items: list[dict[str, Any]],
        payment_mode: str = "CASH",
        cash_tendered: float | str | Decimal | None = None,
        payment_reference: str = "",
        customer_name: str = "Walk-in Guest",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Validate payment invariants, write crash-safe journal, and append an encrypted receipt."""
        self._require_auth(owner_password)
        self._require_writable()

        if payment_mode not in SUPPORTED_PAYMENT_MODES:
            raise ValueError(f"Unsupported payment mode {payment_mode!r}; expected one of {SUPPORTED_PAYMENT_MODES}")
        if not items:
            raise ValueError("Cannot record a sale with zero line items")

        normalized_items: list[dict[str, Any]] = []
        total_paise = 0
        for item in items:
            qty = int(item.get("qty", 1))
            if qty <= 0:
                raise ValueError("Item quantity must be positive")
            unit_paise = _to_paise(item["unit_price"])
            if unit_paise < 0:
                raise ValueError("Unit price cannot be negative")
            line_paise = qty * unit_paise
            total_paise += line_paise
            normalized_items.append(
                {
                    "name": str(item["name"]),
                    "qty": qty,
                    "unit_price": _format_inr(unit_paise),
                    "line_total": _format_inr(line_paise),
                }
            )

        if payment_mode == "CASH":
            if cash_tendered is None:
                raise ValueError("Cash received must be at least the grand total")
            tendered_paise = _to_paise(cash_tendered)
            if tendered_paise < total_paise:
                raise ValueError("Cash received must be at least the grand total")
            change_paise = tendered_paise - total_paise
        else:
            tendered_paise = total_paise
            change_paise = 0

        timestamp = now if now is not None else datetime.now(timezone.utc)
        receipt_no, next_seq = self._compute_next_receipt_seq(timestamp)
        config = self.get_public_config()

        receipt = {
            "receipt_no": receipt_no,
            "created_at": timestamp.isoformat(),
            "month": timestamp.strftime("%Y-%m"),
            "park_name": config.get("park_name", "VaultPOS Terminal"),
            "upi_vpa": config.get("upi_vpa", "merchant@upi"),
            "customer_name": customer_name.strip() or "Walk-in Guest",
            "items": normalized_items,
            "total_amount": _format_inr(total_paise),
            "payment_mode": payment_mode,
            "cash_tendered": _format_inr(tendered_paise),
            "change_due": _format_inr(change_paise),
            "payment_reference": payment_reference.strip(),
        }

        # Two-step durable commit via encrypted pending journal
        self._encrypt_slot(
            PENDING_COMMIT_STORAGE_KEY,
            {"receipt": receipt, "seq_state": next_seq},
            owner_password,
        )
        vault_data = self._decrypt_slot(VAULT_STORAGE_KEY, owner_password)
        vault_data["receipts"].append(receipt)
        self._encrypt_slot(VAULT_STORAGE_KEY, vault_data, owner_password)
        self.storage.set(SEQ_STORAGE_KEY, next_seq)
        self.storage.delete(PENDING_COMMIT_STORAGE_KEY)
        return receipt

    def start_session(
        self,
        owner_password: str,
        *,
        band_id: str,
        guest_name: str,
        duration_minutes: int,
        started_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Start an encrypted timed play session in `vaultpos_live_sessions_v1`."""
        self._require_auth(owner_password)
        self._require_writable()
        if duration_minutes <= 0:
            raise ValueError("Session duration must be positive")
        ts = started_at if started_at is not None else datetime.now(timezone.utc)
        sessions_data = self._decrypt_slot(SESSIONS_STORAGE_KEY, owner_password)
        if any(s["band_id"] == band_id and s["active"] for s in sessions_data["sessions"]):
            raise ValueError(f"Band {band_id!r} already has an active session")
        entry = {
            "band_id": band_id,
            "guest_name": guest_name,
            "duration_minutes": int(duration_minutes),
            "started_at": ts.isoformat(),
            "active": True,
        }
        sessions_data["sessions"].append(entry)
        self._encrypt_slot(SESSIONS_STORAGE_KEY, sessions_data, owner_password)
        return entry

    def close_session(self, owner_password: str, band_id: str) -> dict[str, Any]:
        """Mark an encrypted timed session inactive."""
        self._require_auth(owner_password)
        self._require_writable()
        sessions_data = self._decrypt_slot(SESSIONS_STORAGE_KEY, owner_password)
        for session in sessions_data["sessions"]:
            if session["band_id"] == band_id and session["active"]:
                session["active"] = False
                session["ended_at"] = datetime.now(timezone.utc).isoformat()
                self._encrypt_slot(SESSIONS_STORAGE_KEY, sessions_data, owner_password)
                return session
        raise KeyError(f"No active session found for band {band_id!r}")

    def list_receipts(self, owner_password: str) -> list[dict[str, Any]]:
        """Decrypt and return active ledger receipts."""
        self._require_auth(owner_password)
        return list(self._decrypt_slot(VAULT_STORAGE_KEY, owner_password)["receipts"])

    def list_sessions(self, owner_password: str, *, active_only: bool = False) -> list[dict[str, Any]]:
        """Decrypt and return session timer entries."""
        self._require_auth(owner_password)
        sessions = self._decrypt_slot(SESSIONS_STORAGE_KEY, owner_password)["sessions"]
        return [s for s in sessions if not active_only or s.get("active")]

    def archive_month(self, owner_password: str, year_month: str) -> dict[str, Any]:
        """Move receipts matching `YYYY-MM` into an encrypted monthly archive partition."""
        self._require_auth(owner_password)
        self._require_writable()
        if not _MONTH_RE.match(year_month):
            raise ValueError(f"Invalid archive month {year_month!r}; expected YYYY-MM")

        vault_data = self._decrypt_slot(VAULT_STORAGE_KEY, owner_password)
        to_archive = [r for r in vault_data["receipts"] if r.get("month") == year_month]
        remaining = [r for r in vault_data["receipts"] if r.get("month") != year_month]

        archive_key = f"{ARCHIVE_PREFIX}{year_month}"
        prior_archive = {"month": year_month, "receipts": []}
        if self.storage.get(archive_key) is not None:
            prior_archive = self._decrypt_slot(archive_key, owner_password)

        existing_nos = {r.get("receipt_no") for r in prior_archive["receipts"]}
        for rec in to_archive:
            if rec.get("receipt_no") not in existing_nos:
                prior_archive["receipts"].append(rec)

        self._encrypt_slot(archive_key, prior_archive, owner_password)
        vault_data["receipts"] = remaining
        self._encrypt_slot(VAULT_STORAGE_KEY, vault_data, owner_password)

        index = list(self.storage.get(ARCHIVE_INDEX_KEY) or [])
        if year_month not in index:
            index.append(year_month)
            index.sort()
            self.storage.set(ARCHIVE_INDEX_KEY, index)

        return {
            "archive_key": archive_key,
            "archived_count": len(to_archive),
            "remaining_active": len(remaining),
            "total_in_archive": len(prior_archive["receipts"]),
        }

    def read_monthly_archive(self, owner_password: str, year_month: str) -> list[dict[str, Any]]:
        """Decrypt receipts from a previously archived `YYYY-MM` partition."""
        self._require_auth(owner_password)
        archive_key = f"{ARCHIVE_PREFIX}{year_month}"
        data = self._decrypt_slot(archive_key, owner_password)
        return list(data["receipts"])

    def export_backup(self, owner_password: str) -> dict[str, Any]:
        """Export an authenticated `ENC_BACKUP_V2` backup envelope covering ledger, sessions, and config."""
        config = self._require_auth(owner_password)
        self._require_writable()
        payload = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "public_config": {k: v for k, v in config.items() if k != "auth"},
            "seq_state": self.storage.get(SEQ_STORAGE_KEY),
            "archive_index": self.storage.get(ARCHIVE_INDEX_KEY) or [],
            "vault": self._decrypt_slot(VAULT_STORAGE_KEY, owner_password),
            "sessions": self._decrypt_slot(SESSIONS_STORAGE_KEY, owner_password),
        }
        return encrypt_json_envelope(
            payload,
            owner_password,
            aad=b"vaultpos_backup_v2",
            iterations=self.iterations,
        )

    def restore_backup(self, envelope: dict[str, Any], owner_password: str) -> dict[str, Any]:
        """Verify and restore an `ENC_BACKUP_V2` backup, clearing read-only quarantine fallback."""
        self._require_auth(owner_password)
        payload = decrypt_json_envelope(envelope, owner_password, aad=b"vaultpos_backup_v2")
        vault_data = payload["vault"]
        sessions_data = payload["sessions"]
        seq_state = payload["seq_state"]

        self._encrypt_slot(VAULT_STORAGE_KEY, vault_data, owner_password)
        self._encrypt_slot(SESSIONS_STORAGE_KEY, sessions_data, owner_password)
        self.storage.set(SEQ_STORAGE_KEY, seq_state)
        self.storage.set(ARCHIVE_INDEX_KEY, payload.get("archive_index", []))
        self.storage.delete(PENDING_COMMIT_STORAGE_KEY)

        self.read_only = False
        self.quarantine_reason = None
        return {
            "status": "restored",
            "read_only": False,
            "receipt_count": len(vault_data["receipts"]),
            "active_sessions": len(sessions_data["sessions"]),
        }

    def list_quarantines(self) -> list[dict[str, Any]]:
        """Return quarantine metadata entries ordered from oldest to newest."""
        items: list[dict[str, Any]] = []
        for key in self.storage.keys():
            if key.startswith(QUARANTINE_PREFIX):
                entry = self.storage.get(key) or {}
                items.append(
                    {
                        "key": key,
                        "quarantined_at": entry.get("quarantined_at"),
                        "reason": entry.get("reason"),
                        "corrupted_keys": entry.get("corrupted_keys", []),
                    }
                )
        return items
