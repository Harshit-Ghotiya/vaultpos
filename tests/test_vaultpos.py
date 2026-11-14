"""Automated unit tests for VaultPOS cryptography, quarantine recovery, archiving, and thermal receipts."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from vaultpos.cli import main as cli_main
from vaultpos.crypto import (
    BACKUP_SCHEMA_V2,
    DEFAULT_PBKDF2_ITERATIONS,
    VaultCryptoError,
    aes256_gcm_decrypt,
    aes256_gcm_encrypt,
    decrypt_json_envelope,
    derive_key,
    encrypt_json_envelope,
    hash_password,
    verify_password,
)
from vaultpos.receipt import (
    _CODE39_PATTERNS,
    build_escpos_receipt,
    build_upi_uri,
    encode_code39_modules,
    format_thermal_receipt,
)
from vaultpos.vault import (
    CONFIG_STORAGE_KEY,
    PENDING_COMMIT_STORAGE_KEY,
    QUARANTINE_PREFIX,
    SEQ_STORAGE_KEY,
    SESSIONS_STORAGE_KEY,
    VAULT_STORAGE_KEY,
    JsonFileStorage,
    MemoryStorage,
    VaultAuthError,
    VaultReadOnlyError,
    VaultStore,
)

OWNER_PASS = "VaultPOS#2026!"


class CryptoTests(unittest.TestCase):
    """Verify NIST SP 800-38D AES-256-GCM vectors, PBKDF2-SHA256, and tamper detection."""

    def test_nist_sp800_38d_aes256_gcm_vectors(self) -> None:
        vectors = [
            (
                bytes.fromhex("00" * 32),
                bytes.fromhex("00" * 12),
                b"",
                b"",
                b"",
                bytes.fromhex("530f8afbc74536b9a963b4f1c4cb738b"),
            ),
            (
                bytes.fromhex("00" * 32),
                bytes.fromhex("00" * 12),
                bytes.fromhex("00" * 16),
                b"",
                bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18"),
                bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919"),
            ),
            (
                bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
                bytes.fromhex("cafebabefacedbaddecaf888"),
                bytes.fromhex(
                    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
                ),
                bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
                bytes.fromhex(
                    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
                ),
                bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b"),
            ),
        ]
        for key, nonce, pt, aad, expected_ct, expected_tag in vectors:
            ct, tag = aes256_gcm_encrypt(key, nonce, pt, aad=aad)
            self.assertEqual(ct, expected_ct)
            self.assertEqual(tag, expected_tag)
            self.assertEqual(aes256_gcm_decrypt(key, nonce, ct, tag, aad=aad), pt)

    def test_tamper_in_ciphertext_tag_or_aad_raises_value_error(self) -> None:
        key = derive_key(OWNER_PASS, b"0123456789abcdef", iterations=DEFAULT_PBKDF2_ITERATIONS)
        nonce = b"123456789012"
        aad = b"vaultpos_slot_aad"
        ct, tag = aes256_gcm_encrypt(key, nonce, b'{"total":"250.00"}', aad=aad)

        bad_ct = bytes([ct[0] ^ 0x01]) + ct[1:]
        with self.assertRaises(ValueError):
            aes256_gcm_decrypt(key, nonce, bad_ct, tag, aad=aad)

        bad_tag = bytes([tag[0] ^ 0x80]) + tag[1:]
        with self.assertRaises(ValueError):
            aes256_gcm_decrypt(key, nonce, ct, bad_tag, aad=aad)

        with self.assertRaises(ValueError):
            aes256_gcm_decrypt(key, nonce, ct, tag, aad=b"wrong_aad")

    def test_pbkdf2_50k_salted_password_and_envelope_roundtrip(self) -> None:
        record = hash_password(OWNER_PASS)
        self.assertEqual(record["kdf"], "PBKDF2-SHA256")
        self.assertEqual(record["iterations"], 50_000)
        self.assertTrue(verify_password(OWNER_PASS, record))
        self.assertFalse(verify_password("WrongPassword!", record))

        envelope = encrypt_json_envelope({"ok": True, "count": 3}, OWNER_PASS, aad=b"test_aad")
        self.assertEqual(envelope["schema"], BACKUP_SCHEMA_V2)
        self.assertEqual(envelope["iterations"], 50_000)
        self.assertEqual(decrypt_json_envelope(envelope, OWNER_PASS, aad=b"test_aad"), {"ok": True, "count": 3})

        with self.assertRaises(VaultCryptoError):
            decrypt_json_envelope(envelope, "WrongPassword!", aad=b"test_aad")


class VaultWorkflowTests(unittest.TestCase):
    """Verify ledger operations, session timers, crash recovery, quarantine fallback, and archiving."""

    def test_sale_session_and_cash_guardrails(self) -> None:
        store = VaultStore(MemoryStorage())
        with self.assertRaises(VaultAuthError):
            store.initialize("short")

        store.initialize(OWNER_PASS, park_name="Summit Arcade", upi_vpa="summit@ybl")
        dt = datetime(2026, 11, 14, 10, 30, tzinfo=timezone.utc)

        with self.assertRaisesRegex(ValueError, "Cash received must be at least"):
            store.record_sale(
                OWNER_PASS,
                items=[{"name": "All-Day Pass", "qty": 2, "unit_price": "250.00"}],
                payment_mode="CASH",
                cash_tendered="400.00",
                now=dt,
            )

        receipt = store.record_sale(
            OWNER_PASS,
            items=[{"name": "All-Day Pass", "qty": 2, "unit_price": "250.00"}],
            payment_mode="CASH",
            cash_tendered="600.00",
            customer_name="Aarav",
            now=dt,
        )
        self.assertEqual(receipt["receipt_no"], "VP-261114-0001")
        self.assertEqual(receipt["total_amount"], "500.00")
        self.assertEqual(receipt["change_due"], "100.00")

        session = store.start_session(OWNER_PASS, band_id="B-101", guest_name="Aarav", duration_minutes=60, started_at=dt)
        self.assertTrue(session["active"])
        self.assertEqual(len(store.list_sessions(OWNER_PASS, active_only=True)), 1)
        closed = store.close_session(OWNER_PASS, "B-101")
        self.assertFalse(closed["active"])
        self.assertEqual(len(store.list_sessions(OWNER_PASS, active_only=True)), 0)

    def test_pending_commit_replay_on_startup(self) -> None:
        storage = MemoryStorage()
        store = VaultStore(storage)
        store.initialize(OWNER_PASS)
        pending_receipt = {
            "receipt_no": "VP-261114-0001",
            "created_at": "2026-11-14T11:00:00+00:00",
            "month": "2026-11",
            "park_name": "VaultPOS Terminal",
            "upi_vpa": "merchant@upi",
            "customer_name": "Interrupted Guest",
            "items": [{"name": "1 Hr Entry", "qty": 1, "unit_price": "300.00", "line_total": "300.00"}],
            "total_amount": "300.00",
            "payment_mode": "UPI / QR",
            "cash_tendered": "300.00",
            "change_due": "0.00",
            "payment_reference": "UTR998877",
        }
        store._encrypt_slot(
            PENDING_COMMIT_STORAGE_KEY,
            {"receipt": pending_receipt, "seq_state": {"last_date": "261114", "seq": 1}},
            OWNER_PASS,
        )

        status = store.unlock(OWNER_PASS)
        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["pending_recovery"], "replayed")
        self.assertIsNone(storage.get(PENDING_COMMIT_STORAGE_KEY))
        self.assertEqual(len(store.list_receipts(OWNER_PASS)), 1)
        self.assertEqual(storage.get(SEQ_STORAGE_KEY), {"last_date": "261114", "seq": 1})

    def test_corruption_triggers_quarantine_readonly_and_verified_restore_recovers(self) -> None:
        storage = MemoryStorage()
        store = VaultStore(storage)
        store.initialize(OWNER_PASS)
        store.record_sale(
            OWNER_PASS,
            items=[{"name": "Entry Ticket", "qty": 1, "unit_price": "400.00"}],
            payment_mode="UPI / DESK",
            now=datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc),
        )
        backup = store.export_backup(OWNER_PASS)

        # Corrupt the ciphertext in local encrypted ledger storage
        corrupted = storage.get(VAULT_STORAGE_KEY)
        corrupted["ciphertext"] = "AAAA" + corrupted["ciphertext"][4:]
        storage.set(VAULT_STORAGE_KEY, corrupted)

        unlock_res = store.unlock(OWNER_PASS)
        self.assertEqual(unlock_res["status"], "quarantined_read_only")
        self.assertTrue(unlock_res["read_only"])
        self.assertTrue(unlock_res["quarantine_key"].startswith(QUARANTINE_PREFIX))
        self.assertIn(VAULT_STORAGE_KEY, unlock_res["corrupted_keys"])
        self.assertEqual(len(store.list_quarantines()), 1)
        self.assertIsNotNone(storage.get(CONFIG_STORAGE_KEY))
        self.assertIsNotNone(storage.get(SESSIONS_STORAGE_KEY))

        # Mutations must fail while in read-only fallback
        with self.assertRaises(VaultReadOnlyError):
            store.record_sale(
                OWNER_PASS,
                items=[{"name": "Blocked Ticket", "qty": 1, "unit_price": "100.00"}],
                payment_mode="CASH",
                cash_tendered="100.00",
            )

        # Verified ENC_BACKUP_V2 restore lifts read-only fallback cleanly
        restored = store.restore_backup(backup, OWNER_PASS)
        self.assertEqual(restored["status"], "restored")
        self.assertFalse(restored["read_only"])
        self.assertEqual(restored["receipt_count"], 1)
        self.assertEqual(len(store.list_receipts(OWNER_PASS)), 1)

    def test_monthly_vault_archiving(self) -> None:
        store = VaultStore(MemoryStorage())
        store.initialize(OWNER_PASS)
        store.record_sale(
            OWNER_PASS,
            items=[{"name": "Oct Pass", "qty": 1, "unit_price": "250.00"}],
            payment_mode="UPI / QR",
            now=datetime(2026, 10, 29, 9, 0, tzinfo=timezone.utc),
        )
        store.record_sale(
            OWNER_PASS,
            items=[{"name": "Nov Pass", "qty": 1, "unit_price": "350.00"}],
            payment_mode="CASH",
            cash_tendered="500.00",
            now=datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc),
        )

        result = store.archive_month(OWNER_PASS, "2026-10")
        self.assertEqual(result["archived_count"], 1)
        self.assertEqual(result["remaining_active"], 1)
        self.assertEqual(len(store.list_receipts(OWNER_PASS)), 1)
        archived = store.read_monthly_archive(OWNER_PASS, "2026-10")
        self.assertEqual(len(archived), 1)
        self.assertEqual(archived[0]["receipt_no"], "VP-261029-0001")


class ReceiptAndCliTests(unittest.TestCase):
    """Verify UPI QR URI formatting, ISO Code 39 bitstreams, 80mm thermal layouts, and CLI."""

    def test_code39_table_invariants_and_module_encoding(self) -> None:
        self.assertEqual(len(_CODE39_PATTERNS), 44)
        for ch, pat in _CODE39_PATTERNS.items():
            self.assertEqual(len(pat), 9, f"Pattern length mismatch for {ch!r}")
            self.assertEqual(pat.count("w"), 3, f"Code 39 must have 3 wide elements for {ch!r}")

        modules = encode_code39_modules("VP-261114-0001", wide_ratio=3)
        # 16 encoded chars (* + 14 chars + *), each has 3*3 + 6*1 = 15 modules, plus 15 inter-char gaps
        self.assertEqual(len(modules), 16 * 15 + 15)
        self.assertTrue(all(bit in (0, 1) for bit in modules))
        self.assertEqual(modules[0], 1)
        self.assertEqual(modules[-1], 1)

    def test_upi_qr_uri_and_80mm_thermal_escpos(self) -> None:
        uri = build_upi_uri("desk@okicici", "500.00", "VP-261114-0001", payee_name="Summit Arcade")
        self.assertEqual(uri, "upi://pay?pa=desk@okicici&pn=Summit%20Arcade&cu=INR&am=500.00&tr=VP-261114-0001")

        receipt = {
            "receipt_no": "VP-261114-0001",
            "created_at": "2026-11-14T14:22:00+00:00",
            "park_name": "Summit Arcade",
            "upi_vpa": "desk@okicici",
            "customer_name": "Walk-in Guest",
            "items": [{"name": "Trampoline 60m", "qty": 2, "unit_price": "250.00", "line_total": "500.00"}],
            "total_amount": "500.00",
            "payment_mode": "UPI / QR",
            "cash_tendered": "500.00",
            "change_due": "0.00",
            "payment_reference": "",
        }
        layout = format_thermal_receipt(receipt)
        self.assertIn("VP-261114-0001", layout)
        self.assertIn(uri, layout)
        self.assertIn("GRAND TOTAL (INR)", layout)
        self.assertTrue(all(len(line) <= 42 or line.startswith("UPI QR") for line in layout.splitlines()))

        raw_escpos = build_escpos_receipt(receipt)
        self.assertTrue(raw_escpos.startswith(b"\x1b@"))
        self.assertIn(uri.encode("ascii"), raw_escpos)
        self.assertIn(b"\x1dk\x04VP-261114-0001\x00", raw_escpos)
        self.assertTrue(raw_escpos.endswith(b"\x1dV\x42\x00"))

    def test_cli_end_to_end_json_file_storage(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store_path = str(Path(tmpdir) / "pos_vault.json")
            backup_path = str(Path(tmpdir) / "backup.json")
            stdout_buf = io.StringIO()
            with contextlib.redirect_stdout(stdout_buf):
                self.assertEqual(cli_main(["--store", store_path, "init", "--password", OWNER_PASS]), 0)
                self.assertEqual(
                    cli_main(
                        [
                            "--store",
                            store_path,
                            "sale",
                            "--item",
                            "Grip Socks",
                            "--qty",
                            "2",
                            "--price",
                            "120.00",
                            "--mode",
                            "CASH",
                            "--tendered",
                            "300.00",
                            "--password",
                            OWNER_PASS,
                        ]
                    ),
                    0,
                )
                self.assertEqual(cli_main(["--store", store_path, "status", "--password", OWNER_PASS]), 0)
                self.assertEqual(cli_main(["--store", store_path, "backup", backup_path, "--password", OWNER_PASS]), 0)
            output = stdout_buf.getvalue()
            self.assertIn("VP-", output)
            self.assertIn("GRAND TOTAL (INR)", output)
            self.assertIn("Wrote ENC_BACKUP_V2 backup", output)
            self.assertTrue(os.path.exists(backup_path))
            store = VaultStore(JsonFileStorage(store_path))
            self.assertEqual(len(store.list_receipts(OWNER_PASS)), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
