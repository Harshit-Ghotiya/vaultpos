"""Command-line interface for operating and inspecting a local VaultPOS ledger."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Sequence

from .receipt import format_thermal_receipt
from .vault import JsonFileStorage, VaultStore


def _get_password(arg_password: str | None) -> str:
    if arg_password is not None:
        return arg_password
    return getpass.getpass("Owner password: ")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vaultpos", description="Offline-first encrypted POS vault CLI")
    parser.add_argument(
        "--store",
        default="vaultpos_store.json",
        help="Path to the encrypted local JSON vault file (default: vaultpos_store.json)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize a new encrypted POS vault")
    p_init.add_argument("--park-name", default="VaultPOS Terminal")
    p_init.add_argument("--upi-vpa", default="merchant@upi")
    p_init.add_argument("--password", default=None)

    p_sale = sub.add_parser("sale", help="Record an encrypted sale and print 80mm thermal receipt")
    p_sale.add_argument("--item", required=True, help="Item label")
    p_sale.add_argument("--qty", type=int, default=1)
    p_sale.add_argument("--price", required=True, help="Unit price in INR (e.g. 250.00)")
    p_sale.add_argument("--mode", default="CASH", choices=["CASH", "UPI / DESK", "UPI / QR"])
    p_sale.add_argument("--tendered", default=None, help="Cash tendered in INR (required for CASH)")
    p_sale.add_argument("--guest", default="Walk-in Guest")
    p_sale.add_argument("--password", default=None)

    p_status = sub.add_parser("status", help="Unlock and report ledger/quarantine status")
    p_status.add_argument("--password", default=None)

    p_archive = sub.add_parser("archive", help="Move a YYYY-MM slice of receipts to monthly archive")
    p_archive.add_argument("month", help="Target month in YYYY-MM format")
    p_archive.add_argument("--password", default=None)

    p_backup = sub.add_parser("backup", help="Export an encrypted ENC_BACKUP_V2 snapshot")
    p_backup.add_argument("out_path", help="Destination backup JSON path")
    p_backup.add_argument("--password", default=None)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    store = VaultStore(JsonFileStorage(Path(args.store)))

    if args.command == "init":
        pwd = _get_password(args.password)
        cfg = store.initialize(pwd, park_name=args.park_name, upi_vpa=args.upi_vpa)
        print(json.dumps({"status": "initialized", "config": cfg}, indent=2))
        return 0

    if args.command == "sale":
        pwd = _get_password(args.password)
        receipt = store.record_sale(
            pwd,
            items=[{"name": args.item, "qty": args.qty, "unit_price": args.price}],
            payment_mode=args.mode,
            cash_tendered=args.tendered,
            customer_name=args.guest,
        )
        print(format_thermal_receipt(receipt))
        return 0

    if args.command == "status":
        pwd = _get_password(args.password)
        info = store.unlock(pwd)
        info["quarantines"] = store.list_quarantines()
        print(json.dumps(info, indent=2))
        return 0

    if args.command == "archive":
        pwd = _get_password(args.password)
        res = store.archive_month(pwd, args.month)
        print(json.dumps(res, indent=2))
        return 0

    if args.command == "backup":
        pwd = _get_password(args.password)
        envelope = store.export_backup(pwd)
        Path(args.out_path).write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote ENC_BACKUP_V2 backup to {args.out_path}")
        return 0

    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
