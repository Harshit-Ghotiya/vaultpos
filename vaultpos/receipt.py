"""UPI QR URI generation, Code 39 barcode encoding, and 80mm thermal receipt layout/ESC-POS output."""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
from typing import Any
from urllib.parse import quote

RECEIPT_LINE_WIDTH = 42  # 72mm printable width on 80mm thermal roll (Font A, ~42 chars)

# ISO/IEC 16388 Code 39 symbol table: 9 alternating bar/space elements ('n' = narrow, 'w' = wide)
_CODE39_PATTERNS: dict[str, str] = {
    "0": "nnnwwnwnn",
    "1": "wnnwnnnnw",
    "2": "nnwwnnnnw",
    "3": "wnwwnnnnn",
    "4": "nnnwwnnnw",
    "5": "wnnwwnnnn",
    "6": "nnwwwnnnn",
    "7": "nnnwnnwnw",
    "8": "wnnwnnwnn",
    "9": "nnwwnnwnn",
    "A": "wnnnnwnnw",
    "B": "nnwnnwnnw",
    "C": "wnwnnwnnn",
    "D": "nnnnwwnnw",
    "E": "wnnnwwnnn",
    "F": "nnwnwwnnn",
    "G": "nnnnnwwnw",
    "H": "wnnnnwwnn",
    "I": "nnwnnwwnn",
    "J": "nnnnwwwnn",
    "K": "wnnnnnnww",
    "L": "nnwnnnnww",
    "M": "wnwnnnnwn",
    "N": "nnnnwnnww",
    "O": "wnnnwnnwn",
    "P": "nnwnwnnwn",
    "Q": "nnnnnnwww",
    "R": "wnnnnnwwn",
    "S": "nnwnnnwwn",
    "T": "nnnnwnwwn",
    "U": "wwnnnnnnw",
    "V": "nwwnnnnnw",
    "W": "wwwnnnnnn",
    "X": "nwnnwnnnw",
    "Y": "wwnnwnnnn",
    "Z": "nwwnwnnnn",
    "-": "nwnnnnwnw",
    ".": "wwnnnnwnn",
    " ": "nwwnnnwnn",
    "$": "nwnwnwnnn",
    "/": "nwnwnnnwn",
    "+": "nwnnnwnwn",
    "%": "nnnwnwnwn",
    "*": "nwnnwnwnn",
}


def build_upi_uri(
    vpa: str,
    amount_inr: int | float | str | Decimal,
    receipt_no: str,
    *,
    payee_name: str = "VAULTPOS",
) -> str:
    """Build a dynamic amount-embedded UPI payment URI suitable for QR encoding."""
    cleaned_vpa = vpa.strip()
    if "@" not in cleaned_vpa:
        raise ValueError(f"Invalid UPI VPA: {vpa!r}")
    amount = Decimal(str(amount_inr)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if amount <= Decimal("0.00"):
        raise ValueError("UPI QR amount must be greater than zero")
    return (
        f"upi://pay?pa={quote(cleaned_vpa, safe='@._-')}"
        f"&pn={quote(payee_name.strip() or 'VAULTPOS', safe='')}"
        f"&cu=INR&am={amount:.2f}"
        f"&tr={quote(receipt_no.strip(), safe='-_')}"
    )


def encode_code39_modules(text: str, *, wide_ratio: int = 3) -> list[int]:
    """Encode an ASCII Code 39 payload (wrapped in `*` start/stop) as binary 1/0 modules."""
    if wide_ratio < 2:
        raise ValueError("Code 39 wide_ratio must be at least 2")
    normalized = text.strip().upper()
    if not normalized:
        raise ValueError("Code 39 payload cannot be empty")
    if "*" in normalized:
        raise ValueError("Code 39 payload must not include reserved start/stop `*` characters")

    full_text = f"*{normalized}*"
    modules: list[int] = []
    for idx, ch in enumerate(full_text):
        pattern = _CODE39_PATTERNS.get(ch)
        if pattern is None:
            raise ValueError(f"Unsupported Code 39 character: {ch!r}")
        for pos, width_code in enumerate(pattern):
            bit = 1 if pos % 2 == 0 else 0
            span = wide_ratio if width_code == "w" else 1
            modules.extend([bit] * span)
        if idx < len(full_text) - 1:
            modules.append(0)  # inter-character narrow gap
    return modules


def render_code39_ascii(text: str) -> str:
    """Render a compact ASCII visual strip of a Code 39 barcode."""
    modules = encode_code39_modules(text, wide_ratio=2)
    return "".join("#" if bit else " " for bit in modules)


def format_thermal_receipt(receipt: dict[str, Any], *, width: int = RECEIPT_LINE_WIDTH) -> str:
    """Render a 72mm / 42-column thermal receipt layout ready for 80mm POS roll printing."""
    sep = "-" * width
    eq_sep = "=" * width
    park = str(receipt.get("park_name", "VAULTPOS"))[:width]
    receipt_no = str(receipt["receipt_no"])
    created_at = str(receipt.get("created_at", ""))[:19].replace("T", " ")

    lines = [
        park.center(width),
        "80mm Offline Encrypted Thermal Receipt".center(width),
        eq_sep,
        f"Receipt : {receipt_no}",
        f"Date    : {created_at}",
        f"Guest   : {receipt.get('customer_name', 'Walk-in Guest')}",
        f"Pay Mode: {receipt.get('payment_mode', 'CASH')}",
        sep,
        f"{'Item':<22}{'Qty':>4}{'Rate':>7}{'Amt':>9}"[:width],
        sep,
    ]
    for item in receipt.get("items", []):
        name = str(item["name"])[:21]
        qty = int(item["qty"])
        rate = str(item["unit_price"])
        amt = str(item["line_total"])
        lines.append(f"{name:<22}{qty:>4}{rate:>7}{amt:>9}"[:width])

    lines.extend(
        [
            sep,
            f"{'GRAND TOTAL (INR)':<26}{receipt['total_amount']:>16}",
            f"{'TENDERED (INR)':<26}{receipt.get('cash_tendered', receipt['total_amount']):>16}",
            f"{'CHANGE DUE (INR)':<26}{receipt.get('change_due', '0.00'):>16}",
        ]
    )
    if receipt.get("payment_reference"):
        lines.append(f"Ref     : {receipt['payment_reference']}")

    upi_uri = build_upi_uri(
        receipt.get("upi_vpa", "merchant@upi"),
        receipt["total_amount"],
        receipt_no,
        payee_name=park,
    )
    barcode_strip = render_code39_ascii(receipt_no)[:width]
    lines.extend(
        [
            sep,
            f"UPI QR  : {upi_uri}",
            f"Code 39 : *{receipt_no}*",
            barcode_strip.center(width),
            eq_sep,
        ]
    )
    return "\n".join(lines) + "\n"


def build_escpos_qr_packet(payload: str, *, module_size: int = 5) -> bytes:
    """Build native ESC/POS `GS ( k` QR Code store + print byte sequence."""
    data = payload.encode("utf-8")
    p_len = len(data) + 3
    pl, ph = p_len & 0xFF, (p_len >> 8) & 0xFF
    size = max(1, min(16, module_size))
    return b"".join(
        [
            b"\x1d(k\x04\x001A2\x00",  # Function 165: QR Model 2
            bytes([0x1D, 0x28, 0x6B, 0x03, 0x00, 0x31, 0x43, size]),  # Function 167: module size
            b"\x1d(k\x03\x001E0",  # Function 169: ECC Level L
            bytes([0x1D, 0x28, 0x6B, pl, ph, 0x31, 0x50, 0x30]) + data,  # Function 180: store payload
            b"\x1d(k\x03\x001Q0",  # Function 181: print symbol
        ]
    )


def build_escpos_code39_packet(code: str) -> bytes:
    """Build native ESC/POS `GS k` Code 39 barcode print command."""
    normalized = code.strip().upper()
    if any(ch not in _CODE39_PATTERNS or ch == "*" for ch in normalized):
        raise ValueError(f"Invalid Code 39 string for ESC/POS: {code!r}")
    payload = normalized.encode("ascii")
    return b"\x1dh\x3c\x1dw\x02\x1dk\x04" + payload + b"\x00"


def build_escpos_receipt(receipt: dict[str, Any], *, cut: bool = True) -> bytes:
    """Assemble full ESC/POS byte stream (text + Code 39 + UPI QR + partial cut) for 80mm printer."""
    text_body = format_thermal_receipt(receipt).encode("ascii", errors="replace")
    upi_uri = build_upi_uri(
        receipt.get("upi_vpa", "merchant@upi"),
        receipt["total_amount"],
        receipt["receipt_no"],
        payee_name=receipt.get("park_name", "VAULTPOS"),
    )
    chunks = [
        b"\x1b@",  # ESC @ Initialize printer
        text_body,
        b"\x1ba\x01",  # Center align graphics
        build_escpos_code39_packet(receipt["receipt_no"]),
        b"\n",
        build_escpos_qr_packet(upi_uri),
        b"\x1ba\x00",  # Reset left align
    ]
    if cut:
        chunks.append(b"\x1dV\x42\x00")  # GS V 66 0: Feed and partial cut
    return b"".join(chunks)
