# QR Reference Matrices Fixture (`R3`)

`qr-reference-matrices.json` stores reference ISO/IEC 18004 QR Code matrices (Byte mode, ECC Level L) for:
- **Versions 1–10 (`versionsMask0`):** Mask 0 matrices across all supported versions (`v1` 21×21 through `v10` 57×57).
- **Representative UPI Payloads (`upiPayloadsBestMask`):** Best-mask matrices for 47-byte, 58-byte, 78-byte, and 103-byte UPI `upi://pay?...` strings.

Each matrix is verified in `tests/pos-static.test.mjs` against:
1. Exact module-for-module equality with the committed reference rows, including timing modules `(6, 8)` and `(8, 6)` and the fixed dark module `(size - 8, 8)`.
2. `jsQR` raster decoding.
3. An independent ISO/IEC 18004 structural + Reed-Solomon syndrome + Byte-mode bitstream decoder implemented in `tests/pos-static.test.mjs` that strictly rejects any matrix with missing timing modules or dark module.
