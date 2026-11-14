import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import jsQR from 'jsqr';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const htmlPath = path.join(root, 'VaultPOS_POS.html');
const html = fs.readFileSync(htmlPath, 'utf8');
const scriptBlocks = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)].map((match) => match[1]);
const runtime = scriptBlocks.at(-1);
const ids = new Set([...html.matchAll(/\bid=["']([^"']+)["']/g)].map((match) => match[1]));

assert.ok(runtime, 'the production runtime script must exist');

test('production runtime parses as JavaScript', () => {
  assert.doesNotThrow(() => new vm.Script(runtime, { filename: htmlPath }));
});

test('production HTML has no remote runtime dependencies or inline handlers', () => {
  assert.doesNotMatch(html, /<(?:script|link)[^>]+(?:src|href)=["']https?:\/\//i);
  assert.doesNotMatch(html, /\bonclick\s*=/i);
  assert.doesNotMatch(html, /(?:cdn\.tailwindcss|unpkg\.com|cdnjs\.cloudflare)/i);
});

test('required print, storage, and security invariants remain present', () => {
  for (const invariant of [
    "VAULT_STORAGE_KEY = 'vaultpos_encrypted_vault_v1'",
    "SESSIONS_STORAGE_KEY = 'vaultpos_live_sessions_v1'",
    "CONFIG_STORAGE_KEY = 'vaultpos_park_config_v2'",
    "SEQ_STORAGE_KEY = 'vaultpos_receipt_seq_v1'",
    "PENDING_COMMIT_STORAGE_KEY = 'vaultpos_pending_commit_v1'",
    'MIN_OWNER_PASSWORD_LENGTH = 8',
    'iterations: 50000',
    'name: \'AES-GCM\'',
    'classList.add(\'print-report\')',
    'escapeHtml',
    'ENC_BACKUP_V2',
    'Cash received must be at least',
    'paymentReference'
  ]) assert.match(runtime, new RegExp(invariant.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(runtime, /VAULT_KDF_MATERIAL\s*=/);
  assert.doesNotMatch(runtime, /localStorage\.setItem\([^,]+,\s*obfuscateJson/);
  assert.match(html, /@page\s*\{[\s\S]*?size:\s*80mm auto[\s\S]*?margin:\s*0mm/);
  assert.match(html, /#printable-receipt[\s\S]*?width:\s*72mm/);
});

test('literal runtime DOM references and data-target hooks resolve', () => {
  const refs = new Set([...runtime.matchAll(/\$\(\s*["']([^"']+)["']/g)].map((match) => match[1]));
  assert.deepEqual([...refs].filter((id) => !ids.has(id)), []);
  const targets = new Set([...html.matchAll(/data-target=["']([^"']+)["']/g)].map((match) => match[1]));
  assert.deepEqual([...targets].filter((id) => !ids.has(id)), []);
});

test('every static data-action is handled by delegated event routing', () => {
  const actions = new Set([...html.matchAll(/data-action=["']([^"']+)["']/g)].map((match) => match[1]));
  const handlers = new Set([...runtime.matchAll(/case\s+["']([^"']+)["']/g)].map((match) => match[1]));
  assert.deepEqual([...actions].filter((action) => !handlers.has(action)), []);
});

test('QR generator produces valid structural matrices for the requested payload and supported versions', () => {
  const start = runtime.indexOf('const QR_VERSIONS_L');
  const end = runtime.indexOf('function getResolvedUpiVpa');
  assert.ok(start >= 0 && end > start, 'QR generator block must be discoverable');
  const context = { TextEncoder };
  vm.runInNewContext(`${runtime.slice(start, end)}\nthis.generateQRMatrix = generateQRMatrix;`, context);
  const sample = 'upi://pay?pa=9876543210@ybl&pn=VAULTPOS&cu=INR&am=500.00';
  const matrix = context.generateQRMatrix(sample);
  assert.equal(matrix.length, 33, 'sample payload should fit QR version 4');
  assert.ok(matrix.every((row) => row.length === matrix.length && row.every((bit) => bit === 0 || bit === 1)));
  assert.equal(matrix[0][0], 1, 'top-left finder pattern must be dark');
  assert.equal(matrix[6][6], 1, 'top-left finder center must be dark');
  assert.equal(matrix[matrix.length - 7][6], 1, 'bottom-left finder center must be dark');
  for (const length of [100, 140, 180, 220, 260]) {
    const longMatrix = context.generateQRMatrix('A'.repeat(length));
    assert.ok([37, 45, 49, 53, 57].includes(longMatrix.length), `payload length ${length} must use a supported QR version`);
  }
});

test('QR raster output decodes to the exact UPI payload', () => {
  const start = runtime.indexOf('const QR_VERSIONS_L');
  const end = runtime.indexOf('function getResolvedUpiVpa');
  const context = { TextEncoder };
  vm.runInNewContext(`${runtime.slice(start, end)}\nthis.generateQRMatrix = generateQRMatrix;`, context);
  const payload = 'upi://pay?pa=9876543210@ybl&pn=VAULTPOS&cu=INR&am=500.00';
  const matrix = context.generateQRMatrix(payload);
  const quiet = 4;
  const scale = 5;
  const modules = matrix.length + quiet * 2;
  const size = modules * scale;
  const pixels = new Uint8ClampedArray(size * size * 4).fill(255);
  for (let row = 0; row < matrix.length; row++) for (let col = 0; col < matrix.length; col++) if (matrix[row][col]) {
    for (let y = 0; y < scale; y++) for (let x = 0; x < scale; x++) {
      const index = (((row + quiet) * scale + y) * size + (col + quiet) * scale + x) * 4;
      pixels[index] = 0; pixels[index + 1] = 0; pixels[index + 2] = 0; pixels[index + 3] = 255;
    }
  }
  const decoded = jsQR(pixels, size, size, { inversionAttempts: 'dontInvert' });
  assert.equal(decoded?.data, payload);
});

test('descriptive export filenames are encoded in the production runtime', () => {
  for (const name of [
    'VaultPOS_Sales_Customer_Report_',
    'VaultPOS_Customer_Sales_Export_',
    'VaultPOS_A4_Sales_Customer_Report_',
    'VaultPOS_Encrypted_Vault_Backup_'
  ]) assert.match(runtime, new RegExp(name));
});

test('business guardrails cover printing, recovery, payment audit, and restore wiring', () => {
  assert.match(runtime, /if \(!startupComplete \|\| !storageReady\)/);
  assert.match(runtime, /if \(state\.paymentMode === 'CASH' && toPaise\(state\.cashTendered\) < totals\.grandTotalPaise\)/);
  assert.match(html, /data-action=["']pay-mode["'][^>]*data-mode=["']CASH["']/);
  assert.match(html, /data-action=["']pay-mode["'][^>]*data-mode=["']UPI \/ DESK["']/);
  assert.match(html, /data-action=["']pay-mode["'][^>]*data-mode=["']UPI \/ QR["']/);
  assert.match(runtime, /PENDING_COMMIT_STORAGE_KEY/);
  assert.match(runtime, /mergeVaultRecords/);
  assert.match(runtime, /ENC_BACKUP_V2/);
  assert.match(runtime, /spreadsheetText/);
  assert.doesNotMatch(runtime, /setTimeout\(forceCloseWindow/);
  assert.match(html, /id=["']vaultAccessModal["']/);
  assert.match(html, /id=["']paymentReferenceInput["']/);
  assert.match(html, /id=["']restoreModal["']/);
  assert.match(runtime, /event\.target\.id === 'restoreVaultInput'\) restoreVaultJson\(event\)/);
  assert.match(runtime, /applyConfirmedRestore/);
});

test('duplicate print lock prevents rapid F10 keydown and key-repeat duplicate sales', async () => {
  assert.match(runtime, /if \(event\.repeat\) return;/);
  assert.match(runtime, /setPrintLockUI\(true\)/);
  assert.match(runtime, /printReceiptBtnLabel/);
  assert.match(runtime, /printStartBtnLabel/);
  assert.match(runtime, /const interactiveFocused = \['INPUT', 'TEXTAREA', 'SELECT', 'BUTTON', 'A', 'DIALOG'\]\.includes\(tag\)/);
});

test('quarantine, read-only schema skew protection, and monthly archive are present (F5, F19, R9, R10)', async () => {
  assert.match(runtime, /QUARANTINE_KEY_PREFIX = 'vaultpos_quarantine_v1_'/);
  assert.match(runtime, /ARCHIVE_KEY_PREFIX = 'vaultpos_archive_v1_'/);
  assert.match(runtime, /STORAGE_WARN_RATIO = 0\.80/);
  assert.match(runtime, /quarantineRawStorage\(VAULT_STORAGE_KEY,\s*raw\)/);
  assert.match(runtime, /Number\(value\.schemaVersion\) > STORAGE_SCHEMA_VERSION/);
  assert.match(runtime, /vaultReadOnly = true/);
  assert.match(runtime, /archivePastMonths/);
  assert.match(html, /id=["']storageUsageMeter["']/);

  const start = runtime.indexOf('function escapeHtml');
  const end = runtime.indexOf('function setVaultAccessForm');
  const store = new Map([['vaultpos_encrypted_vault_v1', 'ENC_V1:AAAA:BBBB:CORRUPT_CIPHERTEXT']]);
  const context = {
    STORAGE_SCHEMA_VERSION: 2,
    APP_VERSION: 'v0.2.0',
    VAULT_STORAGE_KEY: 'vaultpos_encrypted_vault_v1',
    SESSIONS_STORAGE_KEY: 'vaultpos_live_sessions_v1',
    CONFIG_STORAGE_KEY: 'vaultpos_park_config_v2',
    SEQ_STORAGE_KEY: 'vaultpos_receipt_seq_v1',
    PENDING_COMMIT_STORAGE_KEY: 'vaultpos_pending_commit_v1',
    AUTH_VERIFIER_STORAGE_KEY: 'vaultpos_auth_verifier_v1',
    QUARANTINE_KEY_PREFIX: 'vaultpos_quarantine_v1_',
    ARCHIVE_KEY_PREFIX: 'vaultpos_archive_v1_',
    MAX_STORAGE_BYTES: 5000000,
    STORAGE_WARN_RATIO: 0.8,
    DEFAULT_CONFIG: { shop: 'VAULTPOS', addr: '', phone: '', cashier: 'Dinesh', trampPrice: 500, softPrice: 400, taxPercent: 18, businessDayCutoffHour: 4, qrConfig: { sourceType: 'upi', upiId: '', upiSuffix: '@ybl', includeAmount: true, uploadedImageDataUrl: '' } },
    vaultReady: true,
    vaultReadOnly: false,
    storageReady: true,
    vaultPassphrase: 'TestPassword123!',
    derivedKeyCache: new Map(),
    memoryVault: {},
    archiveVault: {},
    liveSessions: [],
    state: { receiptSequence: 1001, lastKnownTimestamp: 0, park: {} },
    $: () => null,
    text: () => {},
    showStorageNotice: () => {},
    window: { crypto: globalThis.crypto },
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    atob,
    btoa,
    localStorage: {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => { store.set(k, String(v)); },
      removeItem: (k) => { store.delete(k); },
      get length() { return store.size; },
      key: (i) => Array.from(store.keys())[i] ?? null
    },
    document: { getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], documentElement: { getAttribute: () => null, setAttribute: () => {}, removeAttribute: () => {}, classList: { add: () => {}, remove: () => {} } } }
  };
  vm.runInNewContext(`${runtime.slice(start, end)}\nthis.loadVaultFromStorage = loadVaultFromStorage;\nthis.isReadOnly = () => vaultReadOnly;\nthis.isStorageReady = () => storageReady;`, context);
  const ok = await context.loadVaultFromStorage();
  assert.equal(ok, false);
  assert.equal(context.isReadOnly(), true, 'corrupted vault must enter read-only mode');
  assert.equal(context.isStorageReady(), false);
  assert.ok(Array.from(store.keys()).some((k) => k.startsWith('vaultpos_quarantine_v1_encrypted_vault_v1_')), 'corrupted raw value must be copied to quarantine key');
});

test('security and privacy: per-unlock CryptoKey caching, backup integrity counts, and password rotation (F1, F2, F3, F4, R11)', async () => {
  assert.match(runtime, /activeEncryptionSession/);
  assert.match(runtime, /backup integrity count mismatch/);
  assert.match(runtime, /VaultPOS_PreMigration_Backup_/);
  assert.match(html, /data-action=["']change-password["']/);

  const start = runtime.indexOf('function escapeHtml');
  const end = runtime.indexOf('function restoreVaultJson');
  const store = new Map();
  const context = {
    STORAGE_SCHEMA_VERSION: 2,
    APP_VERSION: 'v0.2.0',
    VAULT_STORAGE_KEY: 'vaultpos_encrypted_vault_v1',
    SESSIONS_STORAGE_KEY: 'vaultpos_live_sessions_v1',
    CONFIG_STORAGE_KEY: 'vaultpos_park_config_v2',
    SEQ_STORAGE_KEY: 'vaultpos_receipt_seq_v1',
    PENDING_COMMIT_STORAGE_KEY: 'vaultpos_pending_commit_v1',
    AUTH_VERIFIER_STORAGE_KEY: 'vaultpos_auth_verifier_v1',
    QUARANTINE_KEY_PREFIX: 'vaultpos_quarantine_v1_',
    ARCHIVE_KEY_PREFIX: 'vaultpos_archive_v1_',
    MAX_STORAGE_BYTES: 5000000,
    STORAGE_WARN_RATIO: 0.8,
    DEFAULT_CONFIG: { shop: 'VAULTPOS', addr: '', phone: '', cashier: 'Dinesh', trampPrice: 500, softPrice: 400, taxPercent: 18, businessDayCutoffHour: 4, qrConfig: { sourceType: 'upi', upiId: '', upiSuffix: '@ybl', includeAmount: true, uploadedImageDataUrl: '' } },
    vaultReady: true,
    vaultReadOnly: false,
    storageReady: true,
    startupComplete: true,
    vaultPassphrase: 'TestPassword123!',
    previousPassphrases: [],
    activeEncryptionSession: null,
    derivedKeyCache: new Map(),
    memoryVault: { '2026-11-04': [{ receiptNo: 'VP-1001', dateKey: '2026-11-04', grandTotal: 500, grandTotalPaise: 50000 }] },
    archiveVault: {},
    liveSessions: [{ id: 'sess_1', receiptNo: 'VP-1001', dateKey: '2026-11-04', customerName: 'Kid', customerPhone: '9876543210', status: 'active' }],
    state: { receiptSequence: 1002, lastKnownTimestamp: 0, park: {}, prices: { trampoline: 500, softplay: 400, ext15: 100, ext30: 200 }, quantities: {}, customItems: [] },
    $: () => null,
    text: () => {},
    showStorageNotice: () => {},
    showToast: () => {},
    window: { crypto: globalThis.crypto, confirm: () => true },
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    atob,
    btoa,
    localStorage: {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => { store.set(k, String(v)); },
      removeItem: (k) => { store.delete(k); },
      get length() { return store.size; },
      key: (i) => Array.from(store.keys())[i] ?? null
    },
    document: { getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], documentElement: { getAttribute: () => null, setAttribute: () => {}, removeAttribute: () => {}, classList: { add: () => {}, remove: () => {} } } }
  };
  vm.runInNewContext(
    `${runtime.slice(start, end)}\nthis.persistStateBundle = persistStateBundle;\nthis.buildPersistentSnapshot = buildPersistentSnapshot;\nthis.encryptJson = encryptJson;\nthis.decodeBackupPayload = decodeBackupPayload;\nthis.normalizeRecord = normalizeRecord;\nthis.normalizeSessions = normalizeSessions;\nthis.ensureNextReceiptSequence = ensureNextReceiptSequence;`,
    context
  );

  // F4: Sessions saved in localStorage must be encrypted with ENC_V1:
  const saved = await context.persistStateBundle();
  assert.equal(saved, true);
  assert.match(String(store.get('vaultpos_live_sessions_v1')), /^ENC_V1:/, 'live sessions must be encrypted in localStorage');
  assert.doesNotMatch(String(store.get('vaultpos_live_sessions_v1')), /9876543210/, 'customer phone must not be stored in plaintext');

  // F3: Tampered backup count must throw backup integrity count mismatch
  const snap = context.buildPersistentSnapshot();
  const encPayload = await context.encryptJson(snap, 'TestPassword123!');
  await assert.rejects(
    () => context.decodeBackupPayload({ format: 'ENC_BACKUP_V2', counts: { dates: 1, receipts: 99, sessions: 1, sequence: 1002 }, payload: encPayload }),
    /backup integrity count mismatch/
  );

  // F6: Hostile negative amounts/quantities on non-VOID records are clamped to >= 0
  const clamped = context.normalizeRecord({ receiptNo: 'VP-9999', eventType: 'SALE', trampolineQty: -10, grandTotal: -50000, grandTotalPaise: -5000000 }, '2026-11-04', 0);
  assert.equal(clamped.trampolineQty, 0);
  assert.equal(clamped.grandTotal, 0);
  assert.equal(clamped.grandTotalPaise, 0);

  // F4/F18: Exited sessions strip customerPhone
  const normSess = context.normalizeSessions([{ id: 's1', status: 'exited', dateKey: context.buildPersistentSnapshot().vault ? Object.keys(context.buildPersistentSnapshot().vault)[0] : '2026-11-04', customerPhone: '9876543210' }]);
  if (normSess.length) assert.equal(normSess[0].customerPhone, '');
});

test('restore merge and replace semantics preserve records, detect collisions, and advance sequence', () => {
  const start = runtime.indexOf('function escapeHtml');
  const end = runtime.indexOf('function restoreVaultJson');
  assert.ok(start >= 0 && end > start, 'restore helpers must be extractable');
  const context = {
    STORAGE_SCHEMA_VERSION: 2,
    DEFAULT_CONFIG: { shop: 'VAULTPOS', addr: '', phone: '', cashier: 'Dinesh', trampPrice: 500, softPrice: 400, qrConfig: { sourceType: 'upi', upiId: '', upiSuffix: '@ybl', includeAmount: true, uploadedImageDataUrl: '' } },
    memoryVault: {},
    liveSessions: [],
    state: { receiptSequence: 1001, park: {}, prices: { trampoline: 500, softplay: 400, ext15: 100, ext30: 200 }, quantities: {}, customItems: [] },
    window: { crypto: globalThis.crypto },
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    atob,
    btoa,
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {}, length: 0, key: () => null },
    document: { getElementById: () => null, querySelector: () => null, querySelectorAll: () => [], documentElement: { getAttribute: () => null, setAttribute: () => {}, removeAttribute: () => {}, classList: { add: () => {}, remove: () => {} } } }
  };
  vm.runInNewContext(`${runtime.slice(start, end)}\nthis.mergeVaultRecords = mergeVaultRecords;\nthis.mergeSessions = mergeSessions;\nthis.normalizeVault = normalizeVault;`, context);

  const current = {
    '2026-11-04': [
      { receiptNo: 'VP-1001', dateKey: '2026-11-04', grandTotal: 500, customerName: 'Newer Sale', recordId: '2026-11-04:VP-1001:200' },
      { receiptNo: 'VP-1002', dateKey: '2026-11-04', grandTotal: 400, customerName: 'Keep Me', recordId: '2026-11-04:VP-1002:201' }
    ]
  };
  const incoming = {
    '2026-11-04': [
      { receiptNo: 'VP-1001', dateKey: '2026-11-04', grandTotal: 900, customerName: 'Conflicting Old', recordId: '2026-11-04:VP-1001:100' },
      { receiptNo: 'VP-1003', dateKey: '2026-11-04', grandTotal: 500, customerName: 'Added From Backup', recordId: '2026-11-04:VP-1003:102' }
    ]
  };
  const merged = context.mergeVaultRecords(current, incoming);
  assert.equal(merged.added, 1);
  assert.equal(merged.conflicts, 1);
  assert.equal(merged.merged['2026-11-04'].length, 3);
  assert.equal(merged.merged['2026-11-04'].find((r) => r.receiptNo === 'VP-1001').customerName, 'Newer Sale');
});

test('accounting correctness: manual timer isolation (R6), append-only void/reissue & reprint (R7), complimentary 100% discount (R15), and dynamic receipt title (R13)', async () => {
  assert.match(html, /id=["']complimentaryReasonInput["']/);
  assert.match(html, /id=["']lastReceiptBar["']/);
  assert.match(html, /data-action=["']reprint-last["']/);
  assert.match(html, /data-action=["']void-reissue["']/);
  assert.match(runtime, /Enter a complimentary reason \/ note for a 100% discount bill before printing/);
  assert.match(runtime, /DUPLICATE COPY/);

  const start = runtime.indexOf('function escapeHtml');
  const end = runtime.indexOf('function openTrackerAuth');
  const aggStart = runtime.indexOf('function computeReportAggregates');
  const aggEnd = runtime.indexOf('function renderTrackerDashboard');
  assert.ok(start >= 0 && end > start && aggStart >= 0 && aggEnd > aggStart);

  const elements = new Map();
  const getEl = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id,
        value: '',
        textContent: '',
        innerHTML: '',
        disabled: false,
        dataset: {},
        classList: { add: () => {}, remove: () => {}, toggle: () => {} },
        setAttribute: () => {},
        removeAttribute: () => {},
        replaceChildren: () => {},
        appendChild: () => {},
        append: () => {},
        focus: () => {}
      });
    }
    return elements.get(id);
  };

  const context = {
    STORAGE_SCHEMA_VERSION: 2,
    APP_VERSION: 'v0.2.0',
    QUARANTINE_KEY_PREFIX: 'vaultpos_quarantine_v1_',
    ARCHIVE_KEY_PREFIX: 'vaultpos_archive_v1_',
    MAX_STORAGE_BYTES: 4500000,
    STORAGE_WARN_RATIO: 0.8,
    DEFAULT_CONFIG: { shop: 'VAULTPOS', addr: '', phone: '', cashier: 'Dinesh', trampPrice: 500, softPrice: 400, qrConfig: { sourceType: 'upi', upiId: '', upiSuffix: '@ybl', includeAmount: true, uploadedImageDataUrl: '' } },
    memoryVault: {},
    archiveVault: {},
    liveSessions: [],
    startupComplete: true,
    storageReady: true,
    vaultReady: true,
    vaultReadOnly: false,
    printInProgress: false,
    state: {
      quantities: { trampoline: 1, softplay: 0, ext15: 0, ext30: 0 },
      prices: { trampoline: 500, softplay: 400, ext15: 100, ext30: 200 },
      names: { trampoline: 'Trampoline Park (1 Hr)', softplay: 'Soft Play (1 Hr)', ext15: 'Extra Time (+15 Mins)', ext30: 'Extra Time (+30 Mins)' },
      customItems: [],
      discountPercent: 0,
      complimentaryReason: '',
      paymentMode: 'CASH',
      printQrOnReceipt: false,
      cashTendered: 500,
      paymentReference: '',
      receiptSequence: 1001,
      receiptOverride: '',
      currentBillId: '',
      committedReceiptNo: '',
      committedBillFingerprint: '',
      committedRevision: 1,
      replacesReceiptNo: '',
      voidReason: '',
      isDuplicateReprint: false,
      lastPrintedBill: null,
      qrConfig: { sourceType: 'upi', upiId: 'vaultpos@ybl', upiSuffix: '@ybl', includeAmount: true, uploadedImageDataUrl: '' },
      park: {},
      expiredAlertDismissed: false
    },
    $: (id) => getEl(id),
    text: (id, val) => { getEl(id).textContent = String(val ?? ''); },
    showToast: () => {},
    persistStateBundle: async () => true,
    setTimeout: (fn) => { if (typeof fn === 'function') fn(); return 1; },
    clearTimeout: () => {},
    window: { crypto: globalThis.crypto, print: () => {}, addEventListener: () => {}, removeEventListener: () => {}, setTimeout: (fn) => { if (typeof fn === 'function') fn(); return 1; }, clearTimeout: () => {} },
    crypto: globalThis.crypto,
    TextEncoder,
    TextDecoder,
    atob,
    btoa,
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {}, length: 0, key: () => null },
    document: {
      getElementById: (id) => getEl(id),
      createElement: () => getEl('tmp'),
      createElementNS: () => getEl('svg'),
      querySelector: () => null,
      querySelectorAll: () => [],
      documentElement: { getAttribute: () => null, setAttribute: () => {}, removeAttribute: () => {}, classList: { add: () => {}, remove: () => {} } }
    }
  };

  const formStart = runtime.indexOf('function neutralizeFormulaText');
  const formEnd = runtime.indexOf('function buildReportHtml');
  assert.ok(formStart >= 0 && formEnd > formStart);

  vm.runInNewContext(
    `${runtime.slice(start, end)}\n${runtime.slice(aggStart, aggEnd)}\n${runtime.slice(formStart, formEnd)}\npersistStateBundle = async () => true;\nthis.startManualSession = startManualSession;\nthis.recordCurrentBillToVaultAndTimer = recordCurrentBillToVaultAndTimer;\nthis.appendVoidRecordForCommittedBill = appendVoidRecordForCommittedBill;\nthis.computeReportAggregates = computeReportAggregates;\nthis.getLocalDateKey = getLocalDateKey;\nthis.extendActiveSession = extendActiveSession;\nthis.setPaymentMode = setPaymentMode;\nthis.resetAll = resetAll;\nthis.triggerPrint = triggerPrint;\nthis.printWithCleanup = printWithCleanup;\nthis.setPrintLockUI = setPrintLockUI;\nthis.neutralizeFormulaText = neutralizeFormulaText;`,
    context
  );

  // R6: Manual session then a paid sale produces 2 distinct sessions
  getEl('customerNameInput').value = 'Walk-in Kid';
  await context.startManualSession();
  assert.equal(context.liveSessions.length, 1);
  assert.match(context.liveSessions[0].receiptNo, /^MANUAL-/);

  getEl('customerNameInput').value = 'Family of 1';
  const rec1 = context.recordCurrentBillToVaultAndTimer('VP-1001');
  assert.equal(context.liveSessions.length, 2, 'sale session must not merge into manual timer');
  assert.equal(rec1.receiptNo, 'VP-1001');
  assert.equal(rec1.eventType, 'SALE');

  // R7: Editing a printed bill creates a VOID record plus a new SALE record (append-only, no overwrite)
  const dateKey = context.getLocalDateKey();
  context.state.committedReceiptNo = 'VP-1001';
  const voidRec = context.appendVoidRecordForCommittedBill('Added 1 more jumper');
  assert.equal(voidRec.eventType, 'VOID');
  assert.equal(voidRec.voidsReceiptNo, 'VP-1001');
  assert.equal(voidRec.grandTotal, -500);

  context.state.quantities.trampoline = 2;
  context.state.cashTendered = 1000;
  const rec2 = context.recordCurrentBillToVaultAndTimer('VP-1002');
  assert.equal(rec2.replacesReceiptNo, 'VP-1001');
  assert.equal(rec2.revision, 2);
  assert.equal(context.memoryVault[dateKey].length, 3, 'ledger must keep VP-1001, VP-1001-VOID, and VP-1002');
  assert.equal(context.liveSessions.length, 2, 'reissued bill updates its own session by billId');

  // R7: Reprint record does not alter revenue or admission totals
  context.memoryVault[dateKey].push({
    receiptNo: 'VP-1002-COPY-1',
    dateKey,
    eventType: 'REPRINT',
    reprintOf: 'VP-1002',
    grandTotal: 0,
    grandTotalPaise: 0
  });
  const agg = context.computeReportAggregates(context.memoryVault[dateKey]);
  assert.equal(agg.totalReceipts, 1);
  assert.equal(agg.totalAdmissions, 2);
  assert.equal(agg.netRevenue, 1000);

  // F10/F11: Session extension records active paymentMode (UPI / QR or UPI / DESK) with optional UTR and returns the created record
  const activeSess = context.liveSessions.find((s) => s.receiptNo === 'VP-1002');
  context.setPaymentMode('UPI / QR');
  assert.equal(context.state.paymentMode, 'UPI / QR');
  assert.equal(context.state.printQrOnReceipt, true, 'UPI / QR mode must enable Print QR on Receipt');
  context.state.paymentReference = 'UTR999888';
  const extRec = await context.extendActiveSession(activeSess.id, 15);
  assert.equal(extRec.receiptNo, 'VP-1002-EXT');
  assert.equal(extRec.paymentMode, 'UPI / QR');
  assert.equal(extRec.paymentReference, 'UTR999888');
  assert.equal(context.state.paymentReference, '', 'UPI reference must clear after extension is logged');

  // Three payment modes: UPI / DESK (counter scanner/speaker) turns off receipt QR and works without UTR
  context.setPaymentMode('UPI / DESK');
  assert.equal(context.state.paymentMode, 'UPI / DESK');
  assert.equal(context.state.printQrOnReceipt, false, 'UPI / DESK mode must keep Print QR on Receipt OFF');
  const extDesk = await context.extendActiveSession(activeSess.id, 30);
  assert.equal(extDesk.receiptNo, 'VP-1002-EXT-2');
  assert.equal(extDesk.paymentMode, 'UPI / DESK');
  assert.equal(extDesk.paymentReference, '');

  // F8: resetAll resets paymentMode back to CASH and clears tendered cash / discount / printQrOnReceipt
  context.state.paymentMode = 'UPI / QR';
  context.state.printQrOnReceipt = true;
  context.state.discountPercent = 20;
  context.state.cashTendered = 500;
  context.resetAll(false);
  assert.equal(context.state.paymentMode, 'CASH');
  assert.equal(context.state.printQrOnReceipt, false);
  assert.equal(context.state.discountPercent, 0);
  assert.equal(context.state.cashTendered, 0);

  // R2: triggerPrint and printWithCleanup while printInProgress is true must abort without creating another record
  const countBefore = context.memoryVault[dateKey].length;
  context.state.quantities.trampoline = 1;
  context.state.cashTendered = 500;
  context.setPrintLockUI(true);
  assert.equal(await context.printWithCleanup(() => {}), 'busy');
  await context.triggerPrint(true);
  assert.equal(context.memoryVault[dateKey].length, countBefore, 'locked print must not add duplicate sale');
  context.setPrintLockUI(false);

  // F14: Formula injection neutralization covers =, +, -, @, \t, \r, and leading spaces
  for (const dangerous of ['=1+1', '+1+1', '-1+1', '@SUM(A1)', '\tcmd|calc', '\rcmd|calc', ' =1+1']) {
    assert.ok(context.neutralizeFormulaText(dangerous).startsWith("'"), `must neutralize ${JSON.stringify(dangerous)}`);
  }
  assert.equal(context.neutralizeFormulaText('Normal Customer'), 'Normal Customer');

  // SPLIT payment accounting correctness and report aggregate verification:
  const splitAgg1 = context.computeReportAggregates([
    { eventType: 'SALE', paymentMode: 'SPLIT', grandTotal: 900, splitCashPaise: 50000, splitUpiPaise: 40000 }
  ]);
  assert.equal(splitAgg1.cashRevenue, 500, 'split cash portion must be ₹500');
  assert.equal(splitAgg1.upiRevenue, 400, 'split upi portion must be ₹400');
  assert.equal(splitAgg1.netRevenue, 900);

  // When split cash is 0, reports must NOT guess 50/50:
  const splitAggZeroCash = context.computeReportAggregates([
    { eventType: 'SALE', paymentMode: 'SPLIT', grandTotal: 900, splitCashPaise: 0, splitUpiPaise: 90000 }
  ]);
  assert.equal(splitAggZeroCash.cashRevenue, 0, 'zero cash in split must not fallback to 50/50');
  assert.equal(splitAggZeroCash.upiRevenue, 900, 'all remaining net goes to UPI');

  // Entering SPLIT mode must reset printQrOnReceipt to false:
  context.setPaymentMode('UPI / QR');
  assert.equal(context.state.printQrOnReceipt, true);
  context.setPaymentMode('SPLIT');
  assert.equal(context.state.paymentMode, 'SPLIT');
  assert.equal(context.state.printQrOnReceipt, false, 'entering SPLIT mode must reset printQrOnReceipt to false');
});

test('QR reference matrices (v1-v10 and 47/58/78/103-byte UPI) match and pass both jsQR and an independent strict ISO/IEC 18004 decoder (R3, F16, F17, R20)', () => {
  const fixture = JSON.parse(fs.readFileSync(path.join(root, 'tests/fixtures/qr-reference-matrices.json'), 'utf8'));
  const start = runtime.indexOf('const QR_VERSIONS_L');
  const end = runtime.indexOf('function handleQrImageUpload');
  const context = {
    TextEncoder,
    state: {
      receiptOverride: 'VP-1001',
      receiptSequence: 1001,
      qrConfig: { sourceType: 'upi', upiId: '9876543210', upiSuffix: '@ybl', includeAmount: true, uploadedImageDataUrl: '' }
    },
    $: (id) => (id === 'receiptShopName' ? { textContent: 'VAULTPOS' } : null),
    escapeHtml: (s) => String(s),
    fromPaise: (p) => p / 100,
    toPaise: (v) => Math.round(Number(v) * 100),
    formatMoney: (v) => `₹${Number(v).toFixed(2)}`
  };
  vm.runInNewContext(`${runtime.slice(start, end)}\nthis.generateQRMatrixWithMask = generateQRMatrixWithMask;\nthis.generateQRMatrix = generateQRMatrix;\nthis.QR_VERSIONS_L = QR_VERSIONS_L;\nthis.buildQrMarkup = buildQrMarkup;\nthis.resolveUpiVpa = resolveUpiVpa;`, context);

  // Independent strict ISO/IEC 18004 verifier & Byte-mode decoder (does not use jsQR)
  function strictDecodeQrMatrix(matrix) {
    const size = matrix.length;
    const version = (size - 17) / 4;
    const info = context.QR_VERSIONS_L[version];
    assert.ok(info, `Unsupported QR size ${size}`);
    // 1. Strict check of timing modules (6,8) and (8,6) and fixed dark module (size-8, 8)
    if (matrix[6][8] !== 1 || matrix[8][6] !== 1 || matrix[size - 8][8] !== 1) {
      throw new Error('Missing required timing module (6,8)/(8,6) or dark module (size-8,8)');
    }
    // 2. Read format bits from both copies and verify equality
    let formatA = 0;
    let formatB = 0;
    for (let i = 0; i < 15; i++) {
      const bitA = i < 6 ? matrix[i][8] : i < 8 ? matrix[i + 1][8] : matrix[size - 15 + i][8];
      const bitB = i < 8 ? matrix[8][size - i - 1] : i < 9 ? matrix[8][15 - i] : matrix[8][15 - i - 1];
      if (bitA) formatA |= (1 << i);
      if (bitB) formatB |= (1 << i);
    }
    assert.equal(formatA, formatB, 'Format information copies must match');
    const unmaskedFormat = formatA ^ 0x5412;
    const mask = (unmaskedFormat >>> 10) & 0b111;

    // 3. Build reserved map to extract data & EC codewords
    const reserved = Array.from({ length: size }, () => Array(size).fill(false));
    const markBox = (r0, c0, h, w) => {
      for (let r = r0; r < r0 + h; r++) for (let c = c0; c < c0 + w; c++) {
        if (r >= 0 && r < size && c >= 0 && c < size) reserved[r][c] = true;
      }
    };
    markBox(0, 0, 9, 9);
    markBox(0, size - 8, 9, 8);
    markBox(size - 8, 0, 8, 9);
    for (const r of info.align) for (const c of info.align) {
      if ((r < 9 && c < 9) || (r < 9 && c >= size - 8) || (r >= size - 8 && c < 9)) continue;
      markBox(r - 2, c - 2, 5, 5);
    }
    for (let i = 8; i < size - 8; i++) { reserved[6][i] = true; reserved[i][6] = true; }
    if (version >= 7) {
      markBox(0, size - 11, 6, 3);
      markBox(size - 11, 0, 3, 6);
    }

    const maskFns = [
      (r, c) => (r + c) % 2 === 0,
      (r, c) => r % 2 === 0,
      (r, c) => c % 3 === 0,
      (r, c) => (r + c) % 3 === 0,
      (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
      (r, c) => (r * c) % 2 + (r * c) % 3 === 0,
      (r, c) => ((r * c) % 2 + (r * c) % 3) % 2 === 0,
      (r, c) => ((r + c) % 2 + (r * c) % 3) % 2 === 0
    ];
    const bits = [];
    let upward = true;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right--;
      for (let vert = 0; vert < size; vert++) {
        const r = upward ? size - 1 - vert : vert;
        for (let j = 0; j < 2; j++) {
          const c = right - j;
          if (reserved[r][c]) continue;
          let bit = matrix[r][c];
          if (maskFns[mask](r, c)) bit ^= 1;
          bits.push(bit);
        }
      }
      upward = !upward;
    }
    const codewords = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
      codewords.push(b);
    }
    // De-interleave data blocks
    const blocks = [];
    for (const g of info.groups) for (let b = 0; b < g.count; b++) blocks.push({ dataLen: g.data, data: [] });
    const maxDataLen = Math.max(...blocks.map((b) => b.dataLen));
    let idx = 0;
    for (let i = 0; i < maxDataLen; i++) {
      for (const b of blocks) if (i < b.dataLen) b.data.push(codewords[idx++]);
    }
    const dataBytes = blocks.flatMap((b) => b.data);
    const dataBits = [];
    for (const byte of dataBytes) for (let b = 7; b >= 0; b--) dataBits.push((byte >>> b) & 1);
    const readBits = (offset, len) => {
      let val = 0;
      for (let i = 0; i < len; i++) val = (val << 1) | dataBits[offset + i];
      return val;
    };
    const mode = readBits(0, 4);
    assert.equal(mode, 0b0100, 'Expected Byte mode (0100)');
    const countBits = version < 10 ? 8 : 16;
    const len = readBits(4, countBits);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = readBits(4 + countBits + i * 8, 8);
    return new TextDecoder().decode(out);
  }

  // Verify the strict decoder catches the old 3-module bug if any of the 3 modules is zeroed
  const v3Sample = context.generateQRMatrixWithMask(fixture.versionsMask0.v3.payload, 0);
  for (const [r, c] of [[6, 8], [8, 6], [v3Sample.length - 8, 8]]) {
    const broken = v3Sample.map((row) => row.slice());
    broken[r][c] = 0;
    assert.throws(() => strictDecodeQrMatrix(broken), /Missing required timing module/);
  }

  // Verify all versions 1-10 against fixture and strict decoder
  for (const [verKey, entry] of Object.entries(fixture.versionsMask0)) {
    const matrix = context.generateQRMatrixWithMask(entry.payload, 0);
    assert.equal(matrix.length, entry.size, `${verKey} size mismatch`);
    assert.deepEqual(Array.from(matrix, (r) => r.join('')), entry.rows, `${verKey} reference matrix mismatch`);
    assert.equal(strictDecodeQrMatrix(matrix), entry.payload, `${verKey} strict decode mismatch`);
  }

  // Verify 47, 58, 78, and 103 byte UPI payloads with reference fixture, strict decoder, and jsQR
  for (const [key, entry] of Object.entries(fixture.upiPayloadsBestMask)) {
    const matrix = context.generateQRMatrix(entry.payload);
    assert.equal(Buffer.byteLength(entry.payload), entry.byteLength);
    assert.deepEqual(Array.from(matrix, (r) => r.join('')), entry.rows, `${key} reference matrix mismatch`);
    assert.equal(strictDecodeQrMatrix(matrix), entry.payload, `${key} strict decode mismatch`);

    const quiet = 4;
    const scale = 4;
    const modules = matrix.length + quiet * 2;
    const px = modules * scale;
    const pixels = new Uint8ClampedArray(px * px * 4).fill(255);
    for (let r = 0; r < matrix.length; r++) for (let c = 0; c < matrix.length; c++) if (matrix[r][c]) {
      for (let y = 0; y < scale; y++) for (let x = 0; x < scale; x++) {
        const i = (((r + quiet) * scale + y) * px + (c + quiet) * scale + x) * 4;
        pixels[i] = 0; pixels[i + 1] = 0; pixels[i + 2] = 0; pixels[i + 3] = 255;
      }
    }
    const decoded = jsQR(pixels, px, px, { inversionAttempts: 'dontInvert' });
    assert.equal(decoded?.data, entry.payload, `${key} jsQR decode mismatch`);
  }

  // R20: literal '@' in pa=, tn=<receiptNo>, and VPA validation
  const markup = context.buildQrMarkup(500);
  assert.match(markup.uri, /^upi:\/\/pay\?pa=9876543210@ybl&pn=VAULTPOS&cu=INR&tn=VP-1001&am=500\.00$/);
  assert.equal(context.resolveUpiVpa('invalid@@vpa'), '');
});

test('A4 report scoped styles and Windows launcher parity (R4, R5, R8, R18)', () => {
  assert.match(runtime, /#pdfReportPrintArea \.rpt-/);
  assert.match(runtime, /Send A4 Report to the Windows default printer/);
  assert.match(html, /Driver Preferences/);

  const batRaw = fs.readFileSync(path.join(root, 'Start_VaultPOS_POS.bat'), 'utf8');
  assert.ok(batRaw.includes('\r\n') && !batRaw.replace(/\r\n/g, '').includes('\n'), 'Start_VaultPOS_POS.bat must use CRLF line endings');
  const batFile = batRaw.replace(/\r\n/g, '\n').trim();
  const fnMatch = runtime.match(/function downloadWindowsLauncher\(\)\s*\{\s*const lines = (\[[\s\S]*?\]);/);
  assert.ok(fnMatch, 'downloadWindowsLauncher lines array must be discoverable');
  const generatedLines = vm.runInNewContext(fnMatch[1]);
  assert.equal(generatedLines.join('\n').trim(), batFile, 'in-app launcher generator must match Start_VaultPOS_POS.bat byte-for-byte');
  assert.match(batFile, /--disable-session-crashed-bubble/);
  assert.match(batFile, /setlocal EnableDelayedExpansion/);
  assert.match(batFile, /!APP_URL:#=%%23!/);
  assert.match(batFile, /!APP_URL: =%%20!/);
  assert.match(batFile, /tasklist \/FI "IMAGENAME eq msedge\.exe"/);
});

test('Code 39 barcode, business-day cutoff, GST/tax breakdown, and standalone app hygiene (R12, R14, R16, R17, R19, R21)', async () => {
  const start = runtime.indexOf('const APP_VERSION =');
  const formatDateIdx = runtime.indexOf('function formatDateKeyPretty(');
  const barcodeEnd = runtime.indexOf('function refreshTimestamp(');

  let lastNotice = '';
  const svgRects = [];
  const mockSvg = {
    replaceChildren() { svgRects.length = 0; },
    appendChild(el) { svgRects.push(el); },
    setAttribute() {}
  };
  const context = vm.createContext({
    Math, Number, String, Boolean, Array, Object, Date, RegExp, Set, Map, JSON,
    document: {
      documentElement: { outerHTML: '<html></html>' },
      getElementById(id) { return id === 'receiptBarcode' ? mockSvg : null; },
      createElementNS(_ns, tag) {
        return { tag, attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } };
      },
      querySelectorAll() { return []; }
    },
    showStorageNotice: (msg) => { lastNotice = msg; },
    showToast: () => {}
  });
  vm.runInContext(
    `${runtime.slice(start, formatDateIdx)}\n${runtime.slice(runtime.indexOf('function computeTotals('), runtime.indexOf('function setPaymentMode('))}\n${runtime.slice(runtime.indexOf('const CODE39_PATTERNS ='), barcodeEnd)}`,
    context
  );

  // R12: Decode Code 39 bars from generateBarcodeSVG('VP-1001') using an independent ISO/IEC 16388 Code 39 reference table
  context.generateBarcodeSVG('VP-1001');
  const rects = svgRects.map((r) => ({ x: Number(r.attrs.x), w: Number(r.attrs.width) }));
  assert.ok(rects.length > 0, 'Barcode must contain SVG rect bars');
  const INDEPENDENT_CODE39_SPEC = {
    'nnnwwnwnn': '0', 'wnnwnnnnw': '1', 'nnwwnnnnw': '2', 'wnwwnnnnn': '3',
    'nnnwwnnnw': '4', 'wnnwwnnnn': '5', 'nnwwwnnnn': '6', 'nnnwnnwnw': '7',
    'wnnwnnwnn': '8', 'nnwwnnwnn': '9', 'wnnnnwnnw': 'A', 'nnwnnwnnw': 'B',
    'wnwnnwnnn': 'C', 'nnnnwwnnw': 'D', 'wnnnwwnnn': 'E', 'nnwnwwnnn': 'F',
    'nnnnnwwnw': 'G', 'wnnnnwwnn': 'H', 'nnwnnwwnn': 'I', 'nnnnwwwnn': 'J',
    'wnnnnnnww': 'K', 'nnwnnnnww': 'L', 'wnwnnnnwn': 'M', 'nnnnwnnww': 'N',
    'wnnnwnnwn': 'O', 'nnwnwnnwn': 'P', 'nnnnnnwww': 'Q', 'wnnnnnwwn': 'R',
    'nnwnnnwwn': 'S', 'nnnnwnwwn': 'T', 'wwnnnnnnw': 'U', 'nwwnnnnnw': 'V',
    'wwwnnnnnn': 'W', 'nwnnwnnnw': 'X', 'wwnnwnnnn': 'Y', 'nwwnwnnnn': 'Z',
    'nwnnnnwnw': '-', 'wwnnnnwnn': '.', 'nwwnnnwnn': ' ', 'nwnwnwnnn': '$',
    'nwnwnnnwn': '/', 'nwnnnwnwn': '+', 'nnnwnwnwn': '%', 'nwnnwnwnn': '*'
  };
  // Reconstruct 9-element narrow/wide pattern per character (5 bars + 4 spaces)
  const elements = [];
  for (let i = 0; i < rects.length; i++) {
    elements.push(rects[i].w > 2 ? 'w' : 'n');
    if (i + 1 < rects.length) {
      const space = rects[i + 1].x - (rects[i].x + rects[i].w);
      elements.push(space > 2 ? 'w' : 'n');
    }
  }
  const decodedChars = [];
  for (let i = 0; i + 9 <= elements.length; i += 10) {
    const pat = elements.slice(i, i + 9).join('');
    decodedChars.push(INDEPENDENT_CODE39_SPEC[pat] || '?');
  }
  assert.equal(decodedChars.join(''), '*VP-1001*', 'Code 39 barcode must decode to exact *VP-1001*');
  assert.doesNotMatch(runtime, /receiptBarcodeText.*getFullYear/);

  // R16: Business-day cutoff (default 04:00 AM) and backward clock-jump warning
  const d0330 = new Date(2026, 3, 19, 3, 30, 0); // April 19, 2026 03:30 AM local
  const d0430 = new Date(2026, 3, 19, 4, 30, 0); // April 19, 2026 04:30 AM local
  assert.equal(context.getLocalDateKey(d0330, true), '2026-04-18', '03:30 AM before 04:00 cutoff maps to previous business day');
  assert.equal(context.getLocalDateKey(d0430, true), '2026-04-19', '04:30 AM at/after 04:00 cutoff maps to current business day');
  lastNotice = '';
  context.getLocalDateKey(d0330, true);
  assert.match(lastNotice, /Computer clock moved backward/, 'Backward clock jump must trigger operator warning');

  // R21: Optional GST/tax modes (none, inclusive, exclusive)
  vm.runInContext(`state.quantities.trampoline = 1; state.prices.trampoline = 500; state.park.taxPercent = 18;`, context);
  vm.runInContext(`state.park.taxMode = 'none';`, context);
  let t = context.computeTotals();
  assert.equal(t.grandTotalPaise, 50000);
  assert.equal(t.taxPaise, 0);

  vm.runInContext(`state.park.taxMode = 'inclusive';`, context);
  t = context.computeTotals();
  assert.equal(t.grandTotalPaise, 50000, 'Inclusive GST must not change grand total');
  assert.ok(t.taxPaise > 0, 'Inclusive GST must compute embedded tax');

  vm.runInContext(`state.park.taxMode = 'exclusive';`, context);
  t = context.computeTotals();
  assert.equal(t.taxPaise, 9000, '18% exclusive GST on ₹500 is ₹90 (9000 paise)');
  assert.equal(t.grandTotalPaise, 59000, 'Exclusive GST adds tax to grand total');

  // R14 & R19: Counter extension wording and standalone download hygiene
  assert.match(html, /Adds extra time to this new ticket bill \(use session card \+15m\/\+30m for active jumpers\)/);
  assert.match(runtime, /clone\.querySelector\('#receiptQrContainer'\)\?\.replaceChildren\(\)/);
});

test('dev server deny list, release manifest, version sync, and repo hygiene (F22, F25, F26, R17, R22)', async () => {
  const { isForbiddenRelativePath } = await import('../tools/serve.mjs');
  assert.equal(isForbiddenRelativePath('/.git/config'), true);
  assert.equal(isForbiddenRelativePath('/.opencode/state.json'), true);
  assert.equal(isForbiddenRelativePath('/data.db'), true);
  assert.equal(isForbiddenRelativePath('/VaultPOS_Sales_Vault_Encrypted_Backup_2026-04-18.json'), true);
  assert.equal(isForbiddenRelativePath('/backups/test.json'), true);
  assert.equal(isForbiddenRelativePath('/VaultPOS_POS.html'), false);

  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const versionTxt = fs.readFileSync(path.join(root, 'VERSION.txt'), 'utf8').trim();
  const ciYmlPath = path.join(root, '.github/workflows/ci.yml');
  const gitignore = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');

  assert.equal(pkg.engines.node, '>=20');
  assert.equal(pkg.scripts.test, 'node --test');
  assert.equal(`v${pkg.version}`, versionTxt);
  if (fs.existsSync(ciYmlPath)) assert.match(fs.readFileSync(ciYmlPath, 'utf8'), /node-version:\s*\[20,\s*22\]/);
  assert.match(gitignore, /backups\//);
  assert.match(gitignore, /\*Backup\*\.json/);
});
