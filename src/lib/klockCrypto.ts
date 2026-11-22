import {
  CompressionAlgorithm,
  algorithmFromFlag,
  compressBytes,
  decompressBytes,
  flagFromAlgorithm,
} from './compressionCodecs';

export const KLOCK_MAGIC = 'KLOCK001';
export const HEADER_LENGTH = 41; // 8 (magic) + 1 (flag) + 4 (iterations) + 16 (salt) + 12 (iv)

export type { CompressionAlgorithm };

export interface StagedFile {
  id: string;
  file: File;
  relativePath: string;
  size: number;
  mtime: number;
}

export interface KlockEntryMeta {
  path: string;
  size: number;
  mtime: number;
  sha256: string;
}

export interface KlockManifest {
  version: number;
  createdAt: string;
  compressionAlgorithm?: CompressionAlgorithm;
  payloadSha256?: string;
  entries: KlockEntryMeta[];
}

export interface KlockHeaderInfo {
  magic: string;
  validMagic: boolean;
  compressionAlgorithm: CompressionAlgorithm;
  iterations: number;
  saltHex: string;
  ivHex: string;
  totalBytes: number;
  ciphertextBytes: number;
  archiveSha256?: string;
}

export interface DecryptedEntry {
  path: string;
  size: number;
  mtime: number;
  expectedSha256: string;
  actualSha256: string;
  integrityVerified: boolean;
  data: Uint8Array<ArrayBuffer>;
}

export interface DecryptedArchiveResult {
  header: KlockHeaderInfo;
  manifest: KlockManifest;
  entries: DecryptedEntry[];
  compressedSize: number;
  uncompressedSize: number;
  archiveSha256: string;
  expectedArchiveSha256?: string;
  archiveChecksumMatch: boolean | null;
  containerIntegrityVerified: boolean;
  allFilesVerified: boolean;
  failedIntegrityPaths: string[];
}

export interface BatchProgress {
  stage: 'reading' | 'compressing' | 'deriving' | 'encrypting' | 'checksum';
  label: string;
  current: number;
  total: number;
  percent: number;
}

export interface EncryptArchiveOptions {
  files: StagedFile[];
  passphrase: string;
  keyfileBytes?: Uint8Array<ArrayBuffer> | null;
  compressionAlgorithm: CompressionAlgorithm;
  compressionLevel: 1 | 3 | 6 | 9;
  iterations: number;
  onProgress?: (progress: BatchProgress) => void;
}

export interface EncryptArchiveResult {
  archiveBytes: Uint8Array<ArrayBuffer>;
  archiveSha256: string;
  payloadSha256: string;
  uncompressedTotal: number;
  compressedPayloadSize: number;
  finalArchiveSize: number;
  saltHex: string;
  ivHex: string;
  entryCount: number;
  compressionAlgorithm: CompressionAlgorithm;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  const idx = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, idx);
  return `${idx === 0 ? value.toFixed(0) : value.toFixed(2)} ${units[idx]}`;
}

export async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const digest = await window.crypto.subtle.digest('SHA-256', bytes);
  return toHex(new Uint8Array(digest));
}

export function normalizeExpectedChecksum(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) return null;
  // Support standard `sha256sum` output format: "<64-hex>  filename"
  const match = trimmed.match(/([a-f0-9]{64})/);
  return match ? match[1] : trimmed;
}

async function buildSecretMaterial(
  passphrase: string,
  keyfileBytes?: Uint8Array<ArrayBuffer> | null
): Promise<Uint8Array<ArrayBuffer>> {
  if (keyfileBytes && keyfileBytes.byteLength > 0) {
    const keyfileDigest = await sha256Hex(keyfileBytes);
    const combined = `${passphrase}:${keyfileDigest}`;
    const encoded = textEncoder.encode(combined);
    const copy = new Uint8Array(encoded.byteLength);
    copy.set(encoded);
    return copy;
  }
  const encoded = textEncoder.encode(passphrase);
  const copy = new Uint8Array(encoded.byteLength);
  copy.set(encoded);
  return copy;
}

async function deriveAesGcmKey(
  passphrase: string,
  keyfileBytes: Uint8Array<ArrayBuffer> | null | undefined,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
  usage: KeyUsage[]
): Promise<CryptoKey> {
  const secretBytes = await buildSecretMaterial(passphrase, keyfileBytes);
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    secretBytes,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    usage
  );
}

export function inspectKlockHeader(archiveBytes: Uint8Array): KlockHeaderInfo {
  if (archiveBytes.byteLength < HEADER_LENGTH + 16) {
    throw new Error('File is too small to be a valid .klock encrypted archive.');
  }

  const magic = textDecoder.decode(archiveBytes.subarray(0, 8));
  const validMagic = magic === KLOCK_MAGIC;
  const flag = archiveBytes[8];
  const compressionAlgorithm = validMagic ? algorithmFromFlag(flag) : 'deflate';

  const view = new DataView(
    archiveBytes.buffer,
    archiveBytes.byteOffset,
    archiveBytes.byteLength
  );
  const iterations = view.getUint32(9, false);
  const salt = archiveBytes.subarray(13, 29);
  const iv = archiveBytes.subarray(29, 41);

  return {
    magic,
    validMagic,
    compressionAlgorithm,
    iterations,
    saltHex: toHex(salt),
    ivHex: toHex(iv),
    totalBytes: archiveBytes.byteLength,
    ciphertextBytes: archiveBytes.byteLength - HEADER_LENGTH,
  };
}

export async function encryptKlockArchive(
  options: EncryptArchiveOptions
): Promise<EncryptArchiveResult> {
  const {
    files,
    passphrase,
    keyfileBytes,
    compressionAlgorithm,
    compressionLevel,
    iterations,
    onProgress,
  } = options;

  if (files.length === 0) {
    throw new Error('Stage at least one file before locking the archive.');
  }
  if (!passphrase && (!keyfileBytes || keyfileBytes.byteLength === 0)) {
    throw new Error('Provide a password or keyfile to lock the archive.');
  }

  const yieldToUi = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

  const fileBuffers: Uint8Array<ArrayBuffer>[] = [];
  const entries: KlockEntryMeta[] = [];
  let payloadDataLength = 0;

  for (let i = 0; i < files.length; i++) {
    const item = files[i];
    onProgress?.({
      stage: 'reading',
      label: `Reading & hashing ${item.relativePath}`,
      current: i + 1,
      total: files.length,
      percent: Math.round(((i + 1) / files.length) * 40),
    });
    const ab = await item.file.arrayBuffer();
    const bytes = new Uint8Array(ab);
    const hash = await sha256Hex(bytes);
    fileBuffers.push(bytes);
    entries.push({
      path: item.relativePath,
      size: bytes.byteLength,
      mtime: item.mtime,
      sha256: hash,
    });
    payloadDataLength += bytes.byteLength;
    if (i % 8 === 7) {
      await yieldToUi();
    }
  }

  const concatenatedPayload = new Uint8Array(payloadDataLength);
  let payloadCursor = 0;
  for (const buf of fileBuffers) {
    concatenatedPayload.set(buf, payloadCursor);
    payloadCursor += buf.byteLength;
  }
  const payloadSha256 = await sha256Hex(concatenatedPayload);

  const manifest: KlockManifest = {
    version: 2,
    createdAt: new Date().toISOString(),
    compressionAlgorithm,
    payloadSha256,
    entries,
  };

  const manifestBytes = textEncoder.encode(JSON.stringify(manifest));
  const innerSize = 4 + manifestBytes.byteLength + payloadDataLength;
  const innerContainer = new Uint8Array(innerSize);
  const innerView = new DataView(innerContainer.buffer);
  innerView.setUint32(0, manifestBytes.byteLength, false);
  innerContainer.set(manifestBytes, 4);
  innerContainer.set(concatenatedPayload, 4 + manifestBytes.byteLength);

  onProgress?.({
    stage: 'compressing',
    label: `Compressing ${files.length} file(s) with ${compressionAlgorithm}`,
    current: files.length,
    total: files.length,
    percent: 55,
  });
  await yieldToUi();

  const payloadToEncrypt = compressBytes(
    innerContainer,
    compressionAlgorithm,
    compressionLevel
  );

  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  window.crypto.getRandomValues(salt);
  window.crypto.getRandomValues(iv);

  const headerBytes = new Uint8Array(HEADER_LENGTH);
  headerBytes.set(textEncoder.encode(KLOCK_MAGIC), 0);
  headerBytes[8] = flagFromAlgorithm(compressionAlgorithm);
  new DataView(headerBytes.buffer).setUint32(9, iterations, false);
  headerBytes.set(salt, 13);
  headerBytes.set(iv, 29);

  onProgress?.({
    stage: 'deriving',
    label: `Deriving AES-256 key (${iterations.toLocaleString()} PBKDF2 rounds)`,
    current: files.length,
    total: files.length,
    percent: 75,
  });
  await yieldToUi();

  const aesKey = await deriveAesGcmKey(passphrase, keyfileBytes, salt, iterations, ['encrypt']);

  onProgress?.({
    stage: 'encrypting',
    label: 'Encrypting compressed container with AES-256-GCM',
    current: files.length,
    total: files.length,
    percent: 90,
  });
  await yieldToUi();

  const ciphertextBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: headerBytes,
      tagLength: 128,
    },
    aesKey,
    payloadToEncrypt
  );

  const ciphertext = new Uint8Array(ciphertextBuffer);
  const archiveBytes = new Uint8Array(HEADER_LENGTH + ciphertext.byteLength);
  archiveBytes.set(headerBytes, 0);
  archiveBytes.set(ciphertext, HEADER_LENGTH);

  onProgress?.({
    stage: 'checksum',
    label: 'Generating archive SHA-256 integrity checksum',
    current: files.length,
    total: files.length,
    percent: 98,
  });
  const archiveSha256 = await sha256Hex(archiveBytes);

  return {
    archiveBytes,
    archiveSha256,
    payloadSha256,
    uncompressedTotal: innerSize,
    compressedPayloadSize: payloadToEncrypt.byteLength,
    finalArchiveSize: archiveBytes.byteLength,
    saltHex: toHex(salt),
    ivHex: toHex(iv),
    entryCount: entries.length,
    compressionAlgorithm,
  };
}

export async function decryptKlockArchive(
  archiveBytes: Uint8Array<ArrayBuffer>,
  passphrase: string,
  keyfileBytes?: Uint8Array<ArrayBuffer> | null,
  expectedArchiveChecksum?: string
): Promise<DecryptedArchiveResult> {
  const header = inspectKlockHeader(archiveBytes);
  if (!header.validMagic) {
    throw new Error('Invalid file signature. Expected KLOCK001 container header.');
  }

  const archiveSha256 = await sha256Hex(archiveBytes);
  const normalizedExpected = expectedArchiveChecksum
    ? normalizeExpectedChecksum(expectedArchiveChecksum)
    : null;
  const archiveChecksumMatch =
    normalizedExpected !== null ? normalizedExpected === archiveSha256 : null;

  if (archiveChecksumMatch === false) {
    throw new Error(
      `Archive integrity check failed! Expected SHA-256 ${normalizedExpected}, but computed ${archiveSha256}. The .klock file may be corrupted or modified.`
    );
  }

  const headerBytes = new Uint8Array(HEADER_LENGTH);
  headerBytes.set(archiveBytes.subarray(0, HEADER_LENGTH));

  const salt = new Uint8Array(16);
  salt.set(archiveBytes.subarray(13, 29));

  const iv = new Uint8Array(12);
  iv.set(archiveBytes.subarray(29, 41));

  const ciphertext = new Uint8Array(archiveBytes.byteLength - HEADER_LENGTH);
  ciphertext.set(archiveBytes.subarray(HEADER_LENGTH));

  const aesKey = await deriveAesGcmKey(
    passphrase,
    keyfileBytes,
    salt,
    header.iterations,
    ['decrypt']
  );

  let decryptedCompressed: ArrayBuffer;
  try {
    decryptedCompressed = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: headerBytes,
        tagLength: 128,
      },
      aesKey,
      ciphertext
    );
  } catch {
    throw new Error(
      'Authentication failed: incorrect password, missing keyfile, or tampered archive container (AES-GCM tag mismatch).'
    );
  }

  const decryptedBytes = new Uint8Array(decryptedCompressed);
  let innerContainer: Uint8Array<ArrayBuffer>;
  try {
    innerContainer = decompressBytes(decryptedBytes, header.compressionAlgorithm);
  } catch (err) {
    const detail = err instanceof Error ? err.message : 'invalid compressed stream';
    throw new Error(
      `Decompression failed (${header.compressionAlgorithm}) after decryption: ${detail}`
    );
  }

  if (innerContainer.byteLength < 4) {
    throw new Error('Corrupted inner manifest container.');
  }

  const manifestLen = new DataView(innerContainer.buffer).getUint32(0, false);
  if (4 + manifestLen > innerContainer.byteLength) {
    throw new Error('Manifest length exceeds decrypted payload size.');
  }

  const manifestJson = textDecoder.decode(innerContainer.subarray(4, 4 + manifestLen));
  const manifest = JSON.parse(manifestJson) as KlockManifest;

  const rawPayloadSlice = new Uint8Array(
    innerContainer.byteLength - (4 + manifestLen)
  );
  rawPayloadSlice.set(innerContainer.subarray(4 + manifestLen));
  const computedPayloadSha = await sha256Hex(rawPayloadSlice);
  const containerIntegrityVerified = manifest.payloadSha256
    ? manifest.payloadSha256 === computedPayloadSha
    : true;

  let cursor = 4 + manifestLen;
  const entries: DecryptedEntry[] = [];
  const failedIntegrityPaths: string[] = [];

  for (const meta of manifest.entries) {
    if (cursor + meta.size > innerContainer.byteLength) {
      throw new Error(`Truncated entry data for ${meta.path}`);
    }
    const slice = new Uint8Array(meta.size);
    slice.set(innerContainer.subarray(cursor, cursor + meta.size));
    cursor += meta.size;

    const actualSha256 = await sha256Hex(slice);
    const integrityVerified = actualSha256 === meta.sha256;
    if (!integrityVerified) {
      failedIntegrityPaths.push(meta.path);
    }
    entries.push({
      path: meta.path,
      size: meta.size,
      mtime: meta.mtime,
      expectedSha256: meta.sha256,
      actualSha256,
      integrityVerified,
      data: slice,
    });
  }

  return {
    header: { ...header, archiveSha256 },
    manifest,
    entries,
    compressedSize: decryptedBytes.byteLength,
    uncompressedSize: innerContainer.byteLength,
    archiveSha256,
    expectedArchiveSha256: normalizedExpected ?? undefined,
    archiveChecksumMatch,
    containerIntegrityVerified,
    allFilesVerified:
      containerIntegrityVerified && failedIntegrityPaths.length === 0,
    failedIntegrityPaths,
  };
}

export function generateSecurePassphrase(wordCount = 5): string {
  const words = [
    'alpine', 'amber', 'anchor', 'argon', 'balsa', 'basalt', 'beacon', 'birch',
    'bison', 'bluff', 'boulder', 'bramble', 'bronze', 'canyon', 'cedar', 'chalice',
    'cinder', 'cipher', 'cobalt', 'compass', 'copper', 'cornet', 'crater', 'crest',
    'cypress', 'delta', 'diode', 'drift', 'ember', 'enclave', 'epoch', 'falcon',
    'fathom', 'ferrite', 'fjord', 'flint', 'fossil', 'frost', 'garnet', 'glacier',
    'granite', 'gravel', 'harbor', 'hazel', 'helium', 'horizon', 'iron', 'jasper',
    'juniper', 'keel', 'kernel', 'kestrel', 'larch', 'lattice', 'laurel', 'ledge',
    'lichen', 'lumen', 'lynx', 'magma', 'maple', 'marble', 'marrow', 'meadow',
    'meridian', 'mesa', 'mineral', 'mortar', 'moss', 'nebula', 'nickel', 'nimbus',
    'north', 'obsidian', 'ochre', 'onyx', 'orbit', 'osprey', 'oxide', 'pebble',
    'pendulum', 'petrel', 'phosphor', 'pinnacle', 'plinth', 'polar', 'prism',
    'quartz', 'quiver', 'raven', 'ridge', 'rivet', 'sable', 'saffron', 'sandstone',
    'sequoia', 'shale', 'shelter', 'signal', 'silver', 'slate', 'solstice', 'spruce',
    'stratum', 'summit', 'tallow', 'tarmac', 'thistle', 'timber', 'titanium', 'topaz',
    'torrent', 'tundra', 'umber', 'vector', 'velvet', 'verge', 'vertex', 'vesper',
    'walnut', 'warden', 'willow', 'zenith', 'zircon',
  ];
  const randomValues = new Uint32Array(wordCount + 1);
  window.crypto.getRandomValues(randomValues);
  const picked: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    picked.push(words[randomValues[i] % words.length]);
  }
  const suffix = (randomValues[wordCount] % 900) + 100;
  return `${picked.join('-')}-${suffix}`;
}

export interface PasswordStrengthFeedback {
  bits: number;
  percentage: number;
  score: 0 | 1 | 2 | 3 | 4;
  label: 'Empty' | 'Weak' | 'Moderate' | 'Strong' | 'Very Strong';
  hints: string[];
  checks: {
    minLength: boolean;
    hasMixedCase: boolean;
    hasDigit: boolean;
    hasSymbol: boolean;
  };
  hasWeakPattern: boolean;
}

export function evaluatePasswordStrength(
  passphrase: string,
  hasKeyfile: boolean
): PasswordStrengthFeedback {
  const hasLower = /[a-z]/.test(passphrase);
  const hasUpper = /[A-Z]/.test(passphrase);
  const hasDigit = /[0-9]/.test(passphrase);
  const hasSymbol = /[^a-zA-Z0-9]/.test(passphrase);
  const minLength = passphrase.length >= 12;
  const hasMixedCase = hasLower && hasUpper;

  if (!passphrase && !hasKeyfile) {
    return {
      bits: 0,
      percentage: 0,
      score: 0,
      label: 'Empty',
      hints: ['Enter a password (12+ characters recommended).'],
      checks: { minLength, hasMixedCase, hasDigit, hasSymbol },
      hasWeakPattern: false,
    };
  }

  let charset = 0;
  if (hasLower) charset += 26;
  if (hasUpper) charset += 26;
  if (hasDigit) charset += 10;
  if (hasSymbol) charset += 32;

  const uniqueChars = new Set(passphrase).size;
  const repetitionFactor =
    passphrase.length > 0 ? Math.min(1, uniqueChars / Math.min(passphrase.length, 12)) : 1;

  const lower = passphrase.toLowerCase();
  const hasSequential =
    /(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwerty|asdf|password|admin|letmein)/.test(
      lower
    );
  const hasRepeatedRun = /(.)\1{2,}/.test(passphrase);
  const hasWeakPattern = hasSequential || hasRepeatedRun;

  const rawBits = passphrase.length * (charset > 0 ? Math.log2(charset) : 0);
  const adjustedPassBits =
    rawBits * (0.45 + 0.55 * repetitionFactor) * (hasWeakPattern ? 0.65 : 1);
  const bits = Math.round(adjustedPassBits + (hasKeyfile ? 128 : 0));
  const percentage = Math.min(100, Math.round((bits / 112) * 100));

  const hints: string[] = [];
  if (hasWeakPattern) hints.push('Avoid common words, sequences, or repeated characters');
  if (!minLength) hints.push('Use at least 12 characters');
  if (!hasUpper) hints.push('Add uppercase letters');
  if (!hasDigit) hints.push('Add digits');
  if (!hasSymbol) hints.push('Add symbols or hyphens');

  const checks = { minLength, hasMixedCase, hasDigit, hasSymbol };

  if (bits >= 96 && !hasWeakPattern) {
    return { bits, percentage, score: 4, label: 'Very Strong', hints: [], checks, hasWeakPattern };
  }
  if (bits >= 64) {
    return {
      bits,
      percentage,
      score: 3,
      label: 'Strong',
      hints: hints.slice(0, 1),
      checks,
      hasWeakPattern,
    };
  }
  if (bits >= 40) {
    return {
      bits,
      percentage,
      score: 2,
      label: 'Moderate',
      hints: hints.slice(0, 2),
      checks,
      hasWeakPattern,
    };
  }
  return { bits, percentage, score: 1, label: 'Weak', hints, checks, hasWeakPattern };
}
