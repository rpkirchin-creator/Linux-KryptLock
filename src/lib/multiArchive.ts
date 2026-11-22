import SevenZip from '7z-wasm';
import sevenZipWasmUrl from '7z-wasm/7zz.wasm?url';
import {
  ZipReader,
  ZipWriter,
  Uint8ArrayReader,
  Uint8ArrayWriter,
  configure as configureZipJs,
} from '@zip.js/zip.js';
import { createExtractorFromData, UnrarError } from 'node-unrar-js';
import unrarWasmUrl from 'node-unrar-js/esm/js/unrar.wasm?url';
import { gunzipSync, gzipSync } from 'fflate';
import { getBzip2Api } from './bzip2Codec';
import {
  BatchProgress,
  CompressionAlgorithm,
  DecryptedEntry,
  StagedFile,
  decryptKlockArchive,
  encryptKlockArchive,
  normalizeExpectedChecksum,
  sha256Hex,
} from './klockCrypto';

configureZipJs({ useWebWorkers: false });

export type ArchiveFormatId =
  | 'klock'
  | '7z'
  | 'zip'
  | 'tar.gz'
  | 'gz'
  | 'tar.bz2'
  | 'bz2'
  | 'tar.xz'
  | 'xz'
  | 'tar'
  | 'rar'
  | 'other';

export type PackFormatId =
  | 'klock'
  | '7z'
  | 'zip'
  | 'tar.gz'
  | 'tar.bz2'
  | 'tar.xz'
  | 'rar';

export interface PackFormatMeta {
  id: PackFormatId;
  label: string;
  shortLabel: string;
  extension: string;
  supportsPasswordInBrowser: 'required' | 'optional' | 'none' | 'linux-only';
  browserCreateSupported: boolean;
  summary: string;
}

export const PACK_FORMATS: PackFormatMeta[] = [
  {
    id: 'klock',
    label: 'KryptLock (.klock)',
    shortLabel: '.klock',
    extension: '.klock',
    supportsPasswordInBrowser: 'required',
    browserCreateSupported: true,
    summary: 'AES-256-GCM + SHA-256 integrity + Deflate/Gzip/Bzip2/LZMA',
  },
  {
    id: '7z',
    label: '7-Zip (.7z)',
    shortLabel: '.7z',
    extension: '.7z',
    supportsPasswordInBrowser: 'optional',
    browserCreateSupported: true,
    summary: 'LZMA2 compression with optional AES-256 password & header encryption',
  },
  {
    id: 'zip',
    label: 'ZIP (.zip)',
    shortLabel: '.zip',
    extension: '.zip',
    supportsPasswordInBrowser: 'optional',
    browserCreateSupported: true,
    summary: 'Universal ZIP with optional AES-256 or ZipCrypto password protection',
  },
  {
    id: 'tar.gz',
    label: 'Gzip (.tar.gz / .gz)',
    shortLabel: '.gz / .tgz',
    extension: '.tar.gz',
    supportsPasswordInBrowser: 'none',
    browserCreateSupported: true,
    summary: 'Single-file .gz or multi-file .tar.gz GNU Gzip archive (no password)',
  },
  {
    id: 'tar.bz2',
    label: 'Bzip2 (.tar.bz2 / .bz2)',
    shortLabel: '.bz2 / .tbz2',
    extension: '.tar.bz2',
    supportsPasswordInBrowser: 'none',
    browserCreateSupported: true,
    summary: 'Burrows-Wheeler .bz2 or .tar.bz2 archive (no password)',
  },
  {
    id: 'tar.xz',
    label: 'XZ / LZMA2 (.tar.xz / .xz)',
    shortLabel: '.xz / .txz',
    extension: '.tar.xz',
    supportsPasswordInBrowser: 'none',
    browserCreateSupported: true,
    summary: 'High-ratio .xz or .tar.xz LZMA2 archive (no password)',
  },
  {
    id: 'rar',
    label: 'RAR (.rar)',
    shortLabel: '.rar',
    extension: '.rar',
    supportsPasswordInBrowser: 'linux-only',
    browserCreateSupported: false,
    summary: 'Extract .rar in-browser (with/without password); create .rar via Linux app',
  },
];

let cachedSevenZipWasm: ArrayBuffer | null = null;
let cachedUnrarWasm: ArrayBuffer | null = null;

async function getSevenZipWasmBinary(): Promise<ArrayBuffer> {
  if (!cachedSevenZipWasm) {
    const res = await fetch(sevenZipWasmUrl);
    if (!res.ok) {
      throw new Error(`Failed to load 7zz.wasm (${res.status})`);
    }
    cachedSevenZipWasm = await res.arrayBuffer();
  }
  return cachedSevenZipWasm.slice(0);
}

async function getUnrarWasmBinary(): Promise<ArrayBuffer> {
  if (!cachedUnrarWasm) {
    const res = await fetch(unrarWasmUrl);
    if (!res.ok) {
      throw new Error(`Failed to load unrar.wasm (${res.status})`);
    }
    cachedUnrarWasm = await res.arrayBuffer();
  }
  return cachedUnrarWasm.slice(0);
}

function toArrayBufferUint8(data: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy;
}

function toExactArrayBuffer(data: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy.buffer;
}

async function createSevenZipInstance(logs: string[]) {
  const wasmBinary = await getSevenZipWasmBinary();
  return SevenZip({
    wasmBinary,
    locateFile: (file: string) => (file.endsWith('.wasm') ? sevenZipWasmUrl : file),
    print: (line: string) => logs.push(line),
    printErr: (line: string) => logs.push(line),
  });
}

function ensureSevenZipDir(fs: Awaited<ReturnType<typeof SevenZip>>['FS'], dirPath: string) {
  const parts = dirPath.split('/').filter(Boolean);
  let current = '';
  for (const part of parts) {
    current += `/${part}`;
    try {
      fs.mkdir(current);
    } catch {
      // Directory already exists
    }
  }
}

function walkSevenZipDir(
  fs: Awaited<ReturnType<typeof SevenZip>>['FS'],
  rootDir: string,
  prefix = ''
): Array<{ path: string; data: Uint8Array<ArrayBuffer> }> {
  const results: Array<{ path: string; data: Uint8Array<ArrayBuffer> }> = [];
  const entries = fs.readdir(rootDir);
  for (const name of entries) {
    if (name === '.' || name === '..') continue;
    const fullPath = `${rootDir}/${name}`;
    const relPath = prefix ? `${prefix}/${name}` : name;
    const stat = fs.stat(fullPath);
    if (fs.isDir(stat.mode)) {
      results.push(...walkSevenZipDir(fs, fullPath, relPath));
    } else if (fs.isFile(stat.mode)) {
      const raw = fs.readFile(fullPath);
      results.push({ path: relPath, data: toArrayBufferUint8(raw) });
    }
  }
  return results;
}

function sanitizeArchiveRelPath(relPath: string): string {
  const normalized = relPath
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .split('/')
    .filter((seg) => seg && seg !== '.' && seg !== '..')
    .join('/');
  return normalized || 'file';
}

export interface ArchiveInspectionInfo {
  format: ArchiveFormatId;
  formatLabel: string;
  magicLabel: string;
  totalBytes: number;
  encryptedHint: 'yes' | 'no' | 'possible';
  compressionSummary: string;
  archiveSha256: string;
  // Extra KLOCK001 fields when format === 'klock'
  klockIterations?: number;
  klockCompressionAlgorithm?: CompressionAlgorithm;
  klockSaltHex?: string;
  klockIvHex?: string;
}

export function detectArchiveFormat(
  bytes: Uint8Array,
  filename: string
): ArchiveFormatId {
  const lower = filename.toLowerCase();

  // Check magic bytes first
  if (
    bytes.byteLength >= 8 &&
    bytes[0] === 0x4b &&
    bytes[1] === 0x4c &&
    bytes[2] === 0x4f &&
    bytes[3] === 0x43 &&
    bytes[4] === 0x4b &&
    bytes[5] === 0x30 &&
    bytes[6] === 0x30 &&
    bytes[7] === 0x31
  ) {
    return 'klock';
  }
  // RAR4: Rar!\x1a\x07\x00 | RAR5: Rar!\x1a\x07\x01\x00
  if (
    bytes.byteLength >= 7 &&
    bytes[0] === 0x52 &&
    bytes[1] === 0x61 &&
    bytes[2] === 0x72 &&
    bytes[3] === 0x21 &&
    bytes[4] === 0x1a &&
    bytes[5] === 0x07
  ) {
    return 'rar';
  }
  // 7z: 37 7A BC AF 27 1C
  if (
    bytes.byteLength >= 6 &&
    bytes[0] === 0x37 &&
    bytes[1] === 0x7a &&
    bytes[2] === 0xbc &&
    bytes[3] === 0xaf &&
    bytes[4] === 0x27 &&
    bytes[5] === 0x1c
  ) {
    return '7z';
  }
  // ZIP: PK\x03\x04 or empty PK\x05\x06
  if (
    bytes.byteLength >= 4 &&
    bytes[0] === 0x50 &&
    bytes[1] === 0x4b &&
    ((bytes[2] === 0x03 && bytes[3] === 0x04) ||
      (bytes[2] === 0x05 && bytes[3] === 0x06))
  ) {
    return 'zip';
  }
  // Gzip: 1F 8B
  if (bytes.byteLength >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) return 'tar.gz';
    return 'gz';
  }
  // Bzip2: BZh
  if (
    bytes.byteLength >= 3 &&
    bytes[0] === 0x42 &&
    bytes[1] === 0x5a &&
    bytes[2] === 0x68
  ) {
    if (lower.endsWith('.tar.bz2') || lower.endsWith('.tbz2') || lower.endsWith('.tbz')) {
      return 'tar.bz2';
    }
    return 'bz2';
  }
  // XZ: FD 37 7A 58 5A 00
  if (
    bytes.byteLength >= 6 &&
    bytes[0] === 0xfd &&
    bytes[1] === 0x37 &&
    bytes[2] === 0x7a &&
    bytes[3] === 0x58 &&
    bytes[4] === 0x5a &&
    bytes[5] === 0x00
  ) {
    if (lower.endsWith('.tar.xz') || lower.endsWith('.txz')) return 'tar.xz';
    return 'xz';
  }
  // TAR: "ustar" at offset 257
  if (
    bytes.byteLength >= 263 &&
    bytes[257] === 0x75 &&
    bytes[258] === 0x73 &&
    bytes[259] === 0x74 &&
    bytes[260] === 0x61 &&
    bytes[261] === 0x72
  ) {
    return 'tar';
  }

  // Filename fallback
  if (lower.endsWith('.klock')) return 'klock';
  if (lower.endsWith('.rar')) return 'rar';
  if (lower.endsWith('.7z')) return '7z';
  if (lower.endsWith('.zip')) return 'zip';
  if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) return 'tar.gz';
  if (lower.endsWith('.gz') || lower.endsWith('.gzip')) return 'gz';
  if (lower.endsWith('.tar.bz2') || lower.endsWith('.tbz2') || lower.endsWith('.tbz')) {
    return 'tar.bz2';
  }
  if (lower.endsWith('.bz2')) return 'bz2';
  if (lower.endsWith('.tar.xz') || lower.endsWith('.txz')) return 'tar.xz';
  if (lower.endsWith('.xz')) return 'xz';
  if (lower.endsWith('.tar')) return 'tar';
  return 'other';
}

export function getFormatDisplayLabel(format: ArchiveFormatId): string {
  switch (format) {
    case 'klock':
      return 'KryptLock (.klock)';
    case 'rar':
      return 'RAR Archive (.rar)';
    case '7z':
      return '7-Zip (.7z)';
    case 'zip':
      return 'ZIP (.zip)';
    case 'tar.gz':
      return 'Gzip Tarball (.tar.gz)';
    case 'gz':
      return 'Gzip Stream (.gz)';
    case 'tar.bz2':
      return 'Bzip2 Tarball (.tar.bz2)';
    case 'bz2':
      return 'Bzip2 Stream (.bz2)';
    case 'tar.xz':
      return 'XZ Tarball (.tar.xz)';
    case 'xz':
      return 'XZ / LZMA2 (.xz)';
    case 'tar':
      return 'POSIX Tar (.tar)';
    case 'other':
      return 'Archive (7z-wasm auto)';
  }
}

export async function inspectAnyArchive(
  bytes: Uint8Array<ArrayBuffer>,
  filename: string
): Promise<ArchiveInspectionInfo> {
  const format = detectArchiveFormat(bytes, filename);
  const archiveSha256 = await sha256Hex(bytes);

  if (format === 'klock') {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const flag = bytes.byteLength > 8 ? bytes[8] : 0x01;
    const algoMap: Record<number, CompressionAlgorithm> = {
      0x01: 'deflate',
      0x02: 'store',
      0x03: 'gzip',
      0x04: 'bzip2',
      0x05: 'lzma',
    };
    const algo = algoMap[flag] ?? 'deflate';
    const iterations = bytes.byteLength >= 13 ? view.getUint32(9, false) : 600000;
    const saltHex = bytes.byteLength >= 29 ? Array.from(bytes.subarray(13, 29)).map((b) => b.toString(16).padStart(2, '0')).join('') : '';
    const ivHex = bytes.byteLength >= 41 ? Array.from(bytes.subarray(29, 41)).map((b) => b.toString(16).padStart(2, '0')).join('') : '';
    return {
      format,
      formatLabel: 'KryptLock (.klock)',
      magicLabel: 'KLOCK001',
      totalBytes: bytes.byteLength,
      encryptedHint: 'yes',
      compressionSummary: `AES-256-GCM + ${algo}`,
      archiveSha256,
      klockIterations: iterations,
      klockCompressionAlgorithm: algo,
      klockSaltHex: saltHex,
      klockIvHex: ivHex,
    };
  }

  if (format === 'rar') {
    const isRar5 = bytes.byteLength >= 7 && bytes[6] === 0x01;
    let encryptedHint: 'yes' | 'no' | 'possible' = 'possible';
    try {
      const wasmBinary = await getUnrarWasmBinary();
      const extractor = await createExtractorFromData({
        wasmBinary,
        data: toExactArrayBuffer(bytes),
      });
      const list = extractor.getFileList();
      if (list.arcHeader.flags.headerEncrypted) {
        encryptedHint = 'yes';
      } else {
        const headers = Array.from(list.fileHeaders);
        encryptedHint = headers.some((h) => h.flags.encrypted) ? 'yes' : 'no';
      }
    } catch (err) {
      if (
        err instanceof UnrarError &&
        (err.reason === 'ERAR_MISSING_PASSWORD' || err.reason === 'ERAR_BAD_PASSWORD')
      ) {
        encryptedHint = 'yes';
      }
    }
    return {
      format,
      formatLabel: isRar5 ? 'RAR5 Archive (.rar)' : 'RAR4 Archive (.rar)',
      magicLabel: isRar5 ? 'Rar! (v5)' : 'Rar! (v4)',
      totalBytes: bytes.byteLength,
      encryptedHint,
      compressionSummary: 'Official UnRAR WASM',
      archiveSha256,
    };
  }

  if (format === 'zip') {
    let encryptedHint: 'yes' | 'no' | 'possible' = 'possible';
    try {
      const reader = new ZipReader(new Uint8ArrayReader(bytes));
      const entries = await reader.getEntries();
      encryptedHint = entries.some((e) => e.encrypted) ? 'yes' : 'no';
      await reader.close();
    } catch {
      encryptedHint = 'possible';
    }
    return {
      format,
      formatLabel: 'ZIP Archive (.zip)',
      magicLabel: 'PK\\x03\\x04',
      totalBytes: bytes.byteLength,
      encryptedHint,
      compressionSummary: 'Deflate / AES-256 / ZipCrypto',
      archiveSha256,
    };
  }

  if (format === '7z') {
    return {
      format,
      formatLabel: '7-Zip Archive (.7z)',
      magicLabel: '7z\\xBC\\xAF\\x27\\x1C',
      totalBytes: bytes.byteLength,
      encryptedHint: 'possible',
      compressionSummary: 'LZMA2 / AES-256 (7z-wasm)',
      archiveSha256,
    };
  }

  return {
    format,
    formatLabel: getFormatDisplayLabel(format),
    magicLabel: format.toUpperCase(),
    totalBytes: bytes.byteLength,
    encryptedHint: 'no',
    compressionSummary:
      format === 'gz' || format === 'tar.gz'
        ? 'GNU Gzip (RFC 1952)'
        : format === 'bz2' || format === 'tar.bz2'
          ? 'Bzip2 (BWT)'
          : format === 'xz' || format === 'tar.xz'
            ? 'XZ / LZMA2'
            : '7-Zip Multi-Format WASM',
    archiveSha256,
  };
}

export interface CreateMultiArchiveOptions {
  format: PackFormatId;
  archiveBaseName: string;
  files: StagedFile[];
  passphrase: string;
  keyfileBytes?: Uint8Array<ArrayBuffer> | null;
  klockCompressionAlgorithm: CompressionAlgorithm;
  compressionLevel: 1 | 3 | 6 | 9;
  iterations: number;
  encryptHeaders: boolean;
  zipEncryptionMethod: 'aes256' | 'zipcrypto';
  onProgress?: (progress: BatchProgress) => void;
}

export interface CreatedMultiArchiveResult {
  format: PackFormatId;
  filename: string;
  archiveBytes: Uint8Array<ArrayBuffer>;
  archiveSha256: string;
  uncompressedTotal: number;
  finalArchiveSize: number;
  encrypted: boolean;
  entryCount: number;
  compressionSummary: string;
  saltHex?: string;
}

async function readStagedFileBuffers(
  files: StagedFile[],
  onProgress?: (progress: BatchProgress) => void
): Promise<Array<{ path: string; data: Uint8Array<ArrayBuffer> }>> {
  const out: Array<{ path: string; data: Uint8Array<ArrayBuffer> }> = [];
  for (let i = 0; i < files.length; i++) {
    const item = files[i];
    onProgress?.({
      stage: 'reading',
      label: `Reading ${item.relativePath}`,
      current: i + 1,
      total: files.length,
      percent: Math.round(((i + 1) / files.length) * 35),
    });
    const ab = await item.file.arrayBuffer();
    out.push({
      path: sanitizeArchiveRelPath(item.relativePath),
      data: new Uint8Array(ab),
    });
  }
  return out;
}

export async function createMultiFormatArchive(
  options: CreateMultiArchiveOptions
): Promise<CreatedMultiArchiveResult> {
  const {
    format,
    archiveBaseName,
    files,
    passphrase,
    keyfileBytes,
    klockCompressionAlgorithm,
    compressionLevel,
    iterations,
    encryptHeaders,
    zipEncryptionMethod,
    onProgress,
  } = options;

  if (files.length === 0) {
    throw new Error('Add at least one file or directory before creating an archive.');
  }

  const cleanBase =
    (archiveBaseName.trim() || 'archive').replace(
      /\.(klock|7z|zip|rar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|gz|bz2|xz)$/i,
      ''
    ) || 'archive';

  if (format === 'rar') {
    throw new Error(
      'RAR creation uses the proprietary RAR encoder and runs via the Native Linux CLI/GUI (`kryptlock pack out.rar ...` with `rar` installed). Use `.7z` or `.zip` here, or switch to the Native Linux App tab.'
    );
  }

  if (format === 'klock') {
    const res = await encryptKlockArchive({
      files,
      passphrase,
      keyfileBytes,
      compressionAlgorithm: klockCompressionAlgorithm,
      compressionLevel,
      iterations,
      onProgress,
    });
    return {
      format: 'klock',
      filename: `${cleanBase}.klock`,
      archiveBytes: res.archiveBytes,
      archiveSha256: res.archiveSha256,
      uncompressedTotal: res.uncompressedTotal,
      finalArchiveSize: res.finalArchiveSize,
      encrypted: true,
      entryCount: res.entryCount,
      compressionSummary: `AES-256-GCM (${klockCompressionAlgorithm})`,
      saltHex: res.saltHex,
    };
  }

  const staged = await readStagedFileBuffers(files, onProgress);
  const uncompressedTotal = staged.reduce((acc, item) => acc + item.data.byteLength, 0);

  if (format === 'zip') {
    onProgress?.({
      stage: 'compressing',
      label: passphrase
        ? `Compressing & encrypting ${staged.length} file(s) into .zip...`
        : `Compressing ${staged.length} file(s) into .zip...`,
      current: staged.length,
      total: staged.length,
      percent: 65,
    });

    const writer = new ZipWriter(new Uint8ArrayWriter(), {
      ...(passphrase
        ? {
            password: passphrase,
            zipCrypto: zipEncryptionMethod === 'zipcrypto',
            encryptionStrength: 3,
          }
        : {}),
      level: compressionLevel,
    });

    for (const entry of staged) {
      await writer.add(entry.path, new Uint8ArrayReader(entry.data));
    }
    const zipRaw = await writer.close();
    const archiveBytes = toArrayBufferUint8(zipRaw);
    const archiveSha256 = await sha256Hex(archiveBytes);
    return {
      format: 'zip',
      filename: `${cleanBase}.zip`,
      archiveBytes,
      archiveSha256,
      uncompressedTotal,
      finalArchiveSize: archiveBytes.byteLength,
      encrypted: Boolean(passphrase),
      entryCount: staged.length,
      compressionSummary: passphrase
        ? zipEncryptionMethod === 'zipcrypto'
          ? 'ZIP (ZipCrypto password)'
          : 'ZIP (AES-256 password)'
        : 'ZIP (Deflate, unencrypted)',
    };
  }

  if (format === '7z') {
    onProgress?.({
      stage: 'compressing',
      label: passphrase
        ? `Packing & encrypting ${staged.length} file(s) with 7-Zip WASM...`
        : `Packing ${staged.length} file(s) with 7-Zip WASM...`,
      current: staged.length,
      total: staged.length,
      percent: 65,
    });

    const logs: string[] = [];
    const sz = await createSevenZipInstance(logs);
    sz.FS.mkdir('/work');
    sz.FS.chdir('/work');
    const topItems = new Set<string>();
    for (const entry of staged) {
      const full = `/work/${entry.path}`;
      const slash = full.lastIndexOf('/');
      if (slash > '/work'.length) {
        ensureSevenZipDir(sz.FS, full.slice(0, slash));
      }
      sz.FS.writeFile(full, entry.data);
      topItems.add(entry.path.split('/')[0]);
    }

    const args = ['a', '-t7z', `-mx=${compressionLevel}`];
    if (passphrase) {
      args.push(`-p${passphrase}`);
      if (encryptHeaders) {
        args.push('-mhe=on');
      }
    }
    args.push('/out.7z', ...Array.from(topItems));

    sz.callMain(args);
    let archiveRaw: Uint8Array;
    try {
      archiveRaw = sz.FS.readFile('/out.7z');
    } catch {
      throw new Error(`7-Zip failed to create archive: ${logs.slice(-4).join(' | ')}`);
    }
    const archiveBytes = toArrayBufferUint8(archiveRaw);
    const archiveSha256 = await sha256Hex(archiveBytes);

    return {
      format: '7z',
      filename: `${cleanBase}.7z`,
      archiveBytes,
      archiveSha256,
      uncompressedTotal,
      finalArchiveSize: archiveBytes.byteLength,
      encrypted: Boolean(passphrase),
      entryCount: staged.length,
      compressionSummary: passphrase
        ? encryptHeaders
          ? '7-Zip (AES-256 + Encrypted Headers)'
          : '7-Zip (AES-256 Password)'
        : '7-Zip (LZMA2, unencrypted)',
    };
  }

  // tar.gz / gz, tar.bz2 / bz2, tar.xz / xz
  if (passphrase) {
    throw new Error(
      `Standard ${format} archives do not support native passwords. Clear the password for a plain ${format} archive, or choose .klock, .7z, or .zip for password encryption.`
    );
  }

  const singleFile = staged.length === 1 && !staged[0].path.includes('/');

  if (format === 'tar.gz') {
    onProgress?.({
      stage: 'compressing',
      label: singleFile ? 'Compressing file with Gzip...' : 'Building .tar.gz archive...',
      current: staged.length,
      total: staged.length,
      percent: 70,
    });

    if (singleFile) {
      const gzBytes = toArrayBufferUint8(
        gzipSync(staged[0].data, {
          level: compressionLevel,
          filename: staged[0].path,
        })
      );
      const archiveSha256 = await sha256Hex(gzBytes);
      return {
        format: 'tar.gz',
        filename: `${staged[0].path}.gz`,
        archiveBytes: gzBytes,
        archiveSha256,
        uncompressedTotal,
        finalArchiveSize: gzBytes.byteLength,
        encrypted: false,
        entryCount: 1,
        compressionSummary: 'Gzip (.gz, unencrypted)',
      };
    }

    const logs: string[] = [];
    const sz = await createSevenZipInstance(logs);
    sz.FS.mkdir('/work');
    sz.FS.chdir('/work');
    const topItems = new Set<string>();
    for (const entry of staged) {
      const full = `/work/${entry.path}`;
      const slash = full.lastIndexOf('/');
      if (slash > '/work'.length) {
        ensureSevenZipDir(sz.FS, full.slice(0, slash));
      }
      sz.FS.writeFile(full, entry.data);
      topItems.add(entry.path.split('/')[0]);
    }
    sz.callMain(['a', '-ttar', '/out.tar', ...Array.from(topItems)]);
    const tarBytes = sz.FS.readFile('/out.tar');
    const tgzBytes = toArrayBufferUint8(
      gzipSync(tarBytes, { level: compressionLevel, filename: `${cleanBase}.tar` })
    );
    const archiveSha256 = await sha256Hex(tgzBytes);
    return {
      format: 'tar.gz',
      filename: `${cleanBase}.tar.gz`,
      archiveBytes: tgzBytes,
      archiveSha256,
      uncompressedTotal,
      finalArchiveSize: tgzBytes.byteLength,
      encrypted: false,
      entryCount: staged.length,
      compressionSummary: 'Gzip Tarball (.tar.gz)',
    };
  }

  // tar.bz2 / bz2 OR tar.xz / xz via 7z-wasm
  const codecFlag = format === 'tar.bz2' ? 'bzip2' : 'xz';
  const ext = format === 'tar.bz2' ? 'bz2' : 'xz';

  onProgress?.({
    stage: 'compressing',
    label: singleFile
      ? `Compressing file with ${codecFlag.toUpperCase()}...`
      : `Building .tar.${ext} archive...`,
    current: staged.length,
    total: staged.length,
    percent: 70,
  });

  if (singleFile) {
    const logs: string[] = [];
    const sz = await createSevenZipInstance(logs);
    sz.FS.writeFile(`/${staged[0].path}`, staged[0].data);
    sz.callMain(['a', `-t${codecFlag}`, `-mx=${compressionLevel}`, `/out.${ext}`, `/${staged[0].path}`]);
    const outBytes = toArrayBufferUint8(sz.FS.readFile(`/out.${ext}`));
    const archiveSha256 = await sha256Hex(outBytes);
    return {
      format,
      filename: `${staged[0].path}.${ext}`,
      archiveBytes: outBytes,
      archiveSha256,
      uncompressedTotal,
      finalArchiveSize: outBytes.byteLength,
      encrypted: false,
      entryCount: 1,
      compressionSummary: `${codecFlag.toUpperCase()} (.${ext})`,
    };
  }

  const logs1: string[] = [];
  const szTar = await createSevenZipInstance(logs1);
  szTar.FS.mkdir('/work');
  szTar.FS.chdir('/work');
  const topItems = new Set<string>();
  for (const entry of staged) {
    const full = `/work/${entry.path}`;
    const slash = full.lastIndexOf('/');
    if (slash > '/work'.length) {
      ensureSevenZipDir(szTar.FS, full.slice(0, slash));
    }
    szTar.FS.writeFile(full, entry.data);
    topItems.add(entry.path.split('/')[0]);
  }
  szTar.callMain(['a', '-ttar', '/out.tar', ...Array.from(topItems)]);
  const tarRaw = szTar.FS.readFile('/out.tar');

  const logs2: string[] = [];
  const szComp = await createSevenZipInstance(logs2);
  szComp.FS.writeFile(`/${cleanBase}.tar`, tarRaw);
  szComp.callMain(['a', `-t${codecFlag}`, `-mx=${compressionLevel}`, `/out.tar.${ext}`, `/${cleanBase}.tar`]);
  const finalBytes = toArrayBufferUint8(szComp.FS.readFile(`/out.tar.${ext}`));
  const archiveSha256 = await sha256Hex(finalBytes);

  return {
    format,
    filename: `${cleanBase}.tar.${ext}`,
    archiveBytes: finalBytes,
    archiveSha256,
    uncompressedTotal,
    finalArchiveSize: finalBytes.byteLength,
    encrypted: false,
    entryCount: staged.length,
    compressionSummary: `${codecFlag.toUpperCase()} Tarball (.tar.${ext})`,
  };
}

export interface UnifiedExtractResult {
  format: ArchiveFormatId;
  formatLabel: string;
  entries: DecryptedEntry[];
  compressedSize: number;
  uncompressedSize: number;
  archiveSha256: string;
  expectedArchiveSha256?: string;
  archiveChecksumMatch: boolean | null;
  containerIntegrityVerified: boolean;
  allFilesVerified: boolean;
  failedIntegrityPaths: string[];
  usedPassword: boolean;
}

async function buildEntriesWithSha256(
  rawEntries: Array<{ path: string; data: Uint8Array<ArrayBuffer>; mtime?: number }>
): Promise<DecryptedEntry[]> {
  const out: DecryptedEntry[] = [];
  for (const item of rawEntries) {
    const digest = await sha256Hex(item.data);
    out.push({
      path: item.path,
      size: item.data.byteLength,
      mtime: item.mtime ?? Date.now(),
      expectedSha256: digest,
      actualSha256: digest,
      integrityVerified: true,
      data: item.data,
    });
  }
  return out;
}

async function extractTarWithSevenZip(
  tarBytes: Uint8Array
): Promise<Array<{ path: string; data: Uint8Array<ArrayBuffer> }>> {
  const logs: string[] = [];
  const sz = await createSevenZipInstance(logs);
  sz.FS.writeFile('/inner.tar', tarBytes);
  sz.FS.mkdir('/tarout');
  sz.callMain(['x', '-y', '-o/tarout', '/inner.tar']);
  return walkSevenZipDir(sz.FS, '/tarout');
}

export async function extractAnyArchive(options: {
  archiveBytes: Uint8Array<ArrayBuffer>;
  filename: string;
  passphrase: string;
  keyfileBytes?: Uint8Array<ArrayBuffer> | null;
  expectedArchiveChecksum?: string;
}): Promise<UnifiedExtractResult> {
  const { archiveBytes, filename, passphrase, keyfileBytes, expectedArchiveChecksum } =
    options;

  const format = detectArchiveFormat(archiveBytes, filename);
  const archiveSha256 = await sha256Hex(archiveBytes);
  const normalizedExpected = expectedArchiveChecksum
    ? normalizeExpectedChecksum(expectedArchiveChecksum)
    : null;
  const archiveChecksumMatch =
    normalizedExpected !== null ? normalizedExpected === archiveSha256 : null;

  if (archiveChecksumMatch === false) {
    throw new Error(
      `Archive integrity check failed! Expected SHA-256 ${normalizedExpected}, but computed ${archiveSha256}.`
    );
  }

  if (format === 'klock') {
    const res = await decryptKlockArchive(
      archiveBytes,
      passphrase,
      keyfileBytes,
      expectedArchiveChecksum
    );
    return {
      format: 'klock',
      formatLabel: 'KryptLock (.klock)',
      entries: res.entries,
      compressedSize: res.compressedSize,
      uncompressedSize: res.uncompressedSize,
      archiveSha256: res.archiveSha256,
      expectedArchiveSha256: res.expectedArchiveSha256,
      archiveChecksumMatch: res.archiveChecksumMatch,
      containerIntegrityVerified: res.containerIntegrityVerified,
      allFilesVerified: res.allFilesVerified,
      failedIntegrityPaths: res.failedIntegrityPaths,
      usedPassword: true,
    };
  }

  if (format === 'rar') {
    const wasmBinary = await getUnrarWasmBinary();
    let usedPassword = false;
    try {
      const extractor = await createExtractorFromData({
        wasmBinary,
        data: toExactArrayBuffer(archiveBytes),
        password: passphrase || undefined,
      });
      const extracted = extractor.extract();
      const rawEntries: Array<{ path: string; data: Uint8Array<ArrayBuffer>; mtime?: number }> =
        [];
      for (const item of extracted.files) {
        if (item.fileHeader.flags.encrypted) {
          usedPassword = true;
        }
        if (!item.fileHeader.flags.directory && item.extraction) {
          rawEntries.push({
            path: sanitizeArchiveRelPath(item.fileHeader.name),
            data: toArrayBufferUint8(item.extraction),
            mtime: Date.parse(item.fileHeader.time) || Date.now(),
          });
        }
      }
      const entries = await buildEntriesWithSha256(rawEntries);
      const uncompressedSize = entries.reduce((acc, e) => acc + e.size, 0);
      return {
        format: 'rar',
        formatLabel: 'RAR Archive (.rar)',
        entries,
        compressedSize: archiveBytes.byteLength,
        uncompressedSize,
        archiveSha256,
        expectedArchiveSha256: normalizedExpected ?? undefined,
        archiveChecksumMatch,
        containerIntegrityVerified: true,
        allFilesVerified: true,
        failedIntegrityPaths: [],
        usedPassword: usedPassword || Boolean(passphrase),
      };
    } catch (err) {
      if (err instanceof UnrarError) {
        if (err.reason === 'ERAR_MISSING_PASSWORD') {
          throw new Error(
            'This RAR archive is password-protected. Enter the password and click Unlock / Extract.'
          );
        }
        if (err.reason === 'ERAR_BAD_PASSWORD') {
          throw new Error(
            'Incorrect RAR password (or corrupted encrypted archive).'
          );
        }
        throw new Error(`RAR extraction failed (${err.reason}): ${err.message}`);
      }
      throw err;
    }
  }

  if (format === 'zip') {
    let usedPassword = false;
    try {
      const reader = new ZipReader(new Uint8ArrayReader(archiveBytes), {
        password: passphrase || undefined,
      });
      const zipEntries = await reader.getEntries();
      const rawEntries: Array<{ path: string; data: Uint8Array<ArrayBuffer>; mtime?: number }> =
        [];
      for (const entry of zipEntries) {
        if (entry.directory || !('getData' in entry) || typeof entry.getData !== 'function') {
          continue;
        }
        if (entry.encrypted) {
          usedPassword = true;
          if (!passphrase) {
            await reader.close();
            throw new Error(
              'This ZIP archive is password-protected. Enter the password and try again.'
            );
          }
        }
        const raw = await entry.getData(new Uint8ArrayWriter(), {
          password: passphrase || undefined,
        });
        rawEntries.push({
          path: sanitizeArchiveRelPath(entry.filename),
          data: toArrayBufferUint8(raw),
          mtime: entry.lastModDate ? entry.lastModDate.getTime() : Date.now(),
        });
      }
      await reader.close();
      const entries = await buildEntriesWithSha256(rawEntries);
      const uncompressedSize = entries.reduce((acc, e) => acc + e.size, 0);
      return {
        format: 'zip',
        formatLabel: 'ZIP Archive (.zip)',
        entries,
        compressedSize: archiveBytes.byteLength,
        uncompressedSize,
        archiveSha256,
        expectedArchiveSha256: normalizedExpected ?? undefined,
        archiveChecksumMatch,
        containerIntegrityVerified: true,
        allFilesVerified: true,
        failedIntegrityPaths: [],
        usedPassword,
      };
    } catch (zipErr) {
      const msg = zipErr instanceof Error ? zipErr.message : String(zipErr);
      if (/encrypted|password/i.test(msg)) {
        throw new Error(
          passphrase
            ? 'Incorrect ZIP password or unsupported encryption header.'
            : 'This ZIP archive is password-protected. Enter the password and try again.'
        );
      }
      // Fallback to 7z-wasm for non-standard ZIP codecs (Deflate64, LZMA, Bzip2 in ZIP)
    }
  }

  if (format === 'gz') {
    const decompressed = toArrayBufferUint8(gunzipSync(archiveBytes));
    const singleName = filename.replace(/\.(gz|gzip)$/i, '') || 'decompressed.bin';
    const entries = await buildEntriesWithSha256([
      { path: sanitizeArchiveRelPath(singleName), data: decompressed },
    ]);
    return {
      format: 'gz',
      formatLabel: 'Gzip (.gz)',
      entries,
      compressedSize: archiveBytes.byteLength,
      uncompressedSize: decompressed.byteLength,
      archiveSha256,
      expectedArchiveSha256: normalizedExpected ?? undefined,
      archiveChecksumMatch,
      containerIntegrityVerified: true,
      allFilesVerified: true,
      failedIntegrityPaths: [],
      usedPassword: false,
    };
  }

  if (format === 'bz2') {
    const decompressed = toArrayBufferUint8(getBzip2Api().decompressFile(archiveBytes));
    const singleName = filename.replace(/\.bz2$/i, '') || 'decompressed.bin';
    const entries = await buildEntriesWithSha256([
      { path: sanitizeArchiveRelPath(singleName), data: decompressed },
    ]);
    return {
      format: 'bz2',
      formatLabel: 'Bzip2 (.bz2)',
      entries,
      compressedSize: archiveBytes.byteLength,
      uncompressedSize: decompressed.byteLength,
      archiveSha256,
      expectedArchiveSha256: normalizedExpected ?? undefined,
      archiveChecksumMatch,
      containerIntegrityVerified: true,
      allFilesVerified: true,
      failedIntegrityPaths: [],
      usedPassword: false,
    };
  }

  // 7z, tar.gz, tar.bz2, tar.xz, xz, tar, zip fallback, other
  const logs: string[] = [];
  const sz = await createSevenZipInstance(logs);
  const safeInputName = sanitizeArchiveRelPath(filename.split('/').pop() || 'archive.bin');
  const fsInputPath = `/${safeInputName}`;
  sz.FS.writeFile(fsInputPath, archiveBytes);
  sz.FS.mkdir('/out');

  const args = ['x', '-y', '-o/out'];
  if (passphrase) {
    args.push(`-p${passphrase}`);
  } else {
    // Prevent 7z from waiting on stdin for encrypted archives when password is blank
    args.push('-p');
  }
  args.push(fsInputPath);

  try {
    sz.callMain(args);
  } catch {
    // Some Emscripten exits throw ExitStatus
  }

  let rawEntries = walkSevenZipDir(sz.FS, '/out');
  const logText = logs.join('\n');

  if (rawEntries.length === 0) {
    if (/Wrong password|Can not open encrypted archive|Data Error in encrypted file/i.test(logText)) {
      throw new Error(
        passphrase
          ? 'Incorrect password for this encrypted archive.'
          : 'This archive is password-protected. Enter the password and try again.'
      );
    }
    throw new Error(
      `Failed to extract ${getFormatDisplayLabel(format)}. ${
        logs.slice(-3).join(' ').trim() || 'Unsupported or corrupted archive.'
      }`
    );
  }

  // If single .tar extracted from .tar.gz / .tar.bz2 / .tar.xz, unwrap the inner tar automatically
  if (
    rawEntries.length === 1 &&
    (format === 'tar.gz' ||
      format === 'tar.bz2' ||
      format === 'tar.xz' ||
      rawEntries[0].path.toLowerCase().endsWith('.tar'))
  ) {
    const innerEntries = await extractTarWithSevenZip(rawEntries[0].data);
    if (innerEntries.length > 0) {
      rawEntries = innerEntries;
    }
  }

  const entries = await buildEntriesWithSha256(rawEntries);
  const uncompressedSize = entries.reduce((acc, e) => acc + e.size, 0);

  return {
    format,
    formatLabel: getFormatDisplayLabel(format),
    entries,
    compressedSize: archiveBytes.byteLength,
    uncompressedSize,
    archiveSha256,
    expectedArchiveSha256: normalizedExpected ?? undefined,
    archiveChecksumMatch,
    containerIntegrityVerified: true,
    allFilesVerified: true,
    failedIntegrityPaths: [],
    usedPassword: Boolean(passphrase),
  };
}
