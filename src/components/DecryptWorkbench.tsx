import { useEffect, useRef, useState } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Download,
  Eye,
  EyeOff,
  FileArchive,
  KeyRound,
  Search,
  ShieldAlert,
  ShieldCheck,
  Unlock,
  X,
} from 'lucide-react';
import { zipSync } from 'fflate';
import {
  DecryptedEntry,
  formatBytes,
  normalizeExpectedChecksum,
} from '../lib/klockCrypto';
import {
  ArchiveInspectionInfo,
  UnifiedExtractResult,
  extractAnyArchive,
  inspectAnyArchive,
} from '../lib/multiArchive';
import { NewArchiveHistoryEntry } from '../lib/archiveHistory';

interface DecryptWorkbenchProps {
  incomingArchive: {
    bytes: Uint8Array<ArrayBuffer>;
    filename: string;
    expectedSha256?: string;
  } | null;
  onRecordHistory: (entry: NewArchiveHistoryEntry) => void;
}

export function DecryptWorkbench({
  incomingArchive,
  onRecordHistory,
}: DecryptWorkbenchProps) {
  const [archiveFilename, setArchiveFilename] = useState<string | null>(null);
  const [archiveBytes, setArchiveBytes] = useState<Uint8Array<ArrayBuffer> | null>(null);
  const [inspection, setInspection] = useState<ArchiveInspectionInfo | null>(null);
  const [expectedChecksumInput, setExpectedChecksumInput] = useState('');

  const [passphrase, setPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [keyfileName, setKeyfileName] = useState<string | null>(null);
  const [keyfileBytes, setKeyfileBytes] = useState<Uint8Array<ArrayBuffer> | null>(null);

  const [isDragging, setIsDragging] = useState(false);
  const [isInspecting, setIsInspecting] = useState(false);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [unlocked, setUnlocked] = useState<UnifiedExtractResult | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [previewEntry, setPreviewEntry] = useState<{
    entry: DecryptedEntry;
    textContent?: string;
    imageUrl?: string;
  } | null>(null);

  const archiveInputRef = useRef<HTMLInputElement>(null);
  const checksumInputRef = useRef<HTMLInputElement>(null);
  const keyfileInputRef = useRef<HTMLInputElement>(null);

  const loadArchiveBytes = async (
    bytes: Uint8Array<ArrayBuffer>,
    filename: string,
    expectedSha?: string
  ) => {
    setErrorMsg(null);
    setUnlocked(null);
    setPreviewEntry(null);
    setExpectedChecksumInput(expectedSha ?? '');
    setIsInspecting(true);
    try {
      const info = await inspectAnyArchive(bytes, filename);
      setArchiveBytes(bytes);
      setArchiveFilename(filename);
      setInspection(info);
    } catch (err) {
      setArchiveBytes(null);
      setArchiveFilename(filename);
      setInspection(null);
      setErrorMsg(err instanceof Error ? err.message : 'Unable to inspect archive file.');
    } finally {
      setIsInspecting(false);
    }
  };

  useEffect(() => {
    if (incomingArchive) {
      loadArchiveBytes(
        incomingArchive.bytes,
        incomingArchive.filename,
        incomingArchive.expectedSha256
      );
    }
  }, [incomingArchive]);

  useEffect(() => {
    return () => {
      if (previewEntry?.imageUrl) {
        URL.revokeObjectURL(previewEntry.imageUrl);
      }
    };
  }, [previewEntry]);

  const handleArchiveFile = async (file: File | undefined) => {
    if (!file) return;
    const ab = await file.arrayBuffer();
    await loadArchiveBytes(new Uint8Array(ab), file.name);
  };

  const handleChecksumFile = async (file: File | undefined) => {
    if (!file) return;
    const text = await file.text();
    const normalized = normalizeExpectedChecksum(text);
    setExpectedChecksumInput(normalized ?? text.trim());
    setErrorMsg(null);
  };

  const handleKeyfileSelect = async (file: File | undefined) => {
    if (!file) return;
    const ab = await file.arrayBuffer();
    setKeyfileBytes(new Uint8Array(ab));
    setKeyfileName(file.name);
  };

  const handleUnlockOrExtract = async () => {
    if (!archiveBytes || !archiveFilename) return;
    setErrorMsg(null);
    setIsUnlocking(true);
    try {
      const res = await extractAnyArchive({
        archiveBytes,
        filename: archiveFilename,
        passphrase,
        keyfileBytes,
        expectedArchiveChecksum: expectedChecksumInput || undefined,
      });
      setUnlocked(res);
      onRecordHistory({
        operation: 'decrypt',
        filename: archiveFilename,
        archiveType: res.format === 'other' ? 'archive' : `.${res.format}`,
        compressionSummary: res.formatLabel,
        encrypted: res.usedPassword,
        entryCount: res.entries.length,
        sizeBytes: res.compressedSize,
        sha256: res.archiveSha256,
        integrityStatus:
          res.format === 'klock' || res.archiveChecksumMatch === true
            ? res.allFilesVerified
              ? 'verified'
              : 'failed'
            : 'unverified',
      });
    } catch (err) {
      setUnlocked(null);
      const message =
        err instanceof Error ? err.message : 'Extraction / decryption failed.';
      setErrorMsg(message);
      if (/integrity check failed|checksum mismatch/i.test(message) && inspection) {
        onRecordHistory({
          operation: 'decrypt',
          filename: archiveFilename,
          archiveType:
            inspection.format === 'other' ? 'archive' : `.${inspection.format}`,
          compressionSummary: inspection.formatLabel,
          encrypted: inspection.encryptedHint === 'yes',
          entryCount: 0,
          sizeBytes: inspection.totalBytes,
          sha256: inspection.archiveSha256,
          integrityStatus: 'failed',
        });
      }
    } finally {
      setIsUnlocking(false);
    }
  };

  const handleDownloadSingle = (entry: DecryptedEntry) => {
    const basename = entry.path.split('/').pop() || 'file';
    const blob = new Blob([entry.data], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = basename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleExtractAllZip = () => {
    if (!unlocked) return;
    const zipEntries: Record<string, Uint8Array> = {};
    for (const entry of unlocked.entries) {
      const safePath = entry.path.replace(/^\/+/, '').replace(/\.\.\//g, '');
      zipEntries[safePath] = entry.data;
    }
    const zipped = zipSync(zipEntries, { level: 6 });
    const copy = new Uint8Array(zipped.byteLength);
    copy.set(zipped);
    const base = (archiveFilename || 'extracted').replace(
      /\.(klock|rar|7z|zip|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|gz|bz2|xz|tar)$/i,
      ''
    );
    const blob = new Blob([copy], { type: 'application/zip' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${base}-extracted.zip`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const openPreview = (entry: DecryptedEntry) => {
    const lower = entry.path.toLowerCase();
    if (/\.(png|jpe?g|webp|gif|svg)$/.test(lower)) {
      const mime = lower.endsWith('.svg')
        ? 'image/svg+xml'
        : lower.endsWith('.png')
          ? 'image/png'
          : lower.endsWith('.webp')
            ? 'image/webp'
            : 'image/jpeg';
      const url = URL.createObjectURL(new Blob([entry.data], { type: mime }));
      setPreviewEntry({ entry, imageUrl: url });
      return;
    }

    const decoded = new TextDecoder('utf-8', { fatal: false }).decode(
      entry.data.subarray(0, 128 * 1024)
    );
    setPreviewEntry({ entry, textContent: decoded });
  };

  const normalizedExpected = expectedChecksumInput
    ? normalizeExpectedChecksum(expectedChecksumInput)
    : null;
  const computedArchiveSha = inspection?.archiveSha256 ?? null;
  const preUnlockChecksumStatus: 'idle' | 'match' | 'mismatch' =
    !computedArchiveSha || !normalizedExpected
      ? 'idle'
      : normalizedExpected === computedArchiveSha
        ? 'match'
        : 'mismatch';

  const filteredEntries = unlocked
    ? unlocked.entries.filter((e) =>
        e.path.toLowerCase().includes(searchQuery.trim().toLowerCase())
      )
    : [];

  const isKlock = inspection?.format === 'klock';
  const showPasswordInput =
    inspection &&
    (inspection.format === 'klock' ||
      inspection.format === 'rar' ||
      inspection.format === '7z' ||
      inspection.format === 'zip' ||
      inspection.format === 'other');

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12 items-start">
        {/* Left: Archive Loader & Container Header Inspector */}
        <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#111722] p-6 space-y-5">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Inspect, Verify &amp; Unpack Archive
            </h2>
            <p className="mt-0.5 text-xs text-slate-400">
              Supports .klock, .rar (UnRAR), .7z, .zip, .gz/.tar.gz, .bz2, .xz, and .tar — with or without passwords
            </p>
          </div>

          <input
            ref={archiveInputRef}
            type="file"
            accept=".klock,.rar,.7z,.zip,.gz,.gzip,.tgz,.bz2,.tbz2,.xz,.txz,.tar,.cab,.iso,.lzma,application/octet-stream,application/zip,application/x-rar-compressed,application/x-7z-compressed,application/gzip"
            className="hidden"
            onChange={(e) => {
              handleArchiveFile(e.target.files?.[0]);
              e.target.value = '';
            }}
          />

          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setIsDragging(false);
              handleArchiveFile(e.dataTransfer.files?.[0]);
            }}
            className={`rounded-xl border border-dashed p-5 text-center transition-colors ${
              isDragging
                ? 'border-emerald-500 bg-emerald-500/5'
                : 'border-slate-700 bg-[#0B0F17]/60'
            }`}
          >
            <FileArchive className="mx-auto h-6 w-6 text-slate-400 mb-2" aria-hidden="true" />
            {isInspecting ? (
              <p className="text-xs text-slate-300">Inspecting archive header...</p>
            ) : archiveFilename ? (
              <p className="font-mono text-xs font-medium text-slate-100 truncate">
                {archiveFilename}
              </p>
            ) : (
              <p className="text-xs text-slate-300">
                Drop a .klock, .rar, .7z, .zip, .gz, .bz2, .xz, or .tar file here
              </p>
            )}
            <button
              type="button"
              onClick={() => archiveInputRef.current?.click()}
              className="mt-3 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors"
            >
              {archiveFilename ? 'Choose Another Archive' : 'Browse Archive File'}
            </button>
          </div>

          {inspection && (
            <div className="space-y-2.5 border-t border-slate-800/80 pt-4 text-xs">
              <div className="text-slate-300 font-semibold">
                Detected Archive Inspection
              </div>
              <div className="grid grid-cols-2 gap-y-2 font-mono">
                <span className="text-slate-400">Format</span>
                <span className="text-right text-emerald-400">
                  {inspection.formatLabel}
                </span>
                <span className="text-slate-400">Signature</span>
                <span className="text-right text-slate-200">{inspection.magicLabel}</span>
                <span className="text-slate-400">Engine / Codec</span>
                <span className="text-right text-slate-200">
                  {inspection.compressionSummary}
                </span>
                <span className="text-slate-400">Password Lock</span>
                <span className="text-right text-slate-200">
                  {inspection.encryptedHint === 'yes'
                    ? 'Password Required'
                    : inspection.encryptedHint === 'no'
                      ? 'Unencrypted'
                      : 'Optional / Auto'}
                </span>
                {inspection.klockIterations && (
                  <>
                    <span className="text-slate-400">PBKDF2 Rounds</span>
                    <span className="text-right text-slate-200">
                      {inspection.klockIterations.toLocaleString()}
                    </span>
                  </>
                )}
                <span className="text-slate-400">Archive Size</span>
                <span className="text-right text-slate-200">
                  {formatBytes(inspection.totalBytes)}
                </span>
              </div>
              <div className="rounded-lg border border-slate-800 bg-[#0B0F17] p-2.5 space-y-1">
                <div className="text-[11px] text-slate-400">
                  Computed Archive SHA-256
                </div>
                <div className="font-mono text-[11px] text-slate-200 break-all">
                  {inspection.archiveSha256}
                </div>
              </div>
            </div>
          )}

          {inspection && (
            <div className="space-y-4 border-t border-slate-800/80 pt-4">
              {/* Optional Archive Checksum Verification */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label
                    htmlFor="expected-sha"
                    className="text-xs font-medium text-slate-300"
                  >
                    Verify Expected SHA-256 (Optional)
                  </label>
                  <input
                    ref={checksumInputRef}
                    type="file"
                    accept=".sha256,.txt"
                    className="hidden"
                    onChange={(e) => {
                      handleChecksumFile(e.target.files?.[0]);
                      e.target.value = '';
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => checksumInputRef.current?.click()}
                    className="text-xs font-medium text-emerald-400 hover:text-emerald-300 transition-colors"
                  >
                    Load .sha256 file
                  </button>
                </div>

                <input
                  id="expected-sha"
                  type="text"
                  value={expectedChecksumInput}
                  onChange={(e) => {
                    setExpectedChecksumInput(e.target.value);
                    setErrorMsg(null);
                  }}
                  placeholder="Paste expected 64-char SHA-256 digest"
                  className={`w-full rounded-lg border bg-[#0B0F17] px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none transition-colors ${
                    preUnlockChecksumStatus === 'mismatch'
                      ? 'border-rose-500 focus:border-rose-400'
                      : preUnlockChecksumStatus === 'match'
                        ? 'border-emerald-500/60 focus:border-emerald-400'
                        : 'border-slate-700 focus:border-emerald-500'
                  }`}
                />

                {preUnlockChecksumStatus === 'match' && (
                  <p className="mt-1.5 inline-flex items-center gap-1.5 text-[11px] font-medium text-emerald-400">
                    <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
                    Archive SHA-256 matches expected checksum.
                  </p>
                )}
                {preUnlockChecksumStatus === 'mismatch' && (
                  <p className="mt-1.5 inline-flex items-center gap-1.5 text-[11px] font-medium text-rose-400">
                    <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
                    Checksum mismatch! Computed archive SHA-256 does not match expected digest.
                  </p>
                )}
              </div>

              {showPasswordInput && (
                <div>
                  <label
                    htmlFor="unlock-passphrase"
                    className="block text-xs font-medium text-slate-300 mb-1.5"
                  >
                    {inspection.encryptedHint === 'no'
                      ? 'Password (Optional — archive is unencrypted)'
                      : inspection.format === 'klock'
                        ? 'Password'
                        : 'Password (if encrypted)'}
                  </label>
                  <div className="flex items-center rounded-lg border border-slate-700 bg-[#0B0F17] focus-within:border-emerald-500 transition-colors">
                    <input
                      id="unlock-passphrase"
                      type={showPassphrase ? 'text' : 'password'}
                      value={passphrase}
                      onChange={(e) => setPassphrase(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') handleUnlockOrExtract();
                      }}
                      placeholder={
                        inspection.encryptedHint === 'no'
                          ? 'Leave empty (unencrypted)'
                          : 'Enter password (or leave empty if unencrypted)'
                      }
                      className="w-full bg-transparent px-3 py-2 text-sm font-mono text-slate-100 focus:outline-none"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassphrase((v) => !v)}
                      aria-label={showPassphrase ? 'Hide password' : 'Show password'}
                      className="px-3 text-slate-400 hover:text-slate-200"
                    >
                      {showPassphrase ? (
                        <EyeOff className="h-4 w-4" aria-hidden="true" />
                      ) : (
                        <Eye className="h-4 w-4" aria-hidden="true" />
                      )}
                    </button>
                  </div>
                </div>
              )}

              {isKlock && (
                <div>
                  <input
                    ref={keyfileInputRef}
                    type="file"
                    className="hidden"
                    onChange={(e) => {
                      handleKeyfileSelect(e.target.files?.[0]);
                      e.target.value = '';
                    }}
                  />
                  {keyfileName ? (
                    <div className="flex items-center justify-between rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-xs">
                      <span className="flex items-center gap-2 font-mono text-slate-200 truncate">
                        <KeyRound
                          className="h-3.5 w-3.5 text-emerald-400 shrink-0"
                          aria-hidden="true"
                        />
                        {keyfileName}
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          setKeyfileName(null);
                          setKeyfileBytes(null);
                        }}
                        className="ml-2 text-slate-400 hover:text-rose-400"
                      >
                        Remove
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => keyfileInputRef.current?.click()}
                      className="w-full rounded-lg border border-dashed border-slate-700 bg-[#0B0F17]/60 px-3 py-2 text-xs font-medium text-slate-400 hover:border-slate-500 hover:text-slate-200 transition-colors"
                    >
                      Attach Keyfile (if locked with 2FA keyfile)
                    </button>
                  )}
                </div>
              )}

              <button
                type="button"
                disabled={isUnlocking}
                onClick={handleUnlockOrExtract}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-slate-950 transition-colors hover:bg-emerald-400 disabled:opacity-50"
              >
                <Unlock className="h-4 w-4" aria-hidden="true" />
                {isUnlocking
                  ? 'Extracting & Verifying...'
                  : inspection.encryptedHint === 'no'
                    ? 'Verify Checksum & Extract Archive'
                    : 'Unlock, Verify & Extract'}
              </button>
            </div>
          )}

          {errorMsg && (
            <div
              role="alert"
              className="flex items-start gap-2.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3.5 py-3 text-xs text-rose-200"
            >
              <AlertCircle
                className="h-4 w-4 shrink-0 mt-0.5 text-rose-400"
                aria-hidden="true"
              />
              <div className="space-y-0.5">
                <p className="font-semibold text-rose-300">Extract / Integrity Alert</p>
                <p className="leading-relaxed">{errorMsg}</p>
              </div>
            </div>
          )}
        </div>

        {/* Right: Decrypted / Extracted Contents Browser */}
        <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-[#111722] overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 px-6 py-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Extracted Archive Browser
              </h2>
              <p className="mt-0.5 text-xs text-slate-400 font-mono">
                {unlocked
                  ? `${unlocked.entries.length} entries · ${formatBytes(unlocked.uncompressedSize)} · ${unlocked.formatLabel}`
                  : 'Load any .klock, .rar, .7z, .zip, .gz, .bz2, or .xz file to inspect and extract'}
              </p>
            </div>

            {unlocked && (
              <div className="flex items-center gap-3">
                <div className="relative">
                  <Search
                    className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500"
                    aria-hidden="true"
                  />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filter paths..."
                    className="w-44 rounded-lg border border-slate-700 bg-[#0B0F17] py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder:text-slate-500 focus:border-emerald-500 focus:outline-none"
                  />
                </div>
                <button
                  type="button"
                  onClick={handleExtractAllZip}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-900 hover:bg-white transition-colors whitespace-nowrap shrink-0"
                >
                  <Download className="h-3.5 w-3.5" aria-hidden="true" />
                  Extract All (.zip)
                </button>
              </div>
            )}
          </div>

          {unlocked && !unlocked.allFilesVerified && (
            <div
              role="alert"
              className="flex items-start gap-2.5 border-b border-rose-500/30 bg-rose-500/10 px-6 py-3 text-xs text-rose-200"
            >
              <AlertTriangle
                className="h-4 w-4 shrink-0 mt-0.5 text-rose-400"
                aria-hidden="true"
              />
              <div>
                <span className="font-semibold text-rose-300">
                  File Integrity Check Failed:
                </span>{' '}
                Re-calculated SHA-256 checksums do not match stored hashes for{' '}
                {unlocked.failedIntegrityPaths.join(', ') || 'container payload'}.
              </div>
            </div>
          )}

          {unlocked && unlocked.allFilesVerified && (
            <div className="flex items-center justify-between gap-4 border-b border-emerald-500/20 bg-emerald-500/5 px-6 py-2.5 text-xs text-emerald-300">
              <span className="inline-flex items-center gap-2 font-medium">
                <ShieldCheck className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
                {unlocked.format === 'klock'
                  ? `Integrity Verified: AES-256-GCM tag and all ${unlocked.entries.length} SHA-256 file checksums match.`
                  : `Extracted ${unlocked.entries.length} file(s) from ${unlocked.formatLabel} and computed SHA-256 digests.`}
              </span>
            </div>
          )}

          {!unlocked ? (
            <div className="flex min-h-[440px] flex-col items-center justify-center px-6 py-12 text-center">
              <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-slate-800 bg-slate-900">
                <Unlock className="h-5 w-5 text-slate-400" aria-hidden="true" />
              </div>
              <p className="text-sm font-medium text-slate-200">
                Ready to unpack .klock, .rar, .7z, .zip, .gz, .bz2, and .xz
              </p>
              <p className="mt-1.5 max-w-md text-xs leading-relaxed text-slate-400">
                Drop an archive on the left, optionally verify its .sha256 digest, enter a password if locked (or leave blank for unencrypted archives), and extract or preview files locally.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto min-h-[400px]">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800/80 text-slate-400">
                    <th className="px-6 py-3 font-medium">Entry Path</th>
                    <th className="px-4 py-3 font-medium text-right">Size</th>
                    <th className="px-4 py-3 font-medium">SHA-256 Status</th>
                    <th className="px-6 py-3 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredEntries.map((entry) => (
                    <tr
                      key={entry.path}
                      className="h-[44px] hover:bg-slate-800/30 transition-colors"
                    >
                      <td className="px-6 py-2.5 font-mono text-slate-200 max-w-[260px] truncate">
                        {entry.path}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-slate-400 whitespace-nowrap">
                        {formatBytes(entry.size)}
                      </td>
                      <td className="px-4 py-2.5 whitespace-nowrap">
                        {entry.integrityVerified ? (
                          <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium">
                            <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                            {unlocked.format === 'klock' ? 'SHA-256 Match' : 'SHA-256 Hashed'}
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-rose-400 font-medium">
                            <AlertCircle className="h-3.5 w-3.5" aria-hidden="true" />
                            Integrity Failed
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-2.5 text-right whitespace-nowrap space-x-3">
                        <button
                          type="button"
                          onClick={() => openPreview(entry)}
                          className="text-slate-300 hover:text-emerald-400 font-medium transition-colors"
                        >
                          Preview
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDownloadSingle(entry)}
                          className="text-emerald-400 hover:text-emerald-300 font-medium transition-colors"
                        >
                          Extract
                        </button>
                      </td>
                    </tr>
                  ))}
                  {filteredEntries.length === 0 && (
                    <tr>
                      <td colSpan={4} className="px-6 py-10 text-center text-slate-400">
                        No entries match "{searchQuery}".
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Preview Drawer */}
      {previewEntry && (
        <div className="rounded-xl border border-slate-800 bg-[#111722] overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-800 px-6 py-3.5">
            <div className="min-w-0">
              <p className="font-mono text-xs font-semibold text-slate-100 truncate">
                {previewEntry.entry.path}
              </p>
              <p className="font-mono text-[11px] text-slate-400 mt-0.5 truncate">
                Computed SHA-256: {previewEntry.entry.actualSha256}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setPreviewEntry(null)}
              aria-label="Close preview"
              className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
          <div className="p-6 max-h-[380px] overflow-auto bg-[#0B0F17]">
            {previewEntry.imageUrl ? (
              <img
                src={previewEntry.imageUrl}
                alt={previewEntry.entry.path}
                referrerPolicy="no-referrer"
                className="max-h-[320px] mx-auto rounded-lg border border-slate-800 object-contain"
              />
            ) : (
              <pre className="font-mono text-xs leading-relaxed text-slate-300 whitespace-pre-wrap break-words">
                {previewEntry.textContent}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
