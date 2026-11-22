import { useRef, useState } from 'react';
import {
  FilePlus2,
  FolderPlus,
  KeyRound,
  Lock,
  RefreshCw,
  Trash2,
  Eye,
  EyeOff,
  Download,
  ArrowRight,
  AlertCircle,
  CheckCircle2,
  FileText,
  Copy,
  Check,
  ShieldCheck,
  Mail,
  Share2,
  Search,
  FolderTree,
  FileArchive,
  Terminal,
} from 'lucide-react';
import {
  COMPRESSION_ALGORITHMS,
  CompressionAlgorithm,
} from '../lib/compressionCodecs';
import {
  BatchProgress,
  StagedFile,
  evaluatePasswordStrength,
  formatBytes,
  generateSecurePassphrase,
} from '../lib/klockCrypto';
import {
  CreatedMultiArchiveResult,
  PACK_FORMATS,
  PackFormatId,
  createMultiFormatArchive,
} from '../lib/multiArchive';
import {
  CollectedBatchFile,
  collectDroppedBatchItems,
  countUniqueDirectories,
  isHiddenOrSystemPath,
} from '../lib/batchFiles';
import { NewArchiveHistoryEntry } from '../lib/archiveHistory';

interface EncryptWorkbenchProps {
  onSendArchiveToUnlock: (
    bytes: Uint8Array<ArrayBuffer>,
    filename: string,
    sha256: string
  ) => void;
  onRecordHistory: (entry: NewArchiveHistoryEntry) => void;
}

export function EncryptWorkbench({
  onSendArchiveToUnlock,
  onRecordHistory,
}: EncryptWorkbenchProps) {
  const [stagedFiles, setStagedFiles] = useState<StagedFile[]>([]);
  const [archiveName, setArchiveName] = useState('vault-backup');
  const [outputFormat, setOutputFormat] = useState<PackFormatId>('klock');
  const [compressionAlgorithm, setCompressionAlgorithm] =
    useState<CompressionAlgorithm>('deflate');
  const [compressionLevel, setCompressionLevel] = useState<1 | 3 | 6 | 9>(6);
  const [iterations, setIterations] = useState<number>(600000);
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [encryptHeaders, setEncryptHeaders] = useState(true);
  const [zipEncryptionMethod, setZipEncryptionMethod] = useState<'aes256' | 'zipcrypto'>(
    'aes256'
  );
  const [keyfileName, setKeyfileName] = useState<string | null>(null);
  const [keyfileBytes, setKeyfileBytes] = useState<Uint8Array<ArrayBuffer> | null>(null);

  const [isDragging, setIsDragging] = useState(false);
  const [isScanningDrop, setIsScanningDrop] = useState(false);
  const [skipHiddenFiles, setSkipHiddenFiles] = useState(true);
  const [skippedHiddenCount, setSkippedHiddenCount] = useState(0);
  const [batchSearch, setBatchSearch] = useState('');
  const [batchProgress, setBatchProgress] = useState<BatchProgress | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copiedSha, setCopiedSha] = useState(false);
  const [copiedRarCmd, setCopiedRarCmd] = useState(false);
  const [recipientEmail, setRecipientEmail] = useState('');
  const [includeChecksumInEmail, setIncludeChecksumInEmail] = useState(true);
  const [emailNotice, setEmailNotice] = useState<string | null>(null);
  const [result, setResult] = useState<CreatedMultiArchiveResult | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const keyfileInputRef = useRef<HTMLInputElement>(null);

  const activeFormatMeta =
    PACK_FORMATS.find((f) => f.id === outputFormat) || PACK_FORMATS[0];

  const stageCollectedFiles = (
    incoming: CollectedBatchFile[],
    rootDirectoryName: string | null,
    skippedCount = 0
  ) => {
    if (skippedCount > 0) {
      setSkippedHiddenCount((prev) => prev + skippedCount);
    }
    if (incoming.length === 0) {
      if (skippedCount > 0) {
        setErrorMsg(
          'Dropped folder contained only hidden/system files. Uncheck the filter above to include them.'
        );
      } else {
        setErrorMsg('No files found inside the dropped directory.');
      }
      return;
    }

    if (rootDirectoryName && archiveName.trim() === 'vault-backup') {
      setArchiveName(rootDirectoryName);
    }

    setStagedFiles((prev) => {
      const existingPaths = new Set(prev.map((p) => p.relativePath));
      const additions: StagedFile[] = [];
      for (const item of incoming) {
        if (!existingPaths.has(item.relativePath)) {
          existingPaths.add(item.relativePath);
          additions.push({
            id: `${item.relativePath}-${item.file.size}-${item.file.lastModified}`,
            file: item.file,
            relativePath: item.relativePath,
            size: item.file.size,
            mtime: item.file.lastModified,
          });
        }
      }
      return [...prev, ...additions];
    });
    setResult(null);
    setErrorMsg(null);
  };

  const addFileList = (list: FileList | File[]) => {
    const incoming = Array.from(list);
    if (incoming.length === 0) return;

    const collected: CollectedBatchFile[] = [];
    let skipped = 0;
    let detectedRootDir: string | null = null;

    for (const file of incoming) {
      const relPath =
        (file as File & { webkitRelativePath?: string }).webkitRelativePath ||
        file.name;
      if (skipHiddenFiles && isHiddenOrSystemPath(relPath)) {
        skipped += 1;
        continue;
      }
      if (!detectedRootDir && relPath.includes('/')) {
        detectedRootDir = relPath.split('/')[0] || null;
      }
      collected.push({ file, relativePath: relPath });
    }

    stageCollectedFiles(collected, detectedRootDir, skipped);
  };

  const handleDropItems = async (dataTransfer: DataTransfer) => {
    setIsScanningDrop(true);
    setErrorMsg(null);
    try {
      const batch = await collectDroppedBatchItems(dataTransfer, skipHiddenFiles);
      stageCollectedFiles(
        batch.files,
        batch.rootDirectoryName,
        batch.skippedHiddenCount
      );
    } catch (err) {
      setErrorMsg(
        err instanceof Error ? err.message : 'Unable to read dropped files or folder.'
      );
    } finally {
      setIsScanningDrop(false);
    }
  };

  const handleLoadSampleFiles = () => {
    const sampleConfig = new File(
      [
        `# Sample Linux Server Configuration\n[wireguard]\ninterface = wg0\nlisten_port = 51820\nallowed_ips = 10.10.0.0/24\n`,
      ],
      'etc/wireguard/wg0.conf',
      { type: 'text/plain', lastModified: Date.now() }
    );
    const sampleNotes = new File(
      [
        `KryptLock Verification Note\n\nThis archive supports KLOCK001 (AES-256-GCM), 7-Zip (.7z), ZIP (.zip), Gzip (.tar.gz / .gz), Bzip2, XZ, and RAR extraction.\n`,
      ],
      'docs/recovery-notes.txt',
      { type: 'text/plain', lastModified: Date.now() }
    );
    const sampleJson = new File(
      [
        JSON.stringify(
          {
            service: 'backups-node-01',
            region: 'eu-central',
            formats: ['klock', '7z', 'zip', 'rar', 'tar.gz', 'tar.bz2', 'tar.xz'],
          },
          null,
          2
        ),
      ],
      'manifests/cluster.json',
      { type: 'application/json', lastModified: Date.now() }
    );

    setStagedFiles([
      {
        id: 'sample-1',
        file: sampleConfig,
        relativePath: 'etc/wireguard/wg0.conf',
        size: sampleConfig.size,
        mtime: sampleConfig.lastModified,
      },
      {
        id: 'sample-2',
        file: sampleNotes,
        relativePath: 'docs/recovery-notes.txt',
        size: sampleNotes.size,
        mtime: sampleNotes.lastModified,
      },
      {
        id: 'sample-3',
        file: sampleJson,
        relativePath: 'manifests/cluster.json',
        size: sampleJson.size,
        mtime: sampleJson.lastModified,
      },
    ]);
    setResult(null);
    setErrorMsg(null);
  };

  const handleKeyfileSelect = async (file: File | undefined) => {
    if (!file) return;
    const ab = await file.arrayBuffer();
    setKeyfileBytes(new Uint8Array(ab));
    setKeyfileName(file.name);
    setResult(null);
  };

  const handleGenerateKeyfile = () => {
    const randomKey = new Uint8Array(64);
    window.crypto.getRandomValues(randomKey);
    const generatedName = `${archiveName.trim() || 'kryptlock'}.key`;
    setKeyfileBytes(randomKey);
    setKeyfileName(generatedName);

    const blob = new Blob([randomKey], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = generatedName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const triggerDownload = (bytes: Uint8Array<ArrayBuffer>, filename: string) => {
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const downloadChecksumFile = (sha256: string, archiveFilename: string) => {
    const content = `${sha256}  ${archiveFilename}\n`;
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${archiveFilename}.sha256`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopySha = async (sha256: string) => {
    try {
      await navigator.clipboard.writeText(sha256);
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 1800);
    } catch {
      // Clipboard blocked
    }
  };

  const handleCopyRarCommand = async (cmd: string) => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopiedRarCmd(true);
      setTimeout(() => setCopiedRarCmd(false), 1800);
    } catch {
      // Clipboard blocked
    }
  };

  const handleCreateArchive = async () => {
    setErrorMsg(null);
    if (outputFormat === 'rar') {
      setErrorMsg(
        'Proprietary .rar compression runs via the Native Linux CLI/GUI (`kryptlock pack out.rar ...`). Select .7z, .zip, or .klock to compress directly in-browser, or use the Unlock/Extract tab to unrar any .rar file.'
      );
      return;
    }
    if (stagedFiles.length === 0) {
      setErrorMsg('Add at least one file or folder to the archive.');
      return;
    }
    if (
      outputFormat === 'klock' &&
      !passphrase &&
      (!keyfileBytes || keyfileBytes.byteLength === 0)
    ) {
      setErrorMsg('Enter a password or attach a keyfile to lock a .klock archive.');
      return;
    }
    if (
      (outputFormat === 'klock' ||
        outputFormat === '7z' ||
        outputFormat === 'zip') &&
      passphrase &&
      passphrase !== confirmPassphrase
    ) {
      setErrorMsg('Passwords do not match. Confirm your encryption password.');
      return;
    }
    if (
      (outputFormat === 'tar.gz' ||
        outputFormat === 'tar.bz2' ||
        outputFormat === 'tar.xz') &&
      passphrase
    ) {
      setErrorMsg(
        `Standard ${outputFormat} archives do not support native passwords. Clear the password field to create an unencrypted ${outputFormat}, or switch to .7z, .zip, or .klock.`
      );
      return;
    }

    setIsProcessing(true);
    setBatchProgress({
      stage: 'reading',
      label: `Preparing ${stagedFiles.length} file(s) for ${activeFormatMeta.shortLabel}...`,
      current: 0,
      total: stagedFiles.length,
      percent: 4,
    });

    try {
      const created = await createMultiFormatArchive({
        format: outputFormat,
        archiveBaseName: archiveName,
        files: stagedFiles,
        passphrase,
        keyfileBytes,
        klockCompressionAlgorithm: compressionAlgorithm,
        compressionLevel,
        iterations,
        encryptHeaders,
        zipEncryptionMethod,
        onProgress: (progress) => setBatchProgress(progress),
      });
      setResult(created);
      triggerDownload(created.archiveBytes, created.filename);
      const archiveTypeExt = created.filename.endsWith('.tar.gz')
        ? '.tar.gz'
        : created.filename.endsWith('.tar.bz2')
          ? '.tar.bz2'
          : created.filename.endsWith('.tar.xz')
            ? '.tar.xz'
            : `.${created.format}`;
      onRecordHistory({
        operation: 'encrypt',
        filename: created.filename,
        archiveType: archiveTypeExt,
        compressionSummary: created.compressionSummary,
        encrypted: created.encrypted,
        entryCount: created.entryCount,
        sizeBytes: created.finalArchiveSize,
        sha256: created.archiveSha256,
        integrityStatus: 'verified',
      });
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Archive creation failed.');
    } finally {
      setIsProcessing(false);
      setBatchProgress(null);
    }
  };

  const totalStagedBytes = stagedFiles.reduce((acc, item) => acc + item.size, 0);
  const directoryCount = countUniqueDirectories(
    stagedFiles.map((item) => item.relativePath)
  );
  const filteredStagedFiles = batchSearch.trim()
    ? stagedFiles.filter((f) =>
        f.relativePath.toLowerCase().includes(batchSearch.trim().toLowerCase())
      )
    : stagedFiles;

  const supportsPasswordField =
    outputFormat === 'klock' ||
    outputFormat === '7z' ||
    outputFormat === 'zip' ||
    outputFormat === 'rar';
  const isPasswordOptional =
    outputFormat === '7z' || outputFormat === 'zip' || outputFormat === 'rar';

  const strength = evaluatePasswordStrength(
    passphrase,
    outputFormat === 'klock' && Boolean(keyfileBytes && keyfileBytes.byteLength > 0)
  );
  const passwordsMismatch =
    confirmPassphrase.length > 0 && passphrase !== confirmPassphrase;

  const activeAlgoInfo = COMPRESSION_ALGORITHMS.find(
    (a) => a.id === compressionAlgorithm
  );

  const compressionRatioPct =
    result && result.uncompressedTotal > 0
      ? Math.round((1 - result.finalArchiveSize / result.uncompressedTotal) * 100)
      : 0;

  const singleFileTarHint =
    stagedFiles.length === 1 && !stagedFiles[0].relativePath.includes('/');
  const resolvedExtension =
    outputFormat === 'tar.gz'
      ? singleFileTarHint
        ? '.gz'
        : '.tar.gz'
      : outputFormat === 'tar.bz2'
        ? singleFileTarHint
          ? '.bz2'
          : '.tar.bz2'
        : outputFormat === 'tar.xz'
          ? singleFileTarHint
            ? '.xz'
            : '.tar.xz'
          : activeFormatMeta.extension;

  const cleanBaseName = (archiveName.trim() || 'vault-backup').replace(
    /\.(klock|7z|zip|rar|tar\.gz|tgz|tar\.bz2|tbz2|tar\.xz|txz|gz|bz2|xz)$/i,
    ''
  );
  const rarInputArgs =
    stagedFiles.length > 0
      ? stagedFiles
          .slice(0, 4)
          .map((f) => `"${f.relativePath}"`)
          .join(' ') + (stagedFiles.length > 4 ? ' ...' : '')
      : './files-or-folder';
  const rarCliCommand = passphrase
    ? `kryptlock pack "${cleanBaseName}.rar" ${rarInputArgs}${
        encryptHeaders ? ' --encrypt-headers' : ''
      } --write-checksum`
    : `kryptlock pack "${cleanBaseName}.rar" ${rarInputArgs} --no-password --write-checksum`;

  const actionButtonLabel = (() => {
    if (isProcessing) return `Packing ${activeFormatMeta.shortLabel}...`;
    const batchSuffix = stagedFiles.length > 1 ? ` (${stagedFiles.length} files)` : '';
    switch (outputFormat) {
      case 'klock':
        return `Compress & Lock .klock${batchSuffix}`;
      case '7z':
        return passphrase
          ? `Compress & Lock .7z${batchSuffix}`
          : `Create .7z Archive${batchSuffix}`;
      case 'zip':
        return passphrase
          ? `Compress & Lock .zip${batchSuffix}`
          : `Create .zip Archive${batchSuffix}`;
      case 'tar.gz':
        return `Compress ${resolvedExtension}${batchSuffix}`;
      case 'tar.bz2':
        return `Compress ${resolvedExtension}${batchSuffix}`;
      case 'tar.xz':
        return `Compress ${resolvedExtension}${batchSuffix}`;
      case 'rar':
        return 'Create .rar via Linux CLI / GUI';
    }
  })();

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-12 items-start">
      {/* Left Column: Staged Archive Contents */}
      <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-[#111722] overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 px-6 py-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Batch Archive Queue
            </h2>
            <p className="mt-0.5 text-xs text-slate-400 font-mono">
              {stagedFiles.length} {stagedFiles.length === 1 ? 'file' : 'files'}
              {directoryCount > 0
                ? ` · ${directoryCount} ${directoryCount === 1 ? 'folder' : 'folders'}`
                : ''}
              {' · '}
              {formatBytes(totalStagedBytes)} raw
              {skippedHiddenCount > 0
                ? ` · ${skippedHiddenCount} hidden skipped`
                : ''}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => {
                if (e.target.files) addFileList(e.target.files);
                e.target.value = '';
              }}
            />
            <input
              ref={folderInputRef}
              type="file"
              // @ts-expect-error webkitdirectory is supported in Chromium/Firefox/Safari
              webkitdirectory=""
              multiple
              className="hidden"
              onChange={(e) => {
                if (e.target.files) addFileList(e.target.files);
                e.target.value = '';
              }}
            />

            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              <FilePlus2 className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
              Add Files
            </button>
            <button
              type="button"
              onClick={() => folderInputRef.current?.click()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              <FolderPlus className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
              Add Directory
            </button>
            {stagedFiles.length > 0 && (
              <button
                type="button"
                onClick={() => {
                  setStagedFiles([]);
                  setSkippedHiddenCount(0);
                  setBatchSearch('');
                  setResult(null);
                }}
                className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium text-slate-400 hover:text-rose-400 transition-colors whitespace-nowrap shrink-0"
              >
                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                Clear Batch
              </button>
            )}
          </div>
        </div>

        {/* Batch Filter & Options Bar */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 bg-[#0B0F17]/40 px-6 py-2.5">
          <label className="inline-flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
            <input
              type="checkbox"
              checked={skipHiddenFiles}
              onChange={(e) => setSkipHiddenFiles(e.target.checked)}
              className="h-3.5 w-3.5 rounded border-slate-700 bg-[#0B0F17] accent-emerald-500"
            />
            <span>Skip system/VCS files (.git, .DS_Store)</span>
          </label>

          {stagedFiles.length > 0 && (
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500"
                aria-hidden="true"
              />
              <input
                type="text"
                value={batchSearch}
                onChange={(e) => setBatchSearch(e.target.value)}
                placeholder="Filter staged paths..."
                className="w-48 rounded-lg border border-slate-700 bg-[#0B0F17] py-1 pl-8 pr-3 text-xs text-slate-200 placeholder:text-slate-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>
          )}
        </div>

        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragging(true);
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setIsDragging(false);
            handleDropItems(e.dataTransfer);
          }}
          className={`min-h-[450px] transition-colors ${
            isDragging ? 'bg-emerald-500/5' : ''
          }`}
        >
          {isScanningDrop ? (
            <div className="flex min-h-[450px] flex-col items-center justify-center px-6 py-12 text-center">
              <FolderTree className="h-6 w-6 text-emerald-400 mb-3" aria-hidden="true" />
              <p className="text-sm font-medium text-slate-200">
                Scanning directory tree...
              </p>
              <p className="mt-1 text-xs text-slate-400">
                Collecting relative paths for batch compression.
              </p>
            </div>
          ) : stagedFiles.length === 0 ? (
            <div className="flex min-h-[450px] flex-col items-center justify-center px-6 py-12 text-center">
              <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl border border-slate-800 bg-slate-900">
                <FileArchive className="h-5 w-5 text-emerald-400" aria-hidden="true" />
              </div>
              <p className="text-sm font-medium text-slate-200">
                Drop multiple files or an entire directory to pack &amp; lock
              </p>
              <p className="mt-1.5 max-w-md text-xs leading-relaxed text-slate-400">
                Compress files into .klock, .7z, .zip, .gz / .tar.gz, .bz2, or .xz archives in one operation — with or without password encryption.
              </p>
              <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-medium text-slate-100 hover:bg-slate-700 transition-colors whitespace-nowrap"
                >
                  Select Files
                </button>
                <button
                  type="button"
                  onClick={() => folderInputRef.current?.click()}
                  className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-medium text-slate-100 hover:bg-slate-700 transition-colors whitespace-nowrap"
                >
                  Select Directory
                </button>
                <button
                  type="button"
                  onClick={handleLoadSampleFiles}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 px-4 py-2 text-xs font-medium text-slate-300 hover:border-slate-600 hover:text-slate-100 transition-colors whitespace-nowrap"
                >
                  <FileText className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
                  Load Sample Batch
                </button>
              </div>
            </div>
          ) : (
            <div className="max-h-[520px] overflow-auto">
              <table className="w-full text-left text-xs">
                <thead className="sticky top-0 bg-[#111722] z-10">
                  <tr className="border-b border-slate-800/80 text-slate-400">
                    <th className="px-6 py-3 font-medium">Relative Path</th>
                    <th className="px-4 py-3 font-medium text-right">Size</th>
                    <th className="px-6 py-3 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredStagedFiles.map((item) => (
                    <tr
                      key={item.id}
                      className="h-[42px] hover:bg-slate-800/30 transition-colors"
                    >
                      <td className="px-6 py-2.5 font-mono text-slate-200 max-w-[360px] truncate">
                        {item.relativePath}
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-slate-400 whitespace-nowrap">
                        {formatBytes(item.size)}
                      </td>
                      <td className="px-6 py-2.5 text-right">
                        <button
                          type="button"
                          onClick={() =>
                            setStagedFiles((prev) => prev.filter((f) => f.id !== item.id))
                          }
                          aria-label={`Remove ${item.relativePath}`}
                          className="text-slate-500 hover:text-rose-400 transition-colors p-1"
                        >
                          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                        </button>
                      </td>
                    </tr>
                  ))}
                  {filteredStagedFiles.length === 0 && (
                    <tr>
                      <td colSpan={3} className="px-6 py-10 text-center text-slate-400">
                        No staged paths match "{batchSearch}".
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Right Column: Archive Format & Lock Configuration */}
      <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-[#111722] p-6 space-y-5">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Archive Format &amp; Encryption Settings
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Choose .klock, .7z, .zip, .gz/.tar.gz, .bz2, .xz, or .rar with optional password lock
          </p>
        </div>

        <div className="space-y-4 border-t border-slate-800/80 pt-4">
          {/* Output Archive Format */}
          <div>
            <span className="block text-xs font-medium text-slate-300 mb-1.5">
              Output Format
            </span>
            <div className="grid grid-cols-4 gap-1 rounded-lg bg-[#0B0F17] p-1 border border-slate-800">
              {PACK_FORMATS.map((fmt) => (
                <button
                  key={fmt.id}
                  type="button"
                  onClick={() => {
                    setOutputFormat(fmt.id);
                    setErrorMsg(null);
                    setResult(null);
                  }}
                  className={`rounded-md py-1.5 px-1.5 text-xs font-mono font-medium transition-colors whitespace-nowrap truncate ${
                    outputFormat === fmt.id
                      ? 'bg-slate-800 text-emerald-400'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {fmt.shortLabel}
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-[11px] text-slate-400">
              <span className="font-mono text-slate-300">{activeFormatMeta.label}</span> ·{' '}
              {activeFormatMeta.summary}
            </p>
          </div>

          <div>
            <label
              htmlFor="archive-name"
              className="block text-xs font-medium text-slate-300 mb-1.5"
            >
              Output Archive Name
            </label>
            <div className="flex items-center rounded-lg border border-slate-700 bg-[#0B0F17] focus-within:border-emerald-500 transition-colors">
              <input
                id="archive-name"
                type="text"
                value={archiveName}
                onChange={(e) => setArchiveName(e.target.value)}
                placeholder="vault-backup"
                className="w-full bg-transparent px-3 py-2 text-sm font-mono text-slate-100 focus:outline-none"
              />
              <span className="pr-3 font-mono text-xs text-slate-500 shrink-0">
                {resolvedExtension}
              </span>
            </div>
          </div>

          {/* KLOCK inner compression codec selector */}
          {outputFormat === 'klock' && (
            <div>
              <span className="block text-xs font-medium text-slate-300 mb-1.5">
                Compression Algorithm
              </span>
              <div className="grid grid-cols-5 gap-1 rounded-lg bg-[#0B0F17] p-1 border border-slate-800">
                {COMPRESSION_ALGORITHMS.map((algo) => (
                  <button
                    key={algo.id}
                    type="button"
                    onClick={() => setCompressionAlgorithm(algo.id)}
                    className={`rounded-md py-1.5 px-1 text-xs font-medium transition-colors whitespace-nowrap truncate ${
                      compressionAlgorithm === algo.id
                        ? 'bg-slate-800 text-slate-50'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {algo.shortLabel}
                  </button>
                ))}
              </div>
              {activeAlgoInfo && (
                <p className="mt-1.5 text-[11px] text-slate-400">
                  <span className="font-mono text-slate-300">
                    {activeAlgoInfo.extensionHint}
                  </span>{' '}
                  · {activeAlgoInfo.summary}
                </p>
              )}
            </div>
          )}

          {/* Compression Level & Format-Specific Options */}
          {outputFormat !== 'rar' && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="compression-level"
                  className="block text-xs font-medium text-slate-300 mb-1.5"
                >
                  Compression Level
                </label>
                <select
                  id="compression-level"
                  disabled={
                    outputFormat === 'klock' &&
                    (compressionAlgorithm === 'store' || compressionAlgorithm === 'bzip2')
                  }
                  value={compressionLevel}
                  onChange={(e) =>
                    setCompressionLevel(Number(e.target.value) as 1 | 3 | 6 | 9)
                  }
                  className="w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-xs font-medium text-slate-100 disabled:opacity-40 focus:border-emerald-500 focus:outline-none"
                >
                  <option value={1}>1 — Fast</option>
                  <option value={3}>3 — Normal</option>
                  <option value={6}>6 — Balanced</option>
                  <option value={9}>9 — Maximum</option>
                </select>
              </div>

              {outputFormat === 'klock' && (
                <div>
                  <label
                    htmlFor="kdf-iterations"
                    className="block text-xs font-medium text-slate-300 mb-1.5"
                  >
                    PBKDF2 Rounds
                  </label>
                  <select
                    id="kdf-iterations"
                    value={iterations}
                    onChange={(e) => setIterations(Number(e.target.value))}
                    className="w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-xs font-mono text-slate-100 focus:border-emerald-500 focus:outline-none"
                  >
                    <option value={100000}>100,000 rounds</option>
                    <option value={310000}>310,000 rounds</option>
                    <option value={600000}>600,000 rounds</option>
                  </select>
                </div>
              )}

              {outputFormat === 'zip' && (
                <div>
                  <label
                    htmlFor="zip-cipher"
                    className="block text-xs font-medium text-slate-300 mb-1.5"
                  >
                    ZIP Cipher (if locked)
                  </label>
                  <select
                    id="zip-cipher"
                    value={zipEncryptionMethod}
                    onChange={(e) =>
                      setZipEncryptionMethod(e.target.value as 'aes256' | 'zipcrypto')
                    }
                    className="w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-xs font-medium text-slate-100 focus:border-emerald-500 focus:outline-none"
                  >
                    <option value="aes256">AES-256 (Strong)</option>
                    <option value="zipcrypto">ZipCrypto (Legacy)</option>
                  </select>
                </div>
              )}

              {outputFormat === '7z' && (
                <div className="flex items-end pb-1">
                  <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={encryptHeaders}
                      onChange={(e) => setEncryptHeaders(e.target.checked)}
                      className="h-3.5 w-3.5 rounded border-slate-700 bg-[#0B0F17] accent-emerald-500"
                    />
                    <span>Encrypt filenames (-mhe)</span>
                  </label>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Password Section (Required for .klock, Optional for .7z / .zip / .rar, Info for .gz/.bz2/.xz) */}
        {supportsPasswordField ? (
          <div className="space-y-3 border-t border-slate-800/80 pt-4">
            <div className="flex items-center justify-between gap-2">
              <label htmlFor="lock-passphrase" className="text-xs font-medium text-slate-300">
                {isPasswordOptional
                  ? 'Password (Optional — leave blank for unencrypted)'
                  : 'Encryption Password'}
              </label>
              <button
                type="button"
                onClick={() => {
                  const generated = generateSecurePassphrase(5);
                  setPassphrase(generated);
                  setConfirmPassphrase(generated);
                  setShowPassphrase(true);
                }}
                className="inline-flex items-center gap-1 text-xs font-medium text-emerald-400 hover:text-emerald-300 transition-colors shrink-0"
              >
                <RefreshCw className="h-3 w-3" aria-hidden="true" />
                Generate
              </button>
            </div>

            <div className="flex items-center rounded-lg border border-slate-700 bg-[#0B0F17] focus-within:border-emerald-500 transition-colors">
              <input
                id="lock-passphrase"
                type={showPassphrase ? 'text' : 'password'}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder={
                  isPasswordOptional
                    ? 'Leave empty for no password, or enter password'
                    : 'Enter password'
                }
                autoComplete="new-password"
                className="w-full bg-transparent px-3 py-2 text-sm font-mono text-slate-100 focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowPassphrase((v) => !v)}
                aria-label={showPassphrase ? 'Hide password' : 'Show password'}
                className="px-3 text-slate-400 hover:text-slate-200 transition-colors"
              >
                {showPassphrase ? (
                  <EyeOff className="h-4 w-4" aria-hidden="true" />
                ) : (
                  <Eye className="h-4 w-4" aria-hidden="true" />
                )}
              </button>
            </div>

            {/* Real-time Visual Password Strength Meter */}
            {(passphrase.length > 0 || outputFormat === 'klock') && (
              <div className="pt-1 space-y-2.5">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-400">
                    Password Strength:{' '}
                    <span
                      className={`font-semibold ${
                        strength.score >= 3
                          ? 'text-emerald-400'
                          : strength.score === 2
                            ? 'text-amber-400'
                            : strength.score === 1
                              ? 'text-rose-400'
                              : 'text-slate-400'
                      }`}
                    >
                      {strength.label}
                    </span>
                  </span>
                  <span className="text-slate-400">{strength.bits} bits entropy</span>
                </div>

                <div
                  role="meter"
                  aria-label="Password strength"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={strength.percentage}
                  aria-valuetext={`${strength.label}, ${strength.bits} bits of entropy`}
                  className="relative h-2 w-full overflow-hidden rounded-full bg-slate-800"
                >
                  <div
                    style={{ width: `${strength.percentage}%` }}
                    className={`h-full rounded-full transition-all duration-200 ${
                      strength.score === 4
                        ? 'bg-emerald-400'
                        : strength.score === 3
                          ? 'bg-emerald-500'
                          : strength.score === 2
                            ? 'bg-amber-500'
                            : strength.score === 1
                              ? 'bg-rose-500'
                              : 'bg-slate-700'
                    }`}
                  />
                  <div className="pointer-events-none absolute inset-0 grid grid-cols-4">
                    <span className="border-r border-[#111722]/90" />
                    <span className="border-r border-[#111722]/90" />
                    <span className="border-r border-[#111722]/90" />
                    <span />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px] font-mono">
                  <div
                    className={`flex items-center gap-1.5 ${
                      strength.checks.minLength ? 'text-emerald-400' : 'text-slate-500'
                    }`}
                  >
                    <Check className="h-3 w-3 shrink-0" aria-hidden="true" />
                    <span>12+ chars ({passphrase.length}/12)</span>
                  </div>
                  <div
                    className={`flex items-center gap-1.5 ${
                      strength.checks.hasMixedCase ? 'text-emerald-400' : 'text-slate-500'
                    }`}
                  >
                    <Check className="h-3 w-3 shrink-0" aria-hidden="true" />
                    <span>Upper &amp; lower case</span>
                  </div>
                  <div
                    className={`flex items-center gap-1.5 ${
                      strength.checks.hasDigit ? 'text-emerald-400' : 'text-slate-500'
                    }`}
                  >
                    <Check className="h-3 w-3 shrink-0" aria-hidden="true" />
                    <span>Numbers (0–9)</span>
                  </div>
                  <div
                    className={`flex items-center gap-1.5 ${
                      strength.checks.hasSymbol ? 'text-emerald-400' : 'text-slate-500'
                    }`}
                  >
                    <Check className="h-3 w-3 shrink-0" aria-hidden="true" />
                    <span>Symbols / hyphens</span>
                  </div>
                </div>

                {strength.hints.length > 0 && (
                  <p className="text-[11px] text-slate-400">
                    {strength.hasWeakPattern ? 'Pattern alert: ' : 'Tip: '}
                    {strength.hints.join(' · ')}
                  </p>
                )}
              </div>
            )}

            {(passphrase.length > 0 || outputFormat === 'klock') &&
              outputFormat !== 'rar' && (
                <div>
                  <label
                    htmlFor="lock-passphrase-confirm"
                    className="block text-xs font-medium text-slate-300 mb-1.5"
                  >
                    Confirm Password
                  </label>
                  <input
                    id="lock-passphrase-confirm"
                    type={showPassphrase ? 'text' : 'password'}
                    value={confirmPassphrase}
                    onChange={(e) => setConfirmPassphrase(e.target.value)}
                    placeholder="Re-enter password"
                    autoComplete="new-password"
                    className={`w-full rounded-lg border bg-[#0B0F17] px-3 py-2 text-sm font-mono text-slate-100 focus:outline-none transition-colors ${
                      passwordsMismatch
                        ? 'border-rose-500 focus:border-rose-400'
                        : 'border-slate-700 focus:border-emerald-500'
                    }`}
                  />
                  {passwordsMismatch && (
                    <p className="mt-1 text-[11px] text-rose-400">
                      Confirmation does not match password.
                    </p>
                  )}
                </div>
              )}
          </div>
        ) : (
          <div className="border-t border-slate-800/80 pt-4 text-xs text-slate-400 leading-relaxed">
            Standard <span className="font-mono text-slate-200">{resolvedExtension}</span>{' '}
            archives do not carry native passwords. Leave unencrypted or choose{' '}
            <button
              type="button"
              onClick={() => setOutputFormat('7z')}
              className="text-emerald-400 hover:underline font-mono"
            >
              .7z
            </button>
            ,{' '}
            <button
              type="button"
              onClick={() => setOutputFormat('zip')}
              className="text-emerald-400 hover:underline font-mono"
            >
              .zip
            </button>
            , or{' '}
            <button
              type="button"
              onClick={() => setOutputFormat('klock')}
              className="text-emerald-400 hover:underline font-mono"
            >
              .klock
            </button>{' '}
            for password encryption.
          </div>
        )}

        {/* RAR Linux CLI bridge */}
        {outputFormat === 'rar' && (
          <div className="rounded-lg border border-slate-800 bg-[#0B0F17] p-3.5 space-y-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-200">
                <Terminal className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                Native Linux RAR Command
              </span>
              <button
                type="button"
                onClick={() => handleCopyRarCommand(rarCliCommand)}
                className="inline-flex items-center gap-1 text-[11px] text-slate-300 hover:text-emerald-400 transition-colors"
              >
                {copiedRarCmd ? (
                  <>
                    <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3" aria-hidden="true" />
                    Copy CLI
                  </>
                )}
              </button>
            </div>
            <pre className="overflow-x-auto font-mono text-[11px] text-emerald-300">
              {rarCliCommand}
            </pre>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Creating .rar files requires the native Linux <span className="font-mono text-slate-300">rar</span> encoder (included in the Native Linux App CLI/GUI). UnRAR extraction works directly in-browser in the Unlock Archive tab.
            </p>
            <label className="inline-flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={encryptHeaders}
                onChange={(e) => setEncryptHeaders(e.target.checked)}
                className="h-3.5 w-3.5 rounded border-slate-700 bg-[#0B0F17] accent-emerald-500"
              />
              <span>Encrypt RAR headers (-hp) when password set</span>
            </label>
          </div>
        )}

        {/* Optional Keyfile for .klock */}
        {outputFormat === 'klock' && (
          <div className="space-y-2 border-t border-slate-800/80 pt-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-300">
                Optional Keyfile (2FA Lock)
              </span>
              <button
                type="button"
                onClick={handleGenerateKeyfile}
                className="text-xs font-medium text-slate-400 hover:text-slate-200 transition-colors"
              >
                Generate .key file
              </button>
            </div>

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
                  className="ml-2 text-slate-400 hover:text-rose-400 shrink-0"
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
                Attach Existing Keyfile
              </button>
            )}
          </div>
        )}

        {errorMsg && (
          <div
            role="alert"
            className="flex items-start gap-2.5 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3.5 py-2.5 text-xs text-rose-300"
          >
            <AlertCircle
              className="h-4 w-4 shrink-0 mt-0.5 text-rose-400"
              aria-hidden="true"
            />
            <span>{errorMsg}</span>
          </div>
        )}

        {batchProgress && (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-300">
              <span className="truncate pr-2">{batchProgress.label}</span>
              <span className="shrink-0 text-emerald-400">{batchProgress.percent}%</span>
            </div>
            <div
              role="progressbar"
              aria-label="Archive compression and encryption progress"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={batchProgress.percent}
              className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800"
            >
              <div
                style={{ width: `${batchProgress.percent}%` }}
                className="h-full rounded-full bg-emerald-500 transition-all duration-150"
              />
            </div>
          </div>
        )}

        <button
          type="button"
          disabled={isProcessing || outputFormat === 'rar'}
          onClick={handleCreateArchive}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-slate-950 transition-colors hover:bg-emerald-400 disabled:opacity-50"
        >
          <Lock className="h-4 w-4" aria-hidden="true" />
          {actionButtonLabel}
        </button>

        {result && (
          <div className="space-y-3 border-t border-slate-800/80 pt-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
              <CheckCircle2 className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>
                Created {result.filename} ({result.compressionSummary})
              </span>
            </div>

            <div className="grid grid-cols-2 gap-y-1.5 text-xs font-mono">
              <span className="text-slate-400">Archive Size</span>
              <span className="text-right text-slate-200">
                {formatBytes(result.finalArchiveSize)}
              </span>
              <span className="text-slate-400">Compression Delta</span>
              <span className="text-right text-slate-200">
                {compressionRatioPct > 0 ? `-${compressionRatioPct}%` : '0%'}
              </span>
              <span className="text-slate-400">Protection</span>
              <span className="text-right text-slate-200">
                {result.encrypted ? 'Password Encrypted' : 'Unencrypted'}
              </span>
              {result.saltHex && (
                <>
                  <span className="text-slate-400">Salt Fingerprint</span>
                  <span className="text-right text-slate-300 truncate">
                    {result.saltHex.slice(0, 16)}...
                  </span>
                </>
              )}
            </div>

            {/* Integrity Checksum Display */}
            <div className="rounded-lg border border-slate-800 bg-[#0B0F17] p-3 space-y-1.5">
              <div className="flex items-center justify-between text-[11px]">
                <span className="inline-flex items-center gap-1.5 font-medium text-slate-300">
                  <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                  Archive SHA-256 Checksum
                </span>
                <button
                  type="button"
                  onClick={() => handleCopySha(result.archiveSha256)}
                  className="inline-flex items-center gap-1 text-slate-300 hover:text-emerald-400 transition-colors"
                >
                  {copiedSha ? (
                    <>
                      <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                      Copied
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" aria-hidden="true" />
                      Copy
                    </>
                  )}
                </button>
              </div>
              <p className="font-mono text-[11px] text-emerald-300 break-all leading-relaxed">
                {result.archiveSha256}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-2 pt-1">
              <button
                type="button"
                onClick={() => triggerDownload(result.archiveBytes, result.filename)}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-2 text-xs font-medium text-slate-100 hover:bg-slate-800 transition-colors"
              >
                <Download className="h-3.5 w-3.5" aria-hidden="true" />
                Save Archive
              </button>
              <button
                type="button"
                onClick={() => downloadChecksumFile(result.archiveSha256, result.filename)}
                className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-2 text-xs font-medium text-slate-100 hover:bg-slate-800 transition-colors"
              >
                <Download className="h-3.5 w-3.5" aria-hidden="true" />
                Save .sha256
              </button>
            </div>

            <button
              type="button"
              onClick={() =>
                onSendArchiveToUnlock(
                  result.archiveBytes,
                  result.filename,
                  result.archiveSha256
                )
              }
              className="w-full inline-flex items-center justify-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20 transition-colors"
            >
              Verify &amp; Extract in Unlock Tab
              <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </button>

            {/* Email Archive */}
            <div className="space-y-3 border-t border-slate-800/80 pt-4">
              <div>
                <h3 className="text-xs font-semibold text-slate-200">
                  Email Compressed / Locked Archive
                </h3>
                <p className="mt-0.5 text-[11px] text-slate-400">
                  Draft an email with archive metadata and checksum. Share any password separately.
                </p>
              </div>

              <div>
                <label
                  htmlFor="recipient-email"
                  className="block text-xs font-medium text-slate-300 mb-1.5"
                >
                  Recipient Email
                </label>
                <input
                  id="recipient-email"
                  type="email"
                  value={recipientEmail}
                  onChange={(e) => {
                    setRecipientEmail(e.target.value);
                    setEmailNotice(null);
                  }}
                  placeholder="colleague@example.com"
                  className="w-full rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeChecksumInEmail}
                  onChange={(e) => setIncludeChecksumInEmail(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-slate-700 bg-[#0B0F17] accent-emerald-500"
                />
                <span>Include SHA-256 verification checksum in email body</span>
              </label>

              {(() => {
                const subject = `${result.encrypted ? 'Encrypted' : 'Compressed'} archive: ${
                  result.filename
                }`;
                const bodyLines = [
                  `Attached is the archive (${result.filename}) created with KryptLock.`,
                  '',
                  `Format: ${result.compressionSummary}`,
                  `Archive Size: ${formatBytes(result.finalArchiveSize)}`,
                  ...(includeChecksumInEmail
                    ? [`SHA-256 Checksum: ${result.archiveSha256}`]
                    : []),
                  '',
                  'To extract: open in KryptLock (Linux GTK4/CLI or Web Workbench).',
                  ...(result.encrypted
                    ? ['Note: The decryption password will be sent separately.']
                    : []),
                ];
                const body = bodyLines.join('\n');
                const mailtoHref = `mailto:${encodeURIComponent(
                  recipientEmail.trim()
                )}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;

                const handleShareOrCopy = async () => {
                  const archiveFile = new File([result.archiveBytes], result.filename, {
                    type: 'application/octet-stream',
                  });
                  if (
                    typeof navigator.share === 'function' &&
                    typeof navigator.canShare === 'function' &&
                    navigator.canShare({ files: [archiveFile] })
                  ) {
                    try {
                      await navigator.share({
                        title: subject,
                        text: body,
                        files: [archiveFile],
                      });
                      setEmailNotice('Shared archive via system share sheet.');
                      return;
                    } catch {
                      // Fall back to clipboard copy below if share dismissed
                    }
                  }
                  try {
                    await navigator.clipboard.writeText(
                      `Subject: ${subject}\n\n${body}`
                    );
                    setEmailNotice(
                      `Copied email message to clipboard. Attach ${result.filename} in your mail app.`
                    );
                  } catch {
                    setEmailNotice(
                      `Use "Open Mail App" and attach your downloaded ${result.filename}.`
                    );
                  }
                };

                return (
                  <div className="space-y-2">
                    <div className="grid grid-cols-2 gap-2">
                      <a
                        href={mailtoHref}
                        onClick={() =>
                          setEmailNotice(
                            `Opened email draft. Attach the saved ${result.filename} file before sending.`
                          )
                        }
                        className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-slate-100 px-3 py-2 text-xs font-semibold text-slate-900 hover:bg-white transition-colors"
                      >
                        <Mail className="h-3.5 w-3.5" aria-hidden="true" />
                        Open Mail App
                      </a>
                      <button
                        type="button"
                        onClick={handleShareOrCopy}
                        className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-2 text-xs font-medium text-slate-100 hover:bg-slate-800 transition-colors"
                      >
                        <Share2 className="h-3.5 w-3.5" aria-hidden="true" />
                        Share / Copy Note
                      </button>
                    </div>
                    {emailNotice && (
                      <p className="text-[11px] text-slate-400 leading-relaxed">
                        {emailNotice}
                      </p>
                    )}
                  </div>
                );
              })()}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
