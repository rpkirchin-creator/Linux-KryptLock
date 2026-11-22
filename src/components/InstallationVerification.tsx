import { useCallback, useEffect, useState } from 'react';
import {
  Check,
  CheckCircle2,
  Copy,
  FileSearch,
  RefreshCw,
  Terminal,
  XCircle,
} from 'lucide-react';

interface VerifiedPathItem {
  id: string;
  label: string;
  scope: string;
  resolvedPath: string;
  exists: boolean;
  executable: boolean;
}

interface VerificationState {
  installed: boolean;
  source: 'host' | 'terminal' | 'file';
  checkedAt: string;
  platform?: string;
  paths: VerifiedPathItem[];
  formats?: Record<string, unknown> | null;
  error?: string | null;
}

const DEFAULT_PATHS: VerifiedPathItem[] = [
  {
    id: 'usr-local-bin',
    label: '/usr/local/bin/kryptlock',
    scope: 'System local CLI',
    resolvedPath: '/usr/local/bin/kryptlock',
    exists: false,
    executable: false,
  },
  {
    id: 'home-local-bin',
    label: '~/.local/bin/kryptlock',
    scope: 'User bundle CLI',
    resolvedPath: '~/.local/bin/kryptlock',
    exists: false,
    executable: false,
  },
  {
    id: 'usr-bin',
    label: '/usr/bin/kryptlock',
    scope: 'Ubuntu .deb CLI',
    resolvedPath: '/usr/bin/kryptlock',
    exists: false,
    executable: false,
  },
];

const TERMINAL_CHECK_CMD =
  'for p in /usr/local/bin/kryptlock "$HOME/.local/bin/kryptlock" /usr/bin/kryptlock; do [ -e "$p" ] && echo "FOUND:$p" || echo "MISSING:$p"; done';

export function InstallationVerification() {
  const [checking, setChecking] = useState(false);
  const [state, setState] = useState<VerificationState>({
    installed: false,
    source: 'host',
    checkedAt: '',
    paths: DEFAULT_PATHS,
    formats: null,
    error: null,
  });
  const [showLocalFallback, setShowLocalFallback] = useState(false);
  const [terminalPaste, setTerminalPaste] = useState('');
  const [copiedCmd, setCopiedCmd] = useState(false);

  const isLocalHost =
    typeof window !== 'undefined' &&
    (window.location.hostname === 'localhost' ||
      window.location.hostname === '127.0.0.1');

  const runHostVerification = useCallback(async () => {
    setChecking(true);
    try {
      const response = await fetch('/api/verify-install', { cache: 'no-store' });
      if (!response.ok) {
        throw new Error(`Verification endpoint returned HTTP ${response.status}`);
      }
      const data = (await response.json()) as {
        installed: boolean;
        checkedAt: string;
        platform?: string;
        paths: VerifiedPathItem[];
        formats?: Record<string, unknown> | null;
      };
      setState({
        installed: Boolean(data.installed),
        source: 'host',
        checkedAt: data.checkedAt || new Date().toISOString(),
        platform: data.platform,
        paths: Array.isArray(data.paths) && data.paths.length > 0 ? data.paths : DEFAULT_PATHS,
        formats: data.formats ?? null,
        error: null,
      });
    } catch (err) {
      setState((prev) => ({
        ...prev,
        installed: false,
        source: 'host',
        checkedAt: new Date().toISOString(),
        error:
          err instanceof Error
            ? err.message
            : 'Unable to reach /api/verify-install from this static host.',
      }));
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    void runHostVerification();
  }, [runHostVerification]);

  const handleCopyTerminalCheck = async () => {
    try {
      await navigator.clipboard.writeText(TERMINAL_CHECK_CMD);
      setCopiedCmd(true);
      setTimeout(() => setCopiedCmd(false), 1800);
    } catch {
      // Clipboard restricted
    }
  };

  const handleParseTerminalOutput = () => {
    const raw = terminalPaste.trim();
    if (!raw) return;

    const hasUsrLocal =
      /FOUND:\s*\/usr\/local\/bin\/kryptlock/i.test(raw) ||
      (/\/usr\/local\/bin\/kryptlock/.test(raw) && !/No such file|MISSING:/i.test(raw));
    const hasHomeLocal =
      /FOUND:.*\.local\/bin\/kryptlock/i.test(raw) ||
      (/\.local\/bin\/kryptlock/.test(raw) && !/No such file|MISSING:/i.test(raw));
    const hasUsrBin =
      /FOUND:\s*\/usr\/bin\/kryptlock/i.test(raw) ||
      (/\/usr\/bin\/kryptlock/.test(raw) && !/No such file|MISSING:/i.test(raw));

    const updatedPaths: VerifiedPathItem[] = [
      {
        id: 'usr-local-bin',
        label: '/usr/local/bin/kryptlock',
        scope: 'System local CLI',
        resolvedPath: '/usr/local/bin/kryptlock',
        exists: hasUsrLocal,
        executable: hasUsrLocal,
      },
      {
        id: 'home-local-bin',
        label: '~/.local/bin/kryptlock',
        scope: 'User bundle CLI',
        resolvedPath: '~/.local/bin/kryptlock',
        exists: hasHomeLocal,
        executable: hasHomeLocal,
      },
      {
        id: 'usr-bin',
        label: '/usr/bin/kryptlock',
        scope: 'Ubuntu .deb CLI',
        resolvedPath: '/usr/bin/kryptlock',
        exists: hasUsrBin,
        executable: hasUsrBin,
      },
    ];

    setState({
      installed: hasUsrLocal || hasHomeLocal || hasUsrBin,
      source: 'terminal',
      checkedAt: new Date().toISOString(),
      paths: updatedPaths,
      formats: null,
      error: null,
    });
  };

  const handleInspectSelectedBinary = async (fileList: FileList | null) => {
    const file = fileList?.[0];
    if (!file) return;
    const text = await file.slice(0, 512).text();
    const looksLikeKryptlock =
      file.name === 'kryptlock' ||
      file.name === 'kryptlock.py' ||
      file.name === 'kryptlock-gui' ||
      text.includes('kryptlock.py') ||
      text.includes('KryptLock');

    const updatedPaths = state.paths.map((item) => {
      if (item.id === 'home-local-bin' && looksLikeKryptlock) {
        return { ...item, exists: true, executable: true };
      }
      return item;
    });

    setState({
      installed: looksLikeKryptlock,
      source: 'file',
      checkedAt: new Date().toISOString(),
      paths: updatedPaths,
      formats: null,
      error: looksLikeKryptlock
        ? null
        : `Selected file "${file.name}" does not match a KryptLock launcher or script.`,
    });
  };

  const formattedTime = state.checkedAt
    ? new Date(state.checkedAt).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : 'Pending';

  return (
    <section
      aria-labelledby="installation-verification-heading"
      className="rounded-xl border border-slate-800 bg-[#111722] overflow-hidden"
    >
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 px-6 py-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-3">
            <h3
              id="installation-verification-heading"
              className="text-sm font-semibold text-slate-100"
            >
              Installation Verification
            </h3>

            <span
              role="status"
              aria-live="polite"
              className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-0.5 text-xs font-semibold whitespace-nowrap ${
                state.installed
                  ? 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
                  : 'border-rose-500/40 bg-rose-500/15 text-rose-300'
              }`}
            >
              {state.installed ? (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                  Installed
                </>
              ) : (
                <>
                  <XCircle className="h-3.5 w-3.5 text-rose-400" aria-hidden="true" />
                  Not Installed
                </>
              )}
            </span>
          </div>

          <p className="text-xs text-slate-400 font-mono">
            Checks /usr/local/bin/kryptlock or ~/.local/bin/kryptlock · Source: {state.source} · Last checked: {formattedTime}
            {state.platform ? ` · Host: ${state.platform}` : ''}
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setShowLocalFallback((v) => !v)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
          >
            <Terminal className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
            {showLocalFallback ? 'Hide Ubuntu Check' : 'Verify Ubuntu PC'}
          </button>

          <button
            type="button"
            onClick={() => void runHostVerification()}
            disabled={checking}
            className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3.5 py-1.5 text-xs font-semibold text-slate-950 hover:bg-emerald-400 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${checking ? 'animate-spin' : ''}`}
              aria-hidden="true"
            />
            {checking ? 'Checking...' : 'Re-check'}
          </button>
        </div>
      </div>

      {/* Path Checklist Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-slate-800/80 text-slate-400">
              <th className="px-6 py-2.5 font-medium">Checked Path</th>
              <th className="px-4 py-2.5 font-medium">Target</th>
              <th className="px-4 py-2.5 font-medium">Resolved Location</th>
              <th className="px-6 py-2.5 font-medium text-right">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {state.paths.map((item) => (
              <tr key={item.id} className="h-[42px] hover:bg-slate-800/20">
                <td className="px-6 py-2 font-mono text-slate-100 whitespace-nowrap">
                  {item.label}
                </td>
                <td className="px-4 py-2 text-slate-400 whitespace-nowrap">
                  {item.scope}
                </td>
                <td className="px-4 py-2 font-mono text-slate-400 truncate max-w-[280px]">
                  {item.resolvedPath}
                </td>
                <td className="px-6 py-2 text-right whitespace-nowrap">
                  <span
                    className={`inline-flex items-center gap-1 font-mono text-xs font-medium ${
                      item.exists ? 'text-emerald-400' : 'text-slate-500'
                    }`}
                  >
                    {item.exists ? (
                      <>
                        <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                        {item.executable ? 'Installed (executable)' : 'Found (not +x)'}
                      </>
                    ) : (
                      'Not Installed'
                    )}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {state.formats && (
        <div className="border-t border-slate-800/80 px-6 py-3 text-xs font-mono text-slate-300">
          Detected backends: {Object.entries(state.formats)
            .map(([k, v]) => `${k}=${String(v ?? 'none')}`)
            .join(' · ')}
        </div>
      )}

      {state.error && (
        <div className="border-t border-slate-800/80 px-6 py-3 text-xs text-rose-400">
          {state.error}
        </div>
      )}

      {(!isLocalHost || showLocalFallback) && (
        <div className="border-t border-slate-800/80 px-6 py-4 space-y-4 bg-[#0B0F17]/60">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-xs text-slate-300">
              {isLocalHost
                ? 'Running on localhost: Re-check inspects your computer directly. You can also verify via terminal output or binary file selection.'
                : 'Browsers cannot read local Ubuntu folders from a remote URL. Run this one-liner in your Ubuntu terminal and paste the output below (or pick your installed binary file):'}
            </p>
            <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0">
              <FileSearch className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
              Select kryptlock Binary
              <input
                type="file"
                className="sr-only"
                onChange={(e) => void handleInspectSelectedBinary(e.target.files)}
              />
            </label>
          </div>

          <div className="flex items-center justify-between gap-2 rounded-lg border border-slate-800 bg-[#0B0F17] px-3 py-2">
            <code className="overflow-x-auto font-mono text-[11px] text-emerald-300 whitespace-nowrap">
              {TERMINAL_CHECK_CMD}
            </code>
            <button
              type="button"
              onClick={handleCopyTerminalCheck}
              className="inline-flex items-center gap-1 text-xs text-slate-300 hover:text-emerald-400 transition-colors whitespace-nowrap shrink-0"
            >
              {copiedCmd ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                  Copy
                </>
              )}
            </button>
          </div>

          <div className="flex flex-col gap-2 sm:flex-row">
            <textarea
              rows={2}
              value={terminalPaste}
              onChange={(e) => setTerminalPaste(e.target.value)}
              placeholder="Paste output here (e.g. FOUND:/home/bernie/.local/bin/kryptlock)..."
              aria-label="Paste Ubuntu verification command output"
              className="flex-1 rounded-lg border border-slate-700 bg-[#0B0F17] px-3 py-2 font-mono text-xs text-slate-200 placeholder:text-slate-500 focus:border-emerald-500 focus:outline-none"
            />
            <button
              type="button"
              onClick={handleParseTerminalOutput}
              disabled={!terminalPaste.trim()}
              className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 text-xs font-medium text-slate-100 hover:bg-slate-700 disabled:opacity-50 transition-colors whitespace-nowrap shrink-0"
            >
              Verify Output
            </button>
          </div>
        </div>
      )}
    </section>
  );
}
