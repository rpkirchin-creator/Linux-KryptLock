import { useState } from 'react';
import {
  Check,
  Copy,
  Download,
  History,
  Lock,
  Search,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Unlock,
} from 'lucide-react';
import { ArchiveHistoryEntry } from '../lib/archiveHistory';
import { formatBytes } from '../lib/klockCrypto';

interface ArchiveHistoryPanelProps {
  entries: ArchiveHistoryEntry[];
  onDeleteItem: (id: string) => void;
  onClearAll: () => void;
}

type HistoryFilter = 'all' | 'encrypt' | 'decrypt';

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function ArchiveHistoryPanel({
  entries,
  onDeleteItem,
  onClearAll,
}: ArchiveHistoryPanelProps) {
  const [filter, setFilter] = useState<HistoryFilter>('all');
  const [search, setSearch] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const filteredEntries = entries.filter((item) => {
    if (filter !== 'all' && item.operation !== filter) return false;
    if (!search.trim()) return true;
    const q = search.trim().toLowerCase();
    return (
      item.filename.toLowerCase().includes(q) ||
      item.archiveType.toLowerCase().includes(q) ||
      item.compressionSummary.toLowerCase().includes(q) ||
      item.sha256.toLowerCase().includes(q)
    );
  });

  const handleCopySha = async (id: string, sha256: string) => {
    try {
      await navigator.clipboard.writeText(sha256);
      setCopiedId(id);
      setTimeout(() => {
        setCopiedId((prev) => (prev === id ? null : prev));
      }, 1600);
    } catch {
      // Clipboard restricted
    }
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(entries, null, 2)], {
      type: 'application/json;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kryptlock-history-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const encryptCount = entries.filter((e) => e.operation === 'encrypt').length;
  const decryptCount = entries.filter((e) => e.operation === 'decrypt').length;

  return (
    <section
      aria-labelledby="archive-history-heading"
      className="rounded-xl border border-slate-800 bg-[#111722] overflow-hidden"
    >
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 px-6 py-4">
        <div className="flex items-start gap-3">
          <div className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-lg border border-slate-800 bg-[#0B0F17] shrink-0">
            <History className="h-4 w-4 text-emerald-400" aria-hidden="true" />
          </div>
          <div>
            <h2
              id="archive-history-heading"
              className="text-sm font-semibold text-slate-100"
            >
              Archive History
            </h2>
            <p className="mt-0.5 text-xs text-slate-400 font-mono">
              {entries.length} {entries.length === 1 ? 'operation' : 'operations'} logged in localStorage · {encryptCount} locked/packed · {decryptCount} unlocked/unpacked
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-[#0B0F17] p-1">
            {(
              [
                { id: 'all', label: 'All' },
                { id: 'encrypt', label: 'Encrypted / Packed' },
                { id: 'decrypt', label: 'Decrypted / Unpacked' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFilter(tab.id)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap ${
                  filter === tab.id
                    ? 'bg-slate-800 text-slate-50'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {entries.length > 0 && (
            <>
              <div className="relative">
                <Search
                  className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500"
                  aria-hidden="true"
                />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search history..."
                  aria-label="Search archive history"
                  className="w-40 rounded-lg border border-slate-700 bg-[#0B0F17] py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder:text-slate-500 focus:border-emerald-500 focus:outline-none"
                />
              </div>

              <button
                type="button"
                onClick={handleExportJson}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
              >
                <Download className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
                Export JSON
              </button>

              <button
                type="button"
                onClick={onClearAll}
                className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium text-slate-400 hover:text-rose-400 transition-colors whitespace-nowrap shrink-0"
              >
                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                Clear History
              </button>
            </>
          )}
        </div>
      </div>

      {entries.length === 0 ? (
        <div className="px-6 py-10 text-center">
          <p className="text-xs font-medium text-slate-300">
            No archive operations recorded yet
          </p>
          <p className="mt-1 text-xs text-slate-500">
            Encrypt, pack, decrypt, or extract an archive above to save a timestamped local record in localStorage.
          </p>
        </div>
      ) : (
        <div className="max-h-[340px] overflow-auto">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-[#111722] z-10">
              <tr className="border-b border-slate-800/80 text-slate-400">
                <th className="px-6 py-3 font-medium">Operation</th>
                <th className="px-4 py-3 font-medium">Archive</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium text-right">Files / Size</th>
                <th className="px-4 py-3 font-medium">Integrity / SHA-256</th>
                <th className="px-4 py-3 font-medium">Timestamp</th>
                <th className="px-6 py-3 font-medium text-right">Remove</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEntries.map((item) => {
                const isEncrypt = item.operation === 'encrypt';
                return (
                  <tr
                    key={item.id}
                    className="h-[48px] hover:bg-slate-800/30 transition-colors"
                  >
                    <td className="px-6 py-2.5 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center gap-1.5 font-medium ${
                          item.integrityStatus === 'failed'
                            ? 'text-rose-400'
                            : isEncrypt
                              ? 'text-emerald-400'
                              : 'text-sky-400'
                        }`}
                      >
                        {isEncrypt ? (
                          <Lock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        ) : (
                          <Unlock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                        )}
                        {isEncrypt
                          ? item.encrypted
                            ? 'Encrypted'
                            : 'Packed'
                          : item.encrypted
                            ? 'Decrypted'
                            : 'Extracted'}
                      </span>
                    </td>

                    <td className="px-4 py-2.5 max-w-[240px]">
                      <div className="font-mono text-slate-100 truncate">
                        {item.filename}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate">
                        {item.compressionSummary}
                      </div>
                    </td>

                    <td className="px-4 py-2.5 whitespace-nowrap font-mono text-slate-200">
                      {item.archiveType}
                      <span className="ml-1.5 text-[11px] text-slate-500">
                        ({item.encrypted ? 'locked' : 'open'})
                      </span>
                    </td>

                    <td className="px-4 py-2.5 text-right font-mono text-slate-300 whitespace-nowrap">
                      {item.entryCount} {item.entryCount === 1 ? 'file' : 'files'} ·{' '}
                      {formatBytes(item.sizeBytes)}
                    </td>

                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <div className="flex items-center gap-2 font-mono">
                        {item.integrityStatus === 'failed' ? (
                          <ShieldAlert
                            className="h-3.5 w-3.5 text-rose-400 shrink-0"
                            aria-hidden="true"
                          />
                        ) : (
                          <ShieldCheck
                            className={`h-3.5 w-3.5 shrink-0 ${
                              item.integrityStatus === 'verified'
                                ? 'text-emerald-400'
                                : 'text-slate-400'
                            }`}
                            aria-hidden="true"
                          />
                        )}
                        <span className="text-[11px] text-slate-300">
                          {item.sha256 ? `${item.sha256.slice(0, 12)}...` : '—'}
                        </span>
                        {item.sha256 && (
                          <button
                            type="button"
                            onClick={() => handleCopySha(item.id, item.sha256)}
                            aria-label={`Copy SHA-256 for ${item.filename}`}
                            className="text-slate-500 hover:text-emerald-400 transition-colors"
                          >
                            {copiedId === item.id ? (
                              <Check className="h-3 w-3 text-emerald-400" aria-hidden="true" />
                            ) : (
                              <Copy className="h-3 w-3" aria-hidden="true" />
                            )}
                          </button>
                        )}
                      </div>
                    </td>

                    <td
                      className="px-4 py-2.5 font-mono text-[11px] text-slate-400 whitespace-nowrap"
                      title={item.timestamp}
                    >
                      {formatTimestamp(item.timestamp)}
                    </td>

                    <td className="px-6 py-2.5 text-right">
                      <button
                        type="button"
                        onClick={() => onDeleteItem(item.id)}
                        aria-label={`Delete history entry for ${item.filename}`}
                        className="p-1 text-slate-500 hover:text-rose-400 transition-colors"
                      >
                        <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    </td>
                  </tr>
                );
              })}

              {filteredEntries.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-slate-400">
                    No history records match the active filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
