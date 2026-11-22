import { useState } from 'react';
import { TopBar, ActiveSection } from './components/TopBar';
import { EncryptWorkbench } from './components/EncryptWorkbench';
import { DecryptWorkbench } from './components/DecryptWorkbench';
import { LinuxAppSection } from './components/LinuxAppSection';
import { FormatSpecSection } from './components/FormatSpecSection';
import { ArchiveHistoryPanel } from './components/ArchiveHistoryPanel';
import { downloadLinuxBundleZip } from './lib/linuxAppSource';
import { downloadUbuntuDeb } from './lib/debBuilder';
import {
  ArchiveHistoryEntry,
  NewArchiveHistoryEntry,
  appendArchiveHistory,
  clearArchiveHistory,
  deleteArchiveHistoryItem,
  loadArchiveHistory,
} from './lib/archiveHistory';

export default function App() {
  const [activeSection, setActiveSection] = useState<ActiveSection>('lock');
  const [historyEntries, setHistoryEntries] = useState<ArchiveHistoryEntry[]>(() =>
    loadArchiveHistory()
  );
  const [incomingArchive, setIncomingArchive] = useState<{
    bytes: Uint8Array<ArrayBuffer>;
    filename: string;
    expectedSha256?: string;
  } | null>(null);

  const handleRecordHistory = (entry: NewArchiveHistoryEntry) => {
    setHistoryEntries(appendArchiveHistory(entry));
  };

  const handleDeleteHistoryItem = (id: string) => {
    setHistoryEntries(deleteArchiveHistoryItem(id));
  };

  const handleClearHistory = () => {
    setHistoryEntries(clearArchiveHistory());
  };

  const handleSendArchiveToUnlock = (
    bytes: Uint8Array<ArrayBuffer>,
    filename: string,
    expectedSha256: string
  ) => {
    setIncomingArchive({ bytes, filename, expectedSha256 });
    setActiveSection('unlock');
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#0B0F17] text-slate-100">
      <TopBar
        activeSection={activeSection}
        onSelectSection={setActiveSection}
        onDownloadBundle={downloadUbuntuDeb}
      />

      <main className="mx-auto w-full max-w-[1280px] flex-1 px-6 py-8 space-y-8">
        <div className="flex flex-col gap-4 border-b border-slate-800/80 pb-6 md:flex-row md:items-end md:justify-between">
          <div className="max-w-2xl space-y-1.5">
            <h1 className="text-2xl font-bold tracking-tight text-slate-50 text-balance">
              Linux Multi-Format Compression &amp; Archive Lock
            </h1>
            <p className="text-sm text-slate-400">
              Pack and extract .klock (AES-256-GCM), .rar / UnRAR, .7z, .zip, .gz / .tar.gz, .bz2, and .xz archives — with or without passwords, SHA-256 integrity checks, and the native Linux GTK4 + CLI bundle.
            </p>
          </div>

          <div className="flex items-center gap-1 rounded-lg border border-slate-800 bg-[#111722] p-1 self-start md:self-auto shrink-0">
            <button
              type="button"
              onClick={() => setActiveSection('lock')}
              className={`rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                activeSection === 'lock'
                  ? 'bg-slate-800 text-slate-50'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Pack &amp; Lock
            </button>
            <button
              type="button"
              onClick={() => setActiveSection('unlock')}
              className={`rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                activeSection === 'unlock'
                  ? 'bg-slate-800 text-slate-50'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Unpack &amp; Unlock
            </button>
            <button
              type="button"
              onClick={() => setActiveSection('linux')}
              className={`rounded-md px-3.5 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                activeSection === 'linux'
                  ? 'bg-slate-800 text-slate-50'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Native Linux App
            </button>
          </div>
        </div>

        {activeSection === 'lock' && (
          <EncryptWorkbench
            onSendArchiveToUnlock={handleSendArchiveToUnlock}
            onRecordHistory={handleRecordHistory}
          />
        )}
        {activeSection === 'unlock' && (
          <DecryptWorkbench
            incomingArchive={incomingArchive}
            onRecordHistory={handleRecordHistory}
          />
        )}
        {(activeSection === 'lock' || activeSection === 'unlock') && (
          <ArchiveHistoryPanel
            entries={historyEntries}
            onDeleteItem={handleDeleteHistoryItem}
            onClearAll={handleClearHistory}
          />
        )}
        {activeSection === 'linux' && (
          <LinuxAppSection
            onDownloadDeb={downloadUbuntuDeb}
            onDownloadBundle={downloadLinuxBundleZip}
          />
        )}
        {activeSection === 'spec' && <FormatSpecSection />}
      </main>

      <footer className="border-t border-slate-800/80 py-6">
        <div className="mx-auto flex max-w-[1280px] flex-wrap items-center justify-between gap-4 px-6 text-xs text-slate-500">
          <span>
            KryptLock · KLOCK001 (AES-256-GCM) · RAR / UnRAR · 7-Zip · ZIP · Gzip · Bzip2 · XZ · SHA-256
          </span>
          <div className="flex items-center gap-6">
            <button
              type="button"
              onClick={() => setActiveSection('linux')}
              className="hover:text-slate-300 transition-colors"
            >
              Linux Installer
            </button>
            <button
              type="button"
              onClick={() => setActiveSection('spec')}
              className="hover:text-slate-300 transition-colors"
            >
              KLOCK001 Spec
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
