import { useState } from 'react';
import {
  AlertCircle,
  Check,
  Copy,
  Download,
  FolderLock,
  Monitor,
  Package,
  Terminal,
} from 'lucide-react';
import { LINUX_BUNDLE_FILES } from '../lib/linuxAppSource';
import { InstallationVerification } from './InstallationVerification';

interface LinuxAppSectionProps {
  onDownloadDeb: () => void;
  onDownloadBundle: () => void;
}

type DistroId = 'ubuntu-deb' | 'ubuntu-zip' | 'fedora' | 'arch';

const DISTRO_COMMANDS: Record<
  DistroId,
  {
    label: string;
    step1Title: string;
    step1Command: string;
    step2Title: string;
    step2Command: string;
    note: string;
  }
> = {
  'ubuntu-deb': {
    label: 'Ubuntu / Debian (.deb)',
    step1Title: '01. Install .deb package & dependencies automatically',
    step1Command:
      'cd ~/Downloads && sudo apt update && sudo apt install -y ./kryptlock_1.0.0_all.deb',
    step2Title: '02. Verify backends & launch GUI (or open from App Grid)',
    step2Command: 'kryptlock formats && kryptlock-gui',
    note: 'Installs /usr/bin/kryptlock, /usr/bin/kryptlock-gui, desktop launcher icon, MIME handlers, and Python/GTK4 packages automatically. For .rar creation, also run: sudo apt install -y unrar rar',
  },
  'ubuntu-zip': {
    label: 'Portable .zip (Ubuntu)',
    step1Title: '01. Install unzip, cryptography & GTK4 libraries',
    step1Command:
      'sudo apt update && sudo apt install -y unzip python3 python3-cryptography python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 python3-tk p7zip-full unrar rar xdg-utils',
    step2Title: '02. Unpack bundle in ~/Downloads & run installer',
    step2Command:
      'cd ~/Downloads && unzip -o kryptlock-linux-bundle.zip && bash kryptlock-linux/install.sh',
    note: 'Configures ~/.local/bin in ~/.bashrc, writes absolute Exec paths in your .desktop file, and runs kryptlock formats automatically.',
  },
  fedora: {
    label: 'Fedora / RHEL',
    step1Title: '01. Install unzip, cryptography & GTK4 libraries',
    step1Command:
      'sudo dnf install -y unzip python3 python3-cryptography python3-gobject gtk4 libadwaita p7zip p7zip-plugins unrar xdg-utils',
    step2Title: '02. Unpack bundle in ~/Downloads & run installer',
    step2Command:
      'cd ~/Downloads && unzip -o kryptlock-linux-bundle.zip && bash kryptlock-linux/install.sh',
    note: 'Installs the GTK4/Libadwaita app and CLI into ~/.local/bin with desktop and MIME integration.',
  },
  arch: {
    label: 'Arch / Manjaro',
    step1Title: '01. Install unzip, cryptography & GTK4 libraries',
    step1Command:
      'sudo pacman -S --needed unzip python python-cryptography python-gobject gtk4 libadwaita 7zip unrar xdg-utils',
    step2Title: '02. Unpack bundle in ~/Downloads & run installer',
    step2Command:
      'cd ~/Downloads && unzip -o kryptlock-linux-bundle.zip && bash kryptlock-linux/install.sh',
    note: 'Installs the GTK4/Libadwaita app and CLI into ~/.local/bin with desktop and MIME integration.',
  },
};

export function LinuxAppSection({
  onDownloadDeb,
  onDownloadBundle,
}: LinuxAppSectionProps) {
  const [selectedDistro, setSelectedDistro] = useState<DistroId>('ubuntu-deb');
  const [selectedFilename, setSelectedFilename] = useState(
    LINUX_BUNDLE_FILES[0].filename
  );
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const activeFile =
    LINUX_BUNDLE_FILES.find((f) => f.filename === selectedFilename) ||
    LINUX_BUNDLE_FILES[0];

  const copyText = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => {
        setCopiedKey((prev) => (prev === key ? null : prev));
      }, 1800);
    } catch {
      // Clipboard API restricted; no-op fallback
    }
  };

  const distro = DISTRO_COMMANDS[selectedDistro];

  return (
    <div className="space-y-8">
      {/* Overview + Download Actions */}
      <div className="flex flex-col gap-6 rounded-xl border border-slate-800 bg-[#111722] p-6 lg:flex-row lg:items-center lg:justify-between">
        <div className="max-w-2xl space-y-2">
          <h2 className="text-xl font-bold tracking-tight text-slate-50 text-balance">
            Native Ubuntu &amp; Linux Desktop Application
          </h2>
          <p className="text-sm leading-relaxed text-slate-400">
            Install KryptLock like a standard Ubuntu app via the <span className="font-mono text-slate-200">.deb</span> installer (recommended) or portable <span className="font-mono text-slate-200">.zip</span> bundle. Supports .klock, .rar / UnRAR, .7z, .zip, .tar.gz, .tar.bz2, and .tar.xz with GTK4/Libadwaita UI, CLI, and Nautilus right-click actions.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={onDownloadDeb}
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400 transition-colors whitespace-nowrap shrink-0"
          >
            <Package className="h-4 w-4" aria-hidden="true" />
            Download Ubuntu .deb
          </button>

          <button
            type="button"
            onClick={onDownloadBundle}
            className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800/70 px-4 py-2.5 text-sm font-medium text-slate-100 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
          >
            <Download className="h-4 w-4 text-slate-300" aria-hidden="true" />
            Portable Bundle (.zip)
          </button>
        </div>
      </div>

      {/* Three Native Capabilities */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-[#111722] p-6 space-y-2">
          <div className="flex items-center gap-2.5 text-slate-100">
            <Monitor className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
            <h3 className="text-sm font-semibold">GTK4 + Tkinter Desktop GUI</h3>
          </div>
          <p className="text-xs leading-relaxed text-slate-400">
            Native Adwaita window supporting .klock, .rar, .7z, .zip, .tar.gz, .tar.bz2, and .tar.xz with optional password encryption and xdg-email attachment composing.
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#111722] p-6 space-y-2">
          <div className="flex items-center gap-2.5 text-slate-100">
            <Terminal className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
            <h3 className="text-sm font-semibold">Multi-Format Python CLI</h3>
          </div>
          <p className="text-xs leading-relaxed text-slate-400">
            Run <span className="font-mono text-slate-200">kryptlock pack</span> and <span className="font-mono text-slate-200">kryptlock unpack</span> across RAR/UnRAR, 7-Zip, AES-256 ZIP, Gzip, Bzip2, XZ, and KLOCK001 with SHA-256 verification.
          </p>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#111722] p-6 space-y-2">
          <div className="flex items-center gap-2.5 text-slate-100">
            <FolderLock className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
            <h3 className="text-sm font-semibold">Ubuntu Launcher &amp; MIME</h3>
          </div>
          <p className="text-xs leading-relaxed text-slate-400">
            Registers the KryptLock app icon, desktop launcher, MIME associations for .klock/.rar/.7z/.zip/.gz/.xz, and Nautilus right-click actions.
          </p>
        </div>
      </div>

      {/* Distro Setup Commands */}
      <div className="rounded-xl border border-slate-800 bg-[#111722] p-6 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <h3 className="text-sm font-semibold text-slate-100">
            Install on Your Linux Distribution
          </h3>
          <div className="flex flex-wrap items-center gap-1 rounded-lg border border-slate-800 bg-[#0B0F17] p-1">
            {(Object.keys(DISTRO_COMMANDS) as DistroId[]).map((id) => (
              <button
                key={id}
                type="button"
                onClick={() => setSelectedDistro(id)}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap shrink-0 ${
                  selectedDistro === id
                    ? 'bg-slate-800 text-slate-50'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {DISTRO_COMMANDS[id].label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>{distro.step1Title}</span>
              <button
                type="button"
                onClick={() => copyText('step1', distro.step1Command)}
                className="inline-flex items-center gap-1 text-slate-300 hover:text-emerald-400 transition-colors whitespace-nowrap shrink-0"
              >
                {copiedKey === 'step1' ? (
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
            <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-[#0B0F17] p-3.5 font-mono text-xs text-emerald-300">
              {distro.step1Command}
            </pre>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>{distro.step2Title}</span>
              <button
                type="button"
                onClick={() => copyText('step2', distro.step2Command)}
                className="inline-flex items-center gap-1 text-slate-300 hover:text-emerald-400 transition-colors whitespace-nowrap shrink-0"
              >
                {copiedKey === 'step2' ? (
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
            <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-[#0B0F17] p-3.5 font-mono text-xs text-slate-200">
              {distro.step2Command}
            </pre>
          </div>
        </div>

        <p className="text-xs text-slate-400">{distro.note}</p>

        {/* Copy-paste troubleshooting banner */}
        <div className="flex items-start gap-3 border-t border-slate-800/80 pt-4 text-xs text-slate-400">
          <AlertCircle className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
          <div className="space-y-1">
            <p className="text-slate-200 font-medium">
              Nothing happened when pasting commands into Terminal?
            </p>
            <p>
              Do not paste the word <span className="font-mono text-slate-200">bash</span> by itself on the first line—typing <span className="font-mono text-slate-200">bash</span> starts an empty subshell so <span className="font-mono text-slate-200">unzip</span> never runs. Use the <strong className="text-slate-200">Copy</strong> button above, which copies a single clean terminal line with no markdown header.
            </p>
          </div>
        </div>
      </div>

      {/* Installation Verification */}
      <InstallationVerification />

      {/* Bundle Source Code Inspector */}
      <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#111722]">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 px-6 py-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              Inspect Native Bundle Source Files
            </h3>
            <p className="mt-0.5 text-xs text-slate-400 font-mono">
              {LINUX_BUNDLE_FILES.length} files packaged across .deb and .zip distributions
            </p>
          </div>

          <button
            type="button"
            onClick={() => copyText(activeFile.filename, activeFile.content)}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/70 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
          >
            {copiedKey === activeFile.filename ? (
              <>
                <Check className="h-3.5 w-3.5 text-emerald-400" aria-hidden="true" />
                Copied {activeFile.filename}
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                Copy {activeFile.filename}
              </>
            )}
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12">
          <div className="lg:col-span-3 border-b lg:border-b-0 lg:border-r border-slate-800 p-3 space-y-1">
            {LINUX_BUNDLE_FILES.map((file) => {
              const isSelected = file.filename === activeFile.filename;
              return (
                <button
                  key={file.filename}
                  type="button"
                  onClick={() => setSelectedFilename(file.filename)}
                  className={`w-full rounded-lg px-3 py-2 text-left transition-colors ${
                    isSelected
                      ? 'bg-slate-800 text-slate-50'
                      : 'text-slate-400 hover:bg-slate-800/40 hover:text-slate-200'
                  }`}
                >
                  <div className="font-mono text-xs font-medium truncate">
                    {file.filename}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5 truncate">
                    {file.label}
                  </div>
                </button>
              );
            })}
          </div>

          <div className="lg:col-span-9 bg-[#0B0F17] max-h-[480px] overflow-auto p-5">
            <pre className="font-mono text-xs leading-relaxed text-slate-300 whitespace-pre">
              {activeFile.content}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
