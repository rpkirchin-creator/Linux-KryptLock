import { ShieldCheck, FileLock2, KeyRound, Binary } from 'lucide-react';

const BINARY_FIELDS = [
  {
    offset: '0x00 .. 0x07',
    length: '8 bytes',
    field: 'Magic Signature',
    description: 'ASCII literal "KLOCK001" identifying container format version 1.',
  },
  {
    offset: '0x08',
    length: '1 byte',
    field: 'Compression Algorithm',
    description:
      '0x01 = Zlib Deflate, 0x02 = Store (uncompressed), 0x03 = Gzip, 0x04 = Bzip2, 0x05 = LZMA.',
  },
  {
    offset: '0x09 .. 0x0C',
    length: '4 bytes',
    field: 'PBKDF2 Iterations',
    description: 'Big-endian uint32 iteration count (default 600,000 rounds of HMAC-SHA256).',
  },
  {
    offset: '0x0D .. 0x1C',
    length: '16 bytes',
    field: 'KDF Salt',
    description: '128-bit CSPRNG salt uniquely generated per archive.',
  },
  {
    offset: '0x1D .. 0x28',
    length: '12 bytes',
    field: 'AES-GCM Nonce (IV)',
    description: '96-bit CSPRNG initialization vector for AES-256-GCM.',
  },
  {
    offset: '0x29 .. EOF',
    length: 'Variable + 16 B tag',
    field: 'Authenticated Ciphertext',
    description:
      'Encrypted inner container (JSON manifest with SHA-256 checksums + file payloads) + 128-bit GCM tag.',
  },
];

const SECURITY_GUARANTEES = [
  {
    icon: FileLock2,
    title: 'Multi-Algorithm Pre-Encryption Compression',
    body: 'Payloads are compressed using Zlib Deflate, Gzip, Bzip2, LZMA, or Store before encryption, reducing ciphertext size without leaking plaintext patterns.',
  },
  {
    icon: ShieldCheck,
    title: 'Multi-Layer SHA-256 & GCM Integrity',
    body: 'Every archive generates an outer .klock SHA-256 checksum (.sha256 sidecar), binds the 41-byte header as AES-GCM AAD, and verifies per-file SHA-256 digests upon decryption.',
  },
  {
    icon: KeyRound,
    title: 'Password Strength & Keyfile 2FA',
    body: 'Password-based encryption derives 256-bit keys with 600,000 PBKDF2-HMAC-SHA256 rounds, real-time entropy estimation, and optional 512-bit keyfile mixing.',
  },
  {
    icon: Binary,
    title: 'Multi-Format Compatibility (RAR / 7z / ZIP / Gzip / XZ)',
    body: 'Alongside KLOCK001, KryptLock unpacks .rar (UnRAR WASM & Linux unrar), creates/extracts .7z and .zip with or without passwords, and handles .tar.gz, .gz, .tar.bz2, and .tar.xz.',
  },
];

export function FormatSpecSection() {
  return (
    <section className="space-y-8">
      <div className="max-w-3xl space-y-2">
        <h2 className="text-2xl font-bold tracking-tight text-slate-50 text-balance">
          Supported Archive Formats &amp; KLOCK001 Specification
        </h2>
        <p className="text-sm leading-relaxed text-slate-400">
          Every .klock archive combines selectable compression (Deflate, Gzip, Bzip2, LZMA, or Store) with authenticated AES-256-GCM encryption and SHA-256 verification. The workbench and Linux bundle also handle .rar, .7z, .zip, .gz/.tar.gz, .bz2, and .xz archives.
        </p>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#111722]">
        <div className="border-b border-slate-800 px-6 py-4">
          <h3 className="text-sm font-semibold text-slate-100">
            Binary Header &amp; Payload Layout
          </h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800/80 text-xs text-slate-400">
                <th className="px-6 py-3 font-medium">Byte Offset</th>
                <th className="px-6 py-3 font-medium">Length</th>
                <th className="px-6 py-3 font-medium">Field</th>
                <th className="px-6 py-3 font-medium">Specification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {BINARY_FIELDS.map((row) => (
                <tr key={row.offset} className="hover:bg-slate-800/30 transition-colors">
                  <td className="px-6 py-3.5 font-mono text-xs text-emerald-400 whitespace-nowrap">
                    {row.offset}
                  </td>
                  <td className="px-6 py-3.5 font-mono text-xs text-slate-300 whitespace-nowrap">
                    {row.length}
                  </td>
                  <td className="px-6 py-3.5 font-medium text-slate-100 whitespace-nowrap">
                    {row.field}
                  </td>
                  <td className="px-6 py-3.5 text-xs leading-relaxed text-slate-400">
                    {row.description}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {SECURITY_GUARANTEES.map((item) => {
          const Icon = item.icon;
          return (
            <div
              key={item.title}
              className="rounded-xl border border-slate-800 bg-[#111722] p-6 space-y-2.5"
            >
              <div className="flex items-center gap-2.5">
                <Icon className="h-4 w-4 text-emerald-400 shrink-0" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-slate-100">{item.title}</h3>
              </div>
              <p className="text-sm leading-relaxed text-slate-400">{item.body}</p>
            </div>
          );
        })}
      </div>
    </section>
  );
}
