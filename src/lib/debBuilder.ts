import { gzipSync, strToU8 } from 'fflate';
import {
  DEB_CONTROL_TEMPLATE,
  DEB_POSTINST,
  DEB_POSTRM,
  KRYPTLOCK_DESKTOP_TEMPLATE,
  KRYPTLOCK_GUI_PY,
  KRYPTLOCK_MIME_XML,
  KRYPTLOCK_PY,
  KRYPTLOCK_SVG,
} from './linuxAppSource';

interface TarEntry {
  path: string;
  mode: number;
  type: '0' | '5';
  content?: Uint8Array;
}

function writeAscii(buf: Uint8Array, offset: number, length: number, text: string): void {
  const bytes = strToU8(text);
  const limit = Math.min(bytes.length, length);
  for (let i = 0; i < limit; i++) {
    buf[offset + i] = bytes[i];
  }
}

function writeOctal(buf: Uint8Array, offset: number, length: number, value: number): void {
  const digits = length - 1;
  const oct = Math.max(0, Math.floor(value)).toString(8).padStart(digits, '0').slice(-digits);
  writeAscii(buf, offset, digits, oct);
  buf[offset + digits] = 0;
}

function buildUstarTar(entries: TarEntry[], mtimeSec: number): Uint8Array {
  const blocks: Uint8Array[] = [];

  for (const entry of entries) {
    const header = new Uint8Array(512);
    const data = entry.type === '0' && entry.content ? entry.content : new Uint8Array(0);

    writeAscii(header, 0, 100, entry.path);
    writeOctal(header, 100, 8, entry.mode);
    writeOctal(header, 108, 8, 0);
    writeOctal(header, 116, 8, 0);
    writeOctal(header, 124, 12, data.byteLength);
    writeOctal(header, 136, 12, mtimeSec);

    // Checksum field must be ASCII spaces during sum calculation
    for (let i = 148; i < 156; i++) {
      header[i] = 0x20;
    }

    header[156] = entry.type.charCodeAt(0);
    writeAscii(header, 257, 6, 'ustar');
    header[262] = 0;
    writeAscii(header, 263, 2, '00');
    writeAscii(header, 265, 32, 'root');
    writeAscii(header, 297, 32, 'root');

    let sum = 0;
    for (let i = 0; i < 512; i++) {
      sum += header[i];
    }
    const chk = sum.toString(8).padStart(6, '0').slice(-6);
    writeAscii(header, 148, 6, chk);
    header[154] = 0;
    header[155] = 0x20;

    blocks.push(header);

    if (data.byteLength > 0) {
      const paddedSize = Math.ceil(data.byteLength / 512) * 512;
      const body = new Uint8Array(paddedSize);
      body.set(data, 0);
      blocks.push(body);
    }
  }

  // Standard 1024-byte EOF trailer (two 512-byte zero blocks)
  blocks.push(new Uint8Array(1024));

  const totalSize = blocks.reduce((acc, chunk) => acc + chunk.byteLength, 0);
  const out = new Uint8Array(totalSize);
  let pos = 0;
  for (const chunk of blocks) {
    out.set(chunk, pos);
    pos += chunk.byteLength;
  }
  return out;
}

function buildArArchive(members: Array<{ name: string; data: Uint8Array }>, mtimeSec: number): Uint8Array<ArrayBuffer> {
  const magic = strToU8('!<arch>\n');
  const chunks: Uint8Array[] = [magic];

  for (const member of members) {
    const headerStr =
      member.name.padEnd(16, ' ').slice(0, 16) +
      String(mtimeSec).padEnd(12, ' ').slice(0, 12) +
      '0     ' +
      '0     ' +
      '100644  ' +
      String(member.data.byteLength).padEnd(10, ' ').slice(0, 10) +
      '`\n';

    const headerBytes = strToU8(headerStr);
    chunks.push(headerBytes);
    chunks.push(member.data);
    if (member.data.byteLength % 2 === 1) {
      chunks.push(new Uint8Array([0x0a]));
    }
  }

  const totalBytes = chunks.reduce((acc, c) => acc + c.byteLength, 0);
  const buffer = new ArrayBuffer(totalBytes);
  const out = new Uint8Array(buffer);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

export function buildUbuntuDebBytes(): Uint8Array<ArrayBuffer> {
  const mtimeSec = Math.floor(Date.now() / 1000);

  const cliWrapper = strToU8(
    '#!/usr/bin/env bash\nPYTHONPATH="/usr/share/kryptlock" exec python3 "/usr/share/kryptlock/kryptlock.py" "$@"\n'
  );
  const guiWrapper = strToU8(
    '#!/usr/bin/env bash\nPYTHONPATH="/usr/share/kryptlock" exec python3 "/usr/share/kryptlock/kryptlock_gui.py" "$@"\n'
  );

  const kryptlockPyBytes = strToU8(KRYPTLOCK_PY);
  const kryptlockGuiBytes = strToU8(KRYPTLOCK_GUI_PY);
  const desktopBytes = strToU8(KRYPTLOCK_DESKTOP_TEMPLATE);
  const mimeBytes = strToU8(KRYPTLOCK_MIME_XML);
  const svgBytes = strToU8(KRYPTLOCK_SVG);

  const dataEntries: TarEntry[] = [
    { path: './', mode: 0o755, type: '5' },
    { path: './usr/', mode: 0o755, type: '5' },
    { path: './usr/bin/', mode: 0o755, type: '5' },
    { path: './usr/bin/kryptlock', mode: 0o755, type: '0', content: cliWrapper },
    { path: './usr/bin/kryptlock-gui', mode: 0o755, type: '0', content: guiWrapper },
    { path: './usr/share/', mode: 0o755, type: '5' },
    { path: './usr/share/kryptlock/', mode: 0o755, type: '5' },
    { path: './usr/share/kryptlock/kryptlock.py', mode: 0o755, type: '0', content: kryptlockPyBytes },
    { path: './usr/share/kryptlock/kryptlock_gui.py', mode: 0o755, type: '0', content: kryptlockGuiBytes },
    { path: './usr/share/applications/', mode: 0o755, type: '5' },
    { path: './usr/share/applications/kryptlock.desktop', mode: 0o644, type: '0', content: desktopBytes },
    { path: './usr/share/mime/', mode: 0o755, type: '5' },
    { path: './usr/share/mime/packages/', mode: 0o755, type: '5' },
    { path: './usr/share/mime/packages/kryptlock-mime.xml', mode: 0o644, type: '0', content: mimeBytes },
    { path: './usr/share/icons/', mode: 0o755, type: '5' },
    { path: './usr/share/icons/hicolor/', mode: 0o755, type: '5' },
    { path: './usr/share/icons/hicolor/scalable/', mode: 0o755, type: '5' },
    { path: './usr/share/icons/hicolor/scalable/apps/', mode: 0o755, type: '5' },
    { path: './usr/share/icons/hicolor/scalable/apps/kryptlock.svg', mode: 0o644, type: '0', content: svgBytes },
  ];

  const installedKb = dataEntries.reduce(
    (sum, item) => sum + (item.content ? Math.max(1, Math.ceil(item.content.byteLength / 1024)) : 0),
    0
  );

  const controlText = DEB_CONTROL_TEMPLATE.replace(
    'Depends:',
    `Installed-Size: ${installedKb}\nDepends:`
  );

  const controlEntries: TarEntry[] = [
    { path: './', mode: 0o755, type: '5' },
    { path: './control', mode: 0o644, type: '0', content: strToU8(controlText) },
    { path: './postinst', mode: 0o755, type: '0', content: strToU8(DEB_POSTINST) },
    { path: './postrm', mode: 0o755, type: '0', content: strToU8(DEB_POSTRM) },
  ];

  const debianBinary = strToU8('2.0\n');
  const controlTarGz = gzipSync(buildUstarTar(controlEntries, mtimeSec), { level: 9 });
  const dataTarGz = gzipSync(buildUstarTar(dataEntries, mtimeSec), { level: 9 });

  return buildArArchive(
    [
      { name: 'debian-binary', data: debianBinary },
      { name: 'control.tar.gz', data: controlTarGz },
      { name: 'data.tar.gz', data: dataTarGz },
    ],
    mtimeSec
  );
}

export function downloadUbuntuDeb(): void {
  const debBytes = buildUbuntuDebBytes();
  const blob = new Blob([debBytes], { type: 'application/vnd.debian.binary-package' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'kryptlock_1.0.0_all.deb';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
