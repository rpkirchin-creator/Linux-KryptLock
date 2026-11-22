# KryptLock — Linux Multi-Format Compression & Encrypted Archive Utility

KryptLock packs, locks, verifies, and extracts **`.klock` (`KLOCK001` AES-256-GCM)**, **`.rar` (RAR & UnRAR with or without passwords)**, **`.7z` (7-Zip with or without AES-256 + header encryption)**, **`.zip` (with or without AES-256 / ZipCrypto)**, **`.gz` / `.tar.gz` / `.tgz`**, **`.bz2` / `.tar.bz2`**, **`.xz` / `.tar.xz`**, and **`.tar`** archives.

It includes:
1. **Native Linux Desktop GUI & CLI** (`kryptlock-linux-bundle.zip`) built with Python 3, `cryptography`, GTK4/Libadwaita (with automatic Tkinter fallback), `rar`/`unrar`, `7z`, Nautilus right-click integration, and `xdg-email` attachment support.
2. **Local Browser Workbench** using WebAssembly (`7z-wasm`, `node-unrar-js` UnRAR WASM) + `@zip.js/zip.js` + W3C Web Crypto API (`AES-GCM` / `PBKDF2` / `SHA-256`).

---

## Requirements

### Native Linux Desktop & CLI
- **Operating System**: Any modern Linux distribution (Ubuntu 22.04+, Debian 12+, Linux Mint 21+, Fedora 39+, Arch Linux, Manjaro, Pop!_OS)
- **Python**: Python 3.9 or newer
- **Display Server (GUI)**: Wayland or X11 (for GTK4/Libadwaita or Tkinter window)
- **Email Client Integration (Optional)**: `xdg-utils` (`xdg-email`) or `thunderbird` for attaching archives directly to an email draft

### Web Workbench (Optional Local Browser Sandbox)
- **Node.js & npm**: Node.js `v20.20.2` and `npm` `10.8.2`
- **Architecture**: `x86_64` (uses Rollup-based Vite 6 `vite@^6.4.6` + `@vitejs/plugin-react@^4.7.0` + TypeScript 5.8, avoiding Vite 8/Rolldown native AVX requirements)
- **Browser**: Chromium, Firefox, GNOME Web, or Edge with WebAssembly + Web Crypto API (`window.crypto.subtle`)

---

## Dependencies

### Linux System & Python Dependencies
| Dependency | Debian / Ubuntu Package | Purpose |
| :--- | :--- | :--- |
| Python Cryptography | `python3-cryptography` | `AESGCM`, `PBKDF2HMAC`, SHA-256 for `.klock` |
| GTK4 + Libadwaita | `python3-gi gir1.2-gtk-4.0 gir1.2-adw-1` | Native GNOME/Adwaita desktop GUI |
| Tkinter (Fallback) | `python3-tk` | Automatic fallback GUI if GTK4 is unavailable |
| 7-Zip | `p7zip-full` (or `7zip`) | Create & extract `.7z` and AES-256 `.zip` archives |
| RAR / UnRAR | `rar unrar` (or `unar`) | Create `.rar` and extract/unrar `.rar` (with/without passwords) |
| XDG Email / Desktop | `xdg-utils` | `xdg-email --attach` & desktop/MIME integration |
| Zenity (Optional) | `zenity` | Interactive prompts for Nautilus right-click script |
| Compression Codecs | Built into Python 3 stdlib | `zipfile`, `tarfile`, `gzip`, `bz2`, `lzma`, `zlib` |

Install system dependencies on Linux:

- **Ubuntu / Debian / Linux Mint / Pop!_OS**
  ```bash
  sudo apt update
  sudo apt install -y python3 python3-cryptography python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 p7zip-full unrar rar xdg-utils
  ```

- **Fedora / RHEL**
  ```bash
  sudo dnf install -y python3 python3-cryptography python3-gobject gtk4 libadwaita p7zip p7zip-plugins unrar xdg-utils
  ```

- **Arch Linux / Manjaro**
  ```bash
  sudo pacman -S --needed python python-cryptography python-gobject gtk4 libadwaita 7zip unrar xdg-utils
  ```

### Web Workbench Dependencies (`package.json`)
- `react`, `react-dom` — UI runtime
- `7z-wasm` — Emscripten WebAssembly 7-Zip (`.7z`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.xz`, `.tar`, etc.)
- `node-unrar-js` — Official UnRAR WebAssembly (`.rar` extraction with & without passwords)
- `@zip.js/zip.js` — Pure-JS `.zip` creation & extraction (AES-256, ZipCrypto, and unencrypted)
- `fflate` — Zlib Deflate, Gzip, and ZIP packaging
- `compressjs` — Pure-JS Bzip2 codec (loaded without `amdefine` via `src/lib/bzip2Codec.ts`)
- `lzma` — Pure-JS LZMA1 codec
- `lucide-react` — Interface icons
- `tailwindcss` / `@tailwindcss/vite` — Utility styling

---

## Installation

### Option A: Ubuntu / Debian `.deb` Package (Recommended)
Download `kryptlock_1.0.0_all.deb` from **Download Ubuntu .deb** (or **Download Linux App**) and run:

```bash
cd ~/Downloads && sudo apt update && sudo apt install -y ./kryptlock_1.0.0_all.deb
```

Then launch **KryptLock** from your Ubuntu Application Grid, or run:

```bash
kryptlock formats && kryptlock-gui
```

### Option B: Portable `.zip` Bundle (All Linux Distros)
Download `kryptlock-linux-bundle.zip` and run this single command from `~/Downloads` (do not type `bash` on a separate line by itself):

```bash
cd ~/Downloads && unzip -o kryptlock-linux-bundle.zip && bash kryptlock-linux/install.sh
```

This installs:
- `~/.local/bin/kryptlock` — Multi-format CLI utility
- `~/.local/bin/kryptlock-gui` — Native GTK4 / Tkinter desktop application
- `~/.local/share/applications/kryptlock.desktop` — Desktop launcher & archive handler (with absolute `Exec=` path)
- `~/.local/share/icons/hicolor/scalable/apps/kryptlock.svg` — Application icon
- `~/.local/share/mime/packages/kryptlock-mime.xml` — XDG MIME association (`application/x-kryptlock`)
- `~/.local/share/nautilus/scripts/Lock with KryptLock` — File manager right-click action

### Option C: Run the Web Workbench Locally (Node.js 20 LTS + npm)
```bash
npm install
npm run dev
# Or create and preview a production build:
npm run build
npm run preview
```

### Rebuilding the `.deb` Package After Editing Source Code
Running `npm install` only installs Node packages into `node_modules/` — it does **not** rebuild `kryptlock_1.0.0_all.deb` or update files already installed in `/usr/bin` and `/usr/share/kryptlock`. After editing `src/lib/linuxAppSource.ts` or `src/lib/debBuilder.ts` in VS Code, rebuild and reinstall the `.deb`:
```bash
npm run build:deb
sudo apt install -y ./kryptlock_1.0.0_all.deb
```
Alternatively, run `npm run dev`, click **Download Ubuntu .deb** in the web UI, and install the newly downloaded `.deb` file.

---

## How to Use the App

### 1. Native Linux CLI (`kryptlock`)
```bash
# RAR & UnRAR (with and without passwords)
kryptlock pack backup.rar ./documents --encrypt-headers --write-checksum
kryptlock pack open-share.rar ./documents --no-password
kryptlock unpack backup.rar -o ./restored
kryptlock unpack open-share.rar -o ./restored --no-password

# 7-Zip (.7z) with and without passwords
kryptlock pack vault.7z ./secrets --encrypt-headers --write-checksum
kryptlock pack public.7z ./assets --no-password
kryptlock unpack vault.7z -o ./restored

# ZIP (.zip) with AES-256 password or unencrypted
kryptlock pack release.zip ./dist
kryptlock pack release-open.zip ./dist --no-password

# Gzip, Bzip2, and XZ archives
kryptlock pack logs.tar.gz ./var-log
kryptlock pack logs.tar.bz2 ./var-log
kryptlock pack logs.tar.xz ./var-log

# KryptLock (.klock) AES-256-GCM vault + SHA-256 + email attachment
kryptlock lock secrets.klock ./documents --algo lzma --write-checksum --email colleague@example.com
kryptlock email vault.7z --to colleague@example.com
```

### 2. Native Linux Desktop GUI (`kryptlock-gui`)
1. Launch **KryptLock** from your application menu or run `kryptlock-gui`.
2. In **Pack & Lock**, add files or folders, choose a format (`klock`, `rar`, `7z`, `zip`, `tar.gz`, `tar.bz2`, `tar.xz`, `gz`), optionally enter a password (or leave blank for unencrypted `.rar`/`.7z`/`.zip`), and click **Create Archive**.
3. Click **Email Archive** to open your Linux mail client (`xdg-email` / Thunderbird) with the archive and `.sha256` sidecar attached.
4. In **Unpack & Verify**, select any `.klock`, `.rar`, `.7z`, `.zip`, `.gz`, `.bz2`, or `.xz` file, verify its SHA-256 checksum, enter a password if locked, and extract.

### 3. Browser Workbench
1. In **Compress & Lock**, drop multiple files or folders, pick `.klock`, `.7z`, `.zip`, `.gz / .tar.gz`, `.bz2 / .tar.bz2`, or `.xz / .tar.xz`, set an optional password (required for `.klock`), and download the archive + `.sha256` sidecar.
2. Use **Email Compressed / Locked Archive** to open a pre-filled `mailto:` draft or system share sheet.
3. In **Unlock Archive**, drop any `.klock`, `.rar` (UnRAR), `.7z`, `.zip`, `.gz`, `.bz2`, `.xz`, or `.tar` file (with or without a password) to verify checksums, preview contents, and extract locally.
