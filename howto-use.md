## How to Use the App

### 1. Native Linux CLI (\`kryptlock\`)
\`\`\`bash
# Create RAR with a password (and encrypted headers) or without a password
kryptlock pack backup.rar ./documents --encrypt-headers --write-checksum
kryptlock pack backup-open.rar ./documents --no-password

# Extract (UnRAR) a password-protected or unencrypted .rar archive
kryptlock unpack backup.rar -o ./restored
kryptlock unpack backup-open.rar -o ./restored --no-password

# Create & extract 7-Zip (.7z) with or without password
kryptlock pack vault.7z ./secrets --encrypt-headers --write-checksum
kryptlock pack public.7z ./assets --no-password
kryptlock unpack vault.7z -o ./restored

# Create & extract ZIP (.zip) with AES-256 password or unencrypted
kryptlock pack release.zip ./dist
kryptlock pack release-open.zip ./dist --no-password

# Gzip, Bzip2, and XZ tarballs
kryptlock pack logs.tar.gz ./var-log
kryptlock pack logs.tar.bz2 ./var-log
kryptlock pack logs.tar.xz ./var-log

# KryptLock (.klock) AES-256-GCM vault with SHA-256 verification & email attachment
kryptlock lock secrets.klock ./documents --algo lzma --write-checksum --email colleague@example.com
kryptlock email vault.7z --to colleague@example.com
\`\`\`

### 2. Native Linux Desktop GUI (\`kryptlock-gui\`)
1. Launch **KryptLock** from your application menu or run \`kryptlock-gui\`.
2. In **Pack & Lock**, add files or folders, choose a format (\`klock\`, \`rar\`, \`7z\`, \`zip\`, \`tar.gz\`, \`tar.bz2\`, \`tar.xz\`, \`gz\`), optionally set a password (or leave blank for unencrypted \`.rar\`/\`.7z\`/\`.zip\`), and click **Create Archive**.
3. Click **Email Archive** to open your Linux mail app (\`xdg-email\` / Thunderbird) with the archive and \`.sha256\` sidecar attached.
4. In **Unpack & Verify**, select any \`.klock\`, \`.rar\`, \`.7z\`, \`.zip\`, \`.gz\`, \`.bz2\`, or \`.xz\` file, enter a password if locked, and extract.

### 3. Browser Workbench
1. In **Pack & Lock**, drop multiple files or folders, pick \`.klock\`, \`.7z\`, \`.zip\`, \`.gz / .tar.gz\`, \`.bz2 / .tar.bz2\`, or \`.xz / .tar.xz\`, and enter an optional password (required for \`.klock\`).
2. In **Unpack & Extract**, drop any \`.klock\`, \`.rar\`, \`.7z\`, \`.zip\`, \`.gz\`, \`.bz2\`, \`.xz\`, or \`.tar\` archive (with or without a password) to verify SHA-256 checksums, preview files, and extract locally.
`;
