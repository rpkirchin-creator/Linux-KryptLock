import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'path';
import type { Connect, Plugin } from 'vite';
import { defineConfig } from 'vite';

interface BinaryPathCheck {
  id: string;
  label: string;
  scope: string;
  resolvedPath: string;
  exists: boolean;
  executable: boolean;
}

function checkBinaryPath(id: string, label: string, scope: string, targetPath: string): BinaryPathCheck {
  const exists = fs.existsSync(targetPath);
  let executable = false;
  if (exists) {
    try {
      fs.accessSync(targetPath, fs.constants.X_OK);
      executable = true;
    } catch {
      executable = false;
    }
  }
  return { id, label, scope, resolvedPath: targetPath, exists, executable };
}

function handleVerifyInstallRequest(_req: Connect.IncomingMessage, res: import('node:http').ServerResponse): void {
  const home = os.homedir();
  const paths: BinaryPathCheck[] = [
    checkBinaryPath('usr-local-bin', '/usr/local/bin/kryptlock', 'System local CLI', '/usr/local/bin/kryptlock'),
    checkBinaryPath(
      'home-local-bin',
      '~/.local/bin/kryptlock',
      'User bundle CLI',
      path.join(home, '.local', 'bin', 'kryptlock')
    ),
    checkBinaryPath('usr-bin', '/usr/bin/kryptlock', 'Ubuntu .deb CLI', '/usr/bin/kryptlock'),
    checkBinaryPath(
      'home-local-gui',
      '~/.local/bin/kryptlock-gui',
      'User bundle GUI',
      path.join(home, '.local', 'bin', 'kryptlock-gui')
    ),
    checkBinaryPath('usr-bin-gui', '/usr/bin/kryptlock-gui', 'Ubuntu .deb GUI', '/usr/bin/kryptlock-gui'),
  ];

  const primaryCli = paths.find(
    (p) => (p.id === 'usr-local-bin' || p.id === 'home-local-bin' || p.id === 'usr-bin') && p.exists
  );
  const installed = paths.some(
    (p) => (p.id === 'usr-local-bin' || p.id === 'home-local-bin') && p.exists
  );
  const debInstalled = paths.some((p) => p.id === 'usr-bin' && p.exists);

  let formats: Record<string, unknown> | null = null;
  if (primaryCli && primaryCli.executable) {
    try {
      const stdout = execFileSync(primaryCli.resolvedPath, ['formats'], {
        timeout: 1500,
        encoding: 'utf8',
      });
      formats = JSON.parse(stdout) as Record<string, unknown>;
    } catch {
      formats = null;
    }
  }

  res.statusCode = 200;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(
    JSON.stringify({
      installed: installed || debInstalled,
      primaryMatch: installed,
      debInstalled,
      checkedAt: new Date().toISOString(),
      platform: `${os.platform()} ${os.arch()}`,
      paths,
      formats,
    })
  );
}

function kryptlockVerifyPlugin(): Plugin {
  const attachMiddleware = (middlewares: Connect.Server) => {
    middlewares.use('/api/verify-install', (req, res, next) => {
      if (req.method !== 'GET') {
        next();
        return;
      }
      handleVerifyInstallRequest(req, res);
    });
  };

  return {
    name: 'kryptlock-install-verifier',
    configureServer(server) {
      attachMiddleware(server.middlewares);
    },
    configurePreviewServer(server) {
      attachMiddleware(server.middlewares);
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), kryptlockVerifyPlugin()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
