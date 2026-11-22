import fs from 'node:fs';
import path from 'node:path';
import esbuild from 'esbuild';

const outDir = '/tmp/kryptlock-deb-build';
fs.rmSync(outDir, { recursive: true, force: true });

await esbuild.build({
  entryPoints: ['src/lib/debBuilder.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  outfile: path.join(outDir, 'debBuilder.mjs'),
});

const { buildUbuntuDebBytes } = await import(path.join(outDir, 'debBuilder.mjs'));
const debBytes = buildUbuntuDebBytes();
const outputPath = path.resolve(process.cwd(), 'kryptlock_1.0.0_all.deb');
fs.writeFileSync(outputPath, debBytes);
fs.rmSync(outDir, { recursive: true, force: true });

console.log(`Built ${outputPath} (${debBytes.byteLength} bytes)`);
console.log('Install or upgrade on Ubuntu with:');
console.log('  sudo apt install -y ./kryptlock_1.0.0_all.deb');
