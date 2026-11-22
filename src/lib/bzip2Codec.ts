import freezeRaw from 'compressjs/lib/freeze.js?raw';
import streamRaw from 'compressjs/lib/Stream.js?raw';
import utilRaw from 'compressjs/lib/Util.js?raw';
import crc32Raw from 'compressjs/lib/CRC32.js?raw';
import bitStreamRaw from 'compressjs/lib/BitStream.js?raw';
import huffmanAllocatorRaw from 'compressjs/lib/HuffmanAllocator.js?raw';
import bwtRaw from 'compressjs/lib/BWT.js?raw';
import bzip2Raw from 'compressjs/lib/Bzip2.js?raw';

interface Bzip2Api {
  compressFile: (data: Uint8Array) => Uint8Array;
  decompressFile: (data: Uint8Array) => Uint8Array;
}

let cachedBzip2: Bzip2Api | null = null;

function evalAmdModule<T>(
  rawSource: string,
  resolvedDeps: Record<string, unknown>
): T {
  let exportedValue: unknown;
  const defineFn = (deps: string[], factory: (...args: unknown[]) => unknown) => {
    const args = deps.map((dep) => {
      if (!(dep in resolvedDeps)) {
        throw new Error(`Missing Bzip2 dependency: ${dep}`);
      }
      return resolvedDeps[dep];
    });
    exportedValue = factory(...args);
  };

  // Strip the Node-only `amdefine` fallback line so Vite/browser never calls require('amdefine')
  const cleaned = rawSource.replace(
    /if\s*\(\s*typeof\s+define\s*!==\s*['"]function['"]\s*\)\s*\{[^}]*\}/,
    ''
  );
  const runner = new Function('define', cleaned);
  runner(defineFn);
  return exportedValue as T;
}

export function getBzip2Api(): Bzip2Api {
  if (cachedBzip2) return cachedBzip2;

  const registry: Record<string, unknown> = {};
  registry['./freeze'] = evalAmdModule(freezeRaw, registry);
  registry['./Stream'] = evalAmdModule(streamRaw, registry);
  registry['./Util'] = evalAmdModule(utilRaw, registry);
  registry['./CRC32'] = evalAmdModule(crc32Raw, registry);
  registry['./BitStream'] = evalAmdModule(bitStreamRaw, registry);
  registry['./HuffmanAllocator'] = evalAmdModule(huffmanAllocatorRaw, registry);
  registry['./BWT'] = evalAmdModule(bwtRaw, registry);
  const bzip2 = evalAmdModule<Bzip2Api>(bzip2Raw, registry);

  cachedBzip2 = bzip2;
  return bzip2;
}
