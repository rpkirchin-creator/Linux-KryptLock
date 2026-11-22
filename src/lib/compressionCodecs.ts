import { zlibSync, unzlibSync, gzipSync, gunzipSync } from 'fflate';
import { getBzip2Api } from './bzip2Codec';
import lzmaRaw from 'lzma/src/lzma_worker-min.js?raw';

export type CompressionAlgorithm = 'deflate' | 'gzip' | 'bzip2' | 'lzma' | 'store';

export interface CompressionAlgorithmInfo {
  id: CompressionAlgorithm;
  flagByte: number;
  label: string;
  shortLabel: string;
  extensionHint: string;
  summary: string;
}

export const COMPRESSION_ALGORITHMS: CompressionAlgorithmInfo[] = [
  {
    id: 'deflate',
    flagByte: 0x01,
    label: 'Zlib Deflate',
    shortLabel: 'Deflate',
    extensionHint: 'RFC 1950',
    summary: 'Fast general-purpose compression with low memory overhead.',
  },
  {
    id: 'gzip',
    flagByte: 0x03,
    label: 'Gzip',
    shortLabel: 'Gzip',
    extensionHint: 'RFC 1952',
    summary: 'Standard GNU zip stream with CRC32 framing.',
  },
  {
    id: 'bzip2',
    flagByte: 0x04,
    label: 'Bzip2',
    shortLabel: 'Bzip2',
    extensionHint: 'BWT + Huffman',
    summary: 'Higher ratio on text, logs, and source code via Burrows-Wheeler.',
  },
  {
    id: 'lzma',
    flagByte: 0x05,
    label: 'LZMA',
    shortLabel: 'LZMA',
    extensionHint: '7z / LZMA1',
    summary: 'Maximum compression ratio for dense archives and binaries.',
  },
  {
    id: 'store',
    flagByte: 0x02,
    label: 'Store (None)',
    shortLabel: 'Store',
    extensionHint: '0% CPU',
    summary: 'Skip compression for already-compressed media or maximum speed.',
  },
];

export function algorithmFromFlag(flag: number): CompressionAlgorithm {
  const match = COMPRESSION_ALGORITHMS.find((a) => a.flagByte === flag);
  if (!match) {
    throw new Error(`Unsupported .klock compression flag: 0x${flag.toString(16)}`);
  }
  return match.id;
}

export function flagFromAlgorithm(algo: CompressionAlgorithm): number {
  const match = COMPRESSION_ALGORITHMS.find((a) => a.id === algo);
  if (!match) {
    throw new Error(`Unknown compression algorithm: ${algo}`);
  }
  return match.flagByte;
}

export function getAlgorithmLabel(algo: CompressionAlgorithm): string {
  return COMPRESSION_ALGORITHMS.find((a) => a.id === algo)?.label ?? algo;
}

interface LzmaWorkerApi {
  compress: (data: Uint8Array | number[], mode: number) => number[];
  decompress: (data: Uint8Array | number[]) => number[] | string;
}

let cachedLzma: LzmaWorkerApi | null = null;

function getLzmaApi(): LzmaWorkerApi {
  if (cachedLzma) return cachedLzma;
  const scope: { LZMA_WORKER?: LzmaWorkerApi } = {};
  const initFn = new Function(lzmaRaw);
  initFn.call(scope);
  if (!scope.LZMA_WORKER) {
    throw new Error('Failed to initialize LZMA compression codec.');
  }
  cachedLzma = scope.LZMA_WORKER;
  return cachedLzma;
}

function toArrayBufferUint8(data: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy;
}

export function compressBytes(
  input: Uint8Array<ArrayBuffer>,
  algorithm: CompressionAlgorithm,
  level: 1 | 3 | 6 | 9
): Uint8Array<ArrayBuffer> {
  switch (algorithm) {
    case 'store':
      return input;
    case 'deflate':
      return toArrayBufferUint8(zlibSync(input, { level }));
    case 'gzip':
      return toArrayBufferUint8(gzipSync(input, { level }));
    case 'bzip2': {
      const compressed = getBzip2Api().compressFile(input);
      return toArrayBufferUint8(compressed);
    }
    case 'lzma': {
      const lzma = getLzmaApi();
      const signedArr = lzma.compress(input, level);
      const out = new Uint8Array(signedArr.length);
      for (let i = 0; i < signedArr.length; i++) {
        out[i] = signedArr[i] & 0xff;
      }
      return out;
    }
  }
}

export function decompressBytes(
  input: Uint8Array<ArrayBuffer>,
  algorithm: CompressionAlgorithm
): Uint8Array<ArrayBuffer> {
  switch (algorithm) {
    case 'store':
      return input;
    case 'deflate':
      return toArrayBufferUint8(unzlibSync(input));
    case 'gzip':
      return toArrayBufferUint8(gunzipSync(input));
    case 'bzip2': {
      const decompressed = getBzip2Api().decompressFile(input);
      return toArrayBufferUint8(decompressed);
    }
    case 'lzma': {
      const lzma = getLzmaApi();
      const res = lzma.decompress(input);
      if (typeof res === 'string') {
        const encoded = new TextEncoder().encode(res);
        return toArrayBufferUint8(encoded);
      }
      const out = new Uint8Array(res.length);
      for (let i = 0; i < res.length; i++) {
        out[i] = res[i] & 0xff;
      }
      return out;
    }
  }
}
