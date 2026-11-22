export interface CollectedBatchFile {
  file: File;
  relativePath: string;
}

export interface BatchCollectionResult {
  files: CollectedBatchFile[];
  rootDirectoryName: string | null;
  skippedHiddenCount: number;
}

const IGNORED_SEGMENT_REGEX = /(^|\/)(\.git|\.DS_Store|Thumbs\.db|desktop\.ini)$/i;

export function isHiddenOrSystemPath(relativePath: string): boolean {
  const normalized = relativePath.replace(/^\/+/, '');
  if (IGNORED_SEGMENT_REGEX.test(normalized)) return true;
  return normalized.split('/').some((part) => part === '.git');
}

function readAllDirectoryEntries(
  reader: FileSystemDirectoryReader
): Promise<FileSystemEntry[]> {
  return new Promise((resolve, reject) => {
    const entries: FileSystemEntry[] = [];
    const readBatch = () => {
      reader.readEntries(
        (batch) => {
          if (batch.length === 0) {
            resolve(entries);
          } else {
            entries.push(...batch);
            readBatch();
          }
        },
        (err) => reject(err)
      );
    };
    readBatch();
  });
}

function readFileEntry(entry: FileSystemFileEntry): Promise<File> {
  return new Promise((resolve, reject) => {
    entry.file(resolve, reject);
  });
}

async function walkEntry(
  entry: FileSystemEntry,
  parentPath: string,
  skipHidden: boolean,
  collected: CollectedBatchFile[],
  stats: { skippedHiddenCount: number }
): Promise<void> {
  const relPath = parentPath ? `${parentPath}/${entry.name}` : entry.name;

  if (skipHidden && isHiddenOrSystemPath(relPath)) {
    stats.skippedHiddenCount += 1;
    return;
  }

  if (entry.isFile) {
    const file = await readFileEntry(entry as FileSystemFileEntry);
    collected.push({ file, relativePath: relPath });
    return;
  }

  if (entry.isDirectory) {
    const dirEntry = entry as FileSystemDirectoryEntry;
    const reader = dirEntry.createReader();
    const children = await readAllDirectoryEntries(reader);
    for (const child of children) {
      await walkEntry(child, relPath, skipHidden, collected, stats);
    }
  }
}

export async function collectDroppedBatchItems(
  dataTransfer: DataTransfer,
  skipHidden: boolean
): Promise<BatchCollectionResult> {
  const collected: CollectedBatchFile[] = [];
  const stats = { skippedHiddenCount: 0 };
  let rootDirectoryName: string | null = null;

  const items = Array.from(dataTransfer.items || []);
  const entries = items
    .map((item) => item.webkitGetAsEntry?.())
    .filter((entry): entry is FileSystemEntry => entry != null);

  if (entries.length > 0) {
    const dirEntries = entries.filter((e) => e.isDirectory);
    if (dirEntries.length === 1 && entries.length === 1) {
      rootDirectoryName = dirEntries[0].name;
    }

    for (const entry of entries) {
      await walkEntry(entry, '', skipHidden, collected, stats);
    }
    return {
      files: collected,
      rootDirectoryName,
      skippedHiddenCount: stats.skippedHiddenCount,
    };
  }

  for (const file of Array.from(dataTransfer.files || [])) {
    const relPath =
      (file as File & { webkitRelativePath?: string }).webkitRelativePath ||
      file.name;
    if (skipHidden && isHiddenOrSystemPath(relPath)) {
      stats.skippedHiddenCount += 1;
      continue;
    }
    collected.push({ file, relativePath: relPath });
  }

  return {
    files: collected,
    rootDirectoryName,
    skippedHiddenCount: stats.skippedHiddenCount,
  };
}

export function countUniqueDirectories(paths: string[]): number {
  const dirs = new Set<string>();
  for (const path of paths) {
    const parts = path.split('/');
    if (parts.length > 1) {
      let prefix = '';
      for (let i = 0; i < parts.length - 1; i++) {
        prefix = prefix ? `${prefix}/${parts[i]}` : parts[i];
        dirs.add(prefix);
      }
    }
  }
  return dirs.size;
}
