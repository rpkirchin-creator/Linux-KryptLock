export type ArchiveOperationType = 'encrypt' | 'decrypt';

export type ArchiveIntegrityStatus = 'verified' | 'failed' | 'unverified';

export interface ArchiveHistoryEntry {
  id: string;
  operation: ArchiveOperationType;
  filename: string;
  archiveType: string;
  compressionSummary: string;
  encrypted: boolean;
  entryCount: number;
  sizeBytes: number;
  sha256: string;
  integrityStatus: ArchiveIntegrityStatus;
  timestamp: string;
}

export type NewArchiveHistoryEntry = Omit<ArchiveHistoryEntry, 'id' | 'timestamp'>;

const STORAGE_KEY = 'kryptlock_archive_history_v1';
const MAX_HISTORY_ENTRIES = 50;

function isValidEntry(value: unknown): value is ArchiveHistoryEntry {
  if (!value || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.id === 'string' &&
    (record.operation === 'encrypt' || record.operation === 'decrypt') &&
    typeof record.filename === 'string' &&
    typeof record.archiveType === 'string' &&
    typeof record.compressionSummary === 'string' &&
    typeof record.encrypted === 'boolean' &&
    typeof record.entryCount === 'number' &&
    typeof record.sizeBytes === 'number' &&
    typeof record.sha256 === 'string' &&
    (record.integrityStatus === 'verified' ||
      record.integrityStatus === 'failed' ||
      record.integrityStatus === 'unverified') &&
    typeof record.timestamp === 'string'
  );
}

export function loadArchiveHistory(): ArchiveHistoryEntry[] {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isValidEntry).slice(0, MAX_HISTORY_ENTRIES);
  } catch {
    return [];
  }
}

export function saveArchiveHistory(entries: ArchiveHistoryEntry[]): void {
  try {
    const trimmed = entries.slice(0, MAX_HISTORY_ENTRIES);
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
  } catch {
    // Ignore storage quota / restricted mode failures
  }
}

export function appendArchiveHistory(
  entry: NewArchiveHistoryEntry
): ArchiveHistoryEntry[] {
  const current = loadArchiveHistory();
  const created: ArchiveHistoryEntry = {
    ...entry,
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
  };
  const updated = [created, ...current].slice(0, MAX_HISTORY_ENTRIES);
  saveArchiveHistory(updated);
  return updated;
}

export function deleteArchiveHistoryItem(id: string): ArchiveHistoryEntry[] {
  const updated = loadArchiveHistory().filter((item) => item.id !== id);
  saveArchiveHistory(updated);
  return updated;
}

export function clearArchiveHistory(): ArchiveHistoryEntry[] {
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Ignore restricted mode failures
  }
  return [];
}
