// Which subjects the Apps table shows as columns. Shared between the pages (a peer offers "Show
// as column in Apps") and remembered per viewer; storage may be missing or blocked.
import { useCallback, useSyncExternalStore } from "react";

const KEY = "socketguard.columns";
const listeners = new Set<() => void>();
let fallback: string[] = [];
let cache: { raw: string | null; value: string[] } = { raw: null, value: [] };

function snapshot(): string[] {
  let raw: string | null;
  try {
    raw = window.localStorage.getItem(KEY);
  } catch {
    return fallback;
  }
  if (raw !== cache.raw) {
    let value: string[] = [];
    try {
      const parsed: unknown = raw === null ? [] : JSON.parse(raw);
      if (Array.isArray(parsed)) value = parsed.filter((k): k is string => typeof k === "string");
    } catch {
      // A damaged value is the same as none.
    }
    cache = { raw, value };
  }
  return cache.value;
}

function write(keys: string[]) {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(keys));
  } catch {
    // Not remembered; the columns still work for this session.
    fallback = keys;
  }
  for (const l of listeners) l();
}

/** Forget the remembered columns (the window's own storage, on removal). */
export function forgetColumns() {
  try {
    window.localStorage.removeItem(KEY);
  } catch {
    // Nothing stored that we can reach.
  }
  fallback = [];
  for (const l of listeners) l();
}

const subscribe = (cb: () => void) => {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
};

/** The keys of the chosen columns (see `buildColumns` in matrix.ts). */
export function useColumns() {
  const keys = useSyncExternalStore(subscribe, snapshot);
  const set = useCallback((next: string[]) => write(next), []);
  const add = useCallback((key: string) => {
    const cur = snapshot();
    if (!cur.includes(key)) write([...cur, key]);
  }, []);
  return { keys, set, add };
}
