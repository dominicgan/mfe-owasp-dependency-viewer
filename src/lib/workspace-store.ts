/**
 * The uploaded set of MFE reports, persisted in IndexedDB.
 *
 * This is a multi-file workflow — a holistic view is only holistic once every
 * MFE is in — so losing the set on reload would mean re-dropping a dozen files
 * to answer a follow-up question. Nothing is uploaded anywhere; this is the
 * same machine's disk.
 *
 * Unlike a single big export, these reports are small (tens of KB each), so
 * each one is a single record and there is no chunking to do.
 */

import type { Finding, ReportMeta } from './parse'

const DB_NAME = 'owasp-mfe-viewer'
const STORE = 'reports'
const DB_VERSION = 1

/** Bump whenever the parser's output shape or derived fields change, so stale
 *  records are ignored rather than silently served against new code. */
export const STORE_VERSION = 1

interface StoredReport {
  reportId: string
  version: number
  meta: ReportMeta
  rows: Finding[]
}

function openDb(): Promise<IDBDatabase | null> {
  if (typeof indexedDB === 'undefined') return Promise.resolve(null)
  return new Promise((resolve) => {
    let req: IDBOpenDBRequest
    try {
      req = indexedDB.open(DB_NAME, DB_VERSION)
    } catch {
      resolve(null)
      return
    }
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE, { keyPath: 'reportId' })
    }
    req.onsuccess = () => resolve(req.result)
    // Private mode and storage-policy failures are not worth surfacing: the
    // workspace still works, it just will not survive a reload.
    req.onerror = () => resolve(null)
    req.onblocked = () => resolve(null)
  })
}

export async function loadStoredReports(): Promise<{ meta: ReportMeta; rows: Finding[] }[]> {
  const db = await openDb()
  if (!db) return []
  try {
    const all = await new Promise<StoredReport[]>((resolve) => {
      const req = db.transaction(STORE, 'readonly').objectStore(STORE).getAll()
      req.onsuccess = () => resolve((req.result as StoredReport[]) ?? [])
      req.onerror = () => resolve([])
    })
    return all
      .filter((r) => r.version === STORE_VERSION && Array.isArray(r.rows) && r.meta)
      .sort((a, b) => (a.meta.addedAt ?? 0) - (b.meta.addedAt ?? 0))
      .map((r) => ({ meta: r.meta, rows: r.rows }))
  } catch {
    return []
  } finally {
    db.close()
  }
}

export async function putStoredReport(meta: ReportMeta, rows: Finding[]): Promise<void> {
  const db = await openDb()
  if (!db) return
  try {
    await new Promise<void>((resolve) => {
      const tx = db.transaction(STORE, 'readwrite')
      tx.objectStore(STORE).put({ reportId: meta.reportId, version: STORE_VERSION, meta, rows } satisfies StoredReport)
      tx.oncomplete = () => resolve()
      // A quota failure costs a re-upload next session, nothing more.
      tx.onerror = () => {
        console.warn('[workspace-store] write failed:', tx.error?.name, tx.error?.message)
        resolve()
      }
      tx.onabort = () => resolve()
    })
  } finally {
    db.close()
  }
}

export async function deleteStoredReport(reportId: string): Promise<void> {
  const db = await openDb()
  if (!db) return
  try {
    await new Promise<void>((resolve) => {
      const tx = db.transaction(STORE, 'readwrite')
      tx.objectStore(STORE).delete(reportId)
      tx.oncomplete = () => resolve()
      tx.onerror = () => resolve()
      tx.onabort = () => resolve()
    })
  } finally {
    db.close()
  }
}

export async function clearStoredReports(): Promise<void> {
  const db = await openDb()
  if (!db) return
  try {
    await new Promise<void>((resolve) => {
      const tx = db.transaction(STORE, 'readwrite')
      tx.objectStore(STORE).clear()
      tx.oncomplete = () => resolve()
      tx.onerror = () => resolve()
      tx.onabort = () => resolve()
    })
  } finally {
    db.close()
  }
}
