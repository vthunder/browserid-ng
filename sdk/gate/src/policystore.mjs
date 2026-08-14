// File-backed policy store (spec §6.5) for the gate: the resource-held,
// owner-signed policy records that admission conjoins with connection
// records. Records are signed artifacts and MUST survive restarts — kept as
// one 0600 JSON file in the gate home (they are not secrets, but the dir is
// owner-only anyway).

import { readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { dirname } from "node:path";

export function createFilePolicyStore(path) {
  let rows = [];
  try {
    const j = JSON.parse(readFileSync(path, "utf8"));
    if (Array.isArray(j.rows)) rows = j.rows;
  } catch {
    /* first run */
  }
  const key = (r) => `${r.grantor}|${r.grantee}|${r.audience}`;
  const save = () => {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, JSON.stringify({ v: 1, rows }, null, 2), { mode: 0o600 });
    try { chmodSync(path, 0o600); } catch { /* best effort */ }
  };
  return {
    async put(row) {
      rows = rows.filter((r) => key(r) !== key(row));
      rows.push(row);
      save();
    },
    async list(audience = null) {
      return audience == null ? [...rows] : rows.filter((r) => r.audience === audience);
    },
    async del(grantor, grantee, audience) {
      const k = `${grantor}|${grantee}|${audience}`;
      rows = rows.filter((r) => key(r) !== k);
      save();
    },
  };
}
