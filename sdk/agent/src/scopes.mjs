// Scope-entry helpers (protocol §5): an entry is a bare scope string or an
// object `{ scope, ...parameters }` carrying attenuations.

/** The scope string of an entry (`"post"` or `{ scope: "post", … }`). */
export const scopeName = (e) => (typeof e === "string" ? e : e && typeof e === "object" ? e.scope : undefined);

/** Two entries are equal iff same scope string and same parameters (a bare
 *  string equals `{ scope }` with no parameters). */
export function scopeEntryEq(a, b) {
  if (scopeName(a) !== scopeName(b)) return false;
  const pa = typeof a === "object" && a ? a : { scope: scopeName(a) };
  const pb = typeof b === "object" && b ? b : { scope: scopeName(b) };
  const keys = [...new Set([...Object.keys(pa), ...Object.keys(pb)])].filter((k) => k !== "scope").sort();
  return keys.every((k) => JSON.stringify(pa[k] ?? null) === JSON.stringify(pb[k] ?? null));
}
