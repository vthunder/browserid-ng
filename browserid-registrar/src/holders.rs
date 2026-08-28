//! Device + holder registry cores (registry-api-v1 §5.3/§5.4), shared by the
//! cookie lane (the broker's `/wsapi/device_certs`, `/wsapi/holders`, …) and
//! the token lane (`/api/v1/devices`, `/api/v1/holders`, …) so the two lanes'
//! validation bars and revocation routing cannot drift — the same rule as the
//! consent cores.
//!
//! The registrar owns the semantics; hosts provide the persistence
//! ([`RegistrarStore`]) and the one thing only a deployment knows: whether a
//! non-own status ref is still one of ITS lists ([`RegistrarHost::revoke_hosted_status`]).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use browserid_core::device::{Holder, HolderMatcher};
use serde::Serialize;

use crate::consent::status_list_uri;
use crate::error::RegistrarError;
use crate::host::RegistrarHost;
use crate::models::DeviceCertRecord;
use crate::store::RegistrarStore;

type Result<T> = std::result::Result<T, RegistrarError>;

// ===========================================================================
// §5.3 Devices
// ===========================================================================

/// One device/config cert row, in the wire shape both lanes list
/// (§5.3 / legacy `/wsapi/device_certs`).
#[derive(Serialize)]
pub struct DeviceCertView {
    pub id: u64,
    pub identities: Vec<String>,
    /// "authentication" (device/agent login) | "authorization" (config, warrant signer)
    pub purpose: String,
    /// The opaque registry-assigned holder id (`<prefix>.<id>`) this cert acts as.
    pub holder: String,
    pub pubkey: String,
    pub iss: String,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked: bool,
}

/// The account's device certs (active and revoked), §5.3 shape.
pub fn device_certs_core(store: &dyn RegistrarStore, user_id: u64) -> Result<Vec<DeviceCertView>> {
    Ok(store
        .list_device_certs(user_id)?
        .into_iter()
        .map(|r| DeviceCertView {
            id: r.id,
            identities: r.identities,
            purpose: r.purpose,
            holder: r.holder,
            pubkey: r.pubkey,
            iss: r.iss,
            issued_at: r.issued_at.to_rfc3339(),
            expires_at: r.expires_at.to_rfc3339(),
            revoked: r.revoked_at.is_some(),
        })
        .collect())
}

/// Route one cert's status ref to its revocation authority and flip the bit
/// (bean pbzn): our own list is flipped locally (legacy refless-URI rows are
/// all registry-issued), a deployment-hosted list (e.g. a hosted tenant's)
/// via the host hook, and a genuinely foreign ref — or a cert with no ref at
/// all — returns `false`: nobody here can revoke it, and callers MUST say so
/// rather than pretend (§5.3).
fn revoke_at_authority(
    store: &dyn RegistrarStore,
    host: &dyn RegistrarHost,
    own_domain: &str,
    cert: &DeviceCertRecord,
) -> Result<bool> {
    let Some(idx) = cert.status_idx else {
        return Ok(false);
    };
    match cert.status_uri.as_deref() {
        // Legacy refless-URI rows: ours only when the ISSUER is us — a
        // foreign cert's idx numbers the ISSUER's list, and flipping the same
        // index on our list would not revoke it anywhere a verifier looks
        // while collaterally revoking an unrelated own-issued cert (ft55).
        None if cert.iss.is_empty() || cert.iss.eq_ignore_ascii_case(own_domain) => {
            store.set_status_revoked_idx(idx)?;
            Ok(true)
        }
        None => Ok(false),
        Some(uri) if uri == status_list_uri(own_domain) => {
            store.set_status_revoked_idx(idx)?;
            Ok(true)
        }
        Some(uri) => host.revoke_hosted_status(uri, idx),
    }
}

/// Owner-scoped soft-revoke of one cert (§5.3): hide the row, and flip its
/// status bit when a list this deployment hosts is the authority. Returns
/// whether the bit actually flipped — `false` means the cert is only hidden
/// here and the caller must route revocation to the issuing authority.
/// Sticky: neither the row's revoked-at nor a status bit is ever un-set by
/// this path. A device MAY revoke itself; deliberately not special-cased.
pub fn revoke_device_core(
    store: &dyn RegistrarStore,
    host: &dyn RegistrarHost,
    own_domain: &str,
    user_id: u64,
    cert_id: u64,
) -> Result<bool> {
    let cert = store
        .list_device_certs(user_id)?
        .into_iter()
        .find(|r| r.id == cert_id)
        .ok_or(RegistrarError::DeviceCertNotFound)?;
    store.revoke_device_cert(user_id, cert_id)?;
    revoke_at_authority(store, host, own_domain, &cert)
}

/// §5.3 `GET /devices/status`: did a revocation actually land on the ISSUER's
/// signed list? Own-list refs are answered from the local store; anything
/// else is a fresh, fail-open-to-"unknown" fetch through the host's
/// verification stack (a network side effect, but no state change — the §4
/// pure-GET rule refers to registry state).
pub async fn device_status_core(
    store: &dyn RegistrarStore,
    verifier: Option<&dyn crate::api::PresentationVerifier>,
    own_domain: &str,
    user_id: u64,
    cert_id: u64,
) -> Result<&'static str> {
    let cert = store
        .list_device_certs(user_id)?
        .into_iter()
        .find(|r| r.id == cert_id)
        .ok_or(RegistrarError::DeviceCertNotFound)?;
    let Some(idx) = cert.status_idx else {
        return Ok("unknown");
    };
    let own = |revoked: bool| if revoked { "revoked" } else { "active" };
    let uri = match cert.status_uri.as_deref() {
        Some(uri) if uri == status_list_uri(own_domain) => {
            return Ok(own(store.is_status_revoked_idx(idx)?));
        }
        Some(uri) => uri.to_string(),
        // Refless-URI rows: registry-issued unless the iss says otherwise —
        // then reconstruct the issuer's conformant well-known list location.
        None if cert.iss.is_empty() || cert.iss.eq_ignore_ascii_case(own_domain) => {
            return Ok(own(store.is_status_revoked_idx(idx)?));
        }
        None => format!("https://{}/.well-known/browserid-status", cert.iss),
    };
    let Some(verifier) = verifier else {
        return Ok("unknown");
    };
    match verifier.check_status_ref(&uri, idx).await {
        Ok(true) => Ok("revoked"),
        Ok(false) => Ok("active"),
        Err(e) => {
            tracing::warn!(iss = %cert.iss, "device status check failed: {e}");
            Ok("unknown")
        }
    }
}

// ===========================================================================
// §5.4 Holders and namespaces — views
// ===========================================================================

#[derive(Serialize)]
pub struct HolderView {
    /// The opaque `<prefix>.<rand>` holder id.
    pub holder_id: String,
    pub label: String,
    /// "trusted" (holds a config/authorization cert → can authorize new sites)
    /// or "login-only" (authentication cert only → reuses existing warrants).
    pub trust: String,
    pub cert_count: usize,
    /// Latest issuance among this holder's certs (RFC 3339), if any.
    pub issued_at: Option<String>,
    /// Warrants whose matcher covers this holder.
    pub warrant_count: usize,
    /// True once ALL of this holder's certs are revoked.
    pub revoked: bool,
    /// A foreign service (holds its own cert): its holder is bound to a warrant,
    /// so it can't be re-categorized without revoking — the UI hides "move".
    pub external: bool,
    /// The identities (emails) this holder's certs act for, deduped.
    pub identities: Vec<String>,
    /// Set while an account-driven namespace move is pending: the label of
    /// the target namespace. The device's certs were revoked at move time; it
    /// re-registers under the target next time it's online.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moving_to: Option<String>,
}

#[derive(Serialize)]
pub struct NamespaceView {
    pub name: String,
    pub prefix: String,
    pub label: String,
    pub holders: Vec<HolderView>,
}

#[derive(Serialize)]
pub struct HoldersView {
    pub namespaces: Vec<NamespaceView>,
    /// Defensive: any holder whose prefix matches no namespace row.
    pub holders_without_namespace: Vec<HolderView>,
}

/// Accumulates the certs sharing one holder id as we scan the cert list.
#[derive(Default)]
struct HolderAcc {
    cert_count: usize,
    has_config: bool,
    latest_issued: Option<chrono::DateTime<chrono::Utc>>,
    all_revoked: bool,
    any_cert: bool,
    identities: BTreeSet<String>,
    external: bool,
}

/// The namespace prefix of a holder id (`<prefix>.<rand>` → `<prefix>`).
fn holder_prefix(holder_id: &str) -> &str {
    holder_id.split_once('.').map(|(p, _)| p).unwrap_or(holder_id)
}

/// A friendly default when the user hasn't labeled a holder: the first four
/// characters of its random suffix, e.g. `holder-q7f2`.
fn default_holder_label(holder_id: &str) -> String {
    let suffix = holder_id.split_once('.').map(|(_, s)| s).unwrap_or(holder_id);
    let short: String = suffix.chars().take(4).collect();
    format!("holder-{short}")
}

/// The grouped account view (namespaces → holders), §5.4 shape.
pub fn holders_view_core(store: &dyn RegistrarStore, user_id: u64) -> Result<HoldersView> {
    let certs = store.list_device_certs(user_id)?;
    let namespaces = store.list_namespaces(user_id)?;
    let labels = store.get_holder_labels(user_id)?;
    let warrants = store.list_warrants(user_id)?;

    // Fold the flat cert list into per-holder accumulators (stable order).
    let mut by_holder: BTreeMap<String, HolderAcc> = BTreeMap::new();
    for c in &certs {
        let acc = by_holder.entry(c.holder.clone()).or_default();
        acc.cert_count += 1;
        acc.identities.extend(c.identities.iter().cloned());
        if c.pubkey.is_empty() {
            acc.external = true;
        }
        if c.purpose == "authorization" {
            acc.has_config = true;
        }
        let revoked = c.revoked_at.is_some();
        if !acc.any_cert {
            acc.all_revoked = revoked;
            acc.any_cert = true;
        } else {
            acc.all_revoked = acc.all_revoked && revoked;
        }
        acc.latest_issued = Some(match acc.latest_issued {
            Some(prev) if prev >= c.issued_at => prev,
            _ => c.issued_at,
        });
    }

    // Pre-parse warrant matchers once so counting is a cheap loop per holder.
    let matchers: Vec<HolderMatcher> = warrants
        .iter()
        .filter_map(|w| w.holder.as_deref())
        .filter_map(|m| HolderMatcher::new(m).ok())
        .collect();
    let warrant_count = |holder_id: &str| -> usize {
        match Holder::new(holder_id) {
            Ok(h) => matchers.iter().filter(|m| m.matches(&h)).count(),
            Err(_) => 0,
        }
    };

    // Pending namespace moves: old holder → target-namespace label (for the
    // "moving to X" badge; rows disappear from here once the device re-issues).
    let moves = store.list_holder_moves(user_id)?;
    let ns_label_of_prefix = |prefix: &str| -> String {
        namespaces
            .iter()
            .find(|n| n.prefix == prefix)
            .map(|n| n.label.clone())
            .unwrap_or_else(|| prefix.to_string())
    };
    let moving_to = |holder_id: &str| -> Option<String> {
        moves
            .iter()
            .find(|(old, _)| old == holder_id)
            .map(|(_, new)| ns_label_of_prefix(holder_prefix(new)))
    };

    let make_view = |holder_id: &str, acc: &HolderAcc| HolderView {
        holder_id: holder_id.to_string(),
        label: labels
            .get(holder_id)
            .cloned()
            .unwrap_or_else(|| default_holder_label(holder_id)),
        trust: if acc.has_config { "trusted" } else { "login-only" }.to_string(),
        cert_count: acc.cert_count,
        issued_at: acc.latest_issued.map(|d| d.to_rfc3339()),
        warrant_count: warrant_count(holder_id),
        revoked: acc.any_cert && acc.all_revoked,
        external: acc.external,
        identities: acc.identities.iter().cloned().collect(),
        moving_to: moving_to(holder_id),
    };

    // Bucket each holder under the namespace whose prefix it carries — except
    // a pending-moved holder, which is shown under its TARGET namespace
    // immediately (the user already decided where it lives; the device just
    // hasn't re-registered yet — the badge says so).
    let effective_prefix = |holder_id: &str| -> String {
        let target = moves
            .iter()
            .find(|(old, _)| old == holder_id)
            .map(|(_, new)| new.as_str())
            .unwrap_or(holder_id);
        holder_prefix(target).to_string()
    };
    let mut ns_views: Vec<NamespaceView> = Vec::new();
    let mut placed: HashSet<String> = HashSet::new();
    for ns in &namespaces {
        let mut holders = Vec::new();
        for (holder_id, acc) in &by_holder {
            if effective_prefix(holder_id) == ns.prefix {
                holders.push(make_view(holder_id, acc));
                placed.insert(holder_id.clone());
            }
        }
        ns_views.push(NamespaceView {
            name: ns.name.clone(),
            prefix: ns.prefix.clone(),
            label: ns.label.clone(),
            holders,
        });
    }
    let orphans = by_holder
        .iter()
        .filter(|(id, _)| !placed.contains(*id))
        .map(|(id, acc)| make_view(id, acc))
        .collect();

    Ok(HoldersView { namespaces: ns_views, holders_without_namespace: orphans })
}

// ===========================================================================
// §5.4 — validation grammars (normative, unified across both lanes)
// ===========================================================================

/// Namespace name: lowercased and trimmed, then `^[a-z][a-z0-9_-]{0,31}$`.
pub fn validate_namespace_name(name: &str) -> Result<String> {
    let n = name.trim().to_lowercase();
    let b = n.as_bytes();
    let ok = !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-')
        });
    if ok {
        Ok(n)
    } else {
        Err(RegistrarError::ValidationError(
            "namespace name must be 1-32 chars: a lowercase letter then letters/digits/_/-".into(),
        ))
    }
}

/// Holder/namespace label: 1–64 Unicode characters, single line.
pub fn validate_label(label: &str) -> Result<String> {
    let l = label.trim();
    let chars = l.chars().count();
    if chars == 0 || chars > 64 || l.chars().any(char::is_control) {
        return Err(RegistrarError::ValidationError(
            "label must be 1–64 characters, single line".into(),
        ));
    }
    Ok(l.to_string())
}

/// Mint a fresh holder id under `prefix` (the registry-assigned name a moved
/// device re-issues as). Same unambiguous alphabet as the broker's issuance
/// paths (no 0/1/l/o).
pub fn assign_holder_id(prefix: &str) -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyz23456789";
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let suffix: String =
        (0..10).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect();
    format!("{prefix}.{suffix}")
}

// ===========================================================================
// §5.4 — holder mutations
// ===========================================================================

/// Owner scoping (§5.4): a holder is addressable only if it appears on one of
/// the account's device certs.
fn owned_certs(
    store: &dyn RegistrarStore,
    user_id: u64,
    holder_id: &str,
) -> Result<Vec<DeviceCertRecord>> {
    let certs: Vec<_> = store
        .list_device_certs(user_id)?
        .into_iter()
        .filter(|c| c.holder == holder_id)
        .collect();
    if certs.is_empty() {
        return Err(RegistrarError::HolderNotFound);
    }
    Ok(certs)
}

/// Friendly label for one holder id.
pub fn rename_holder_core(
    store: &dyn RegistrarStore,
    user_id: u64,
    holder_id: &str,
    label: &str,
) -> Result<()> {
    let label = validate_label(label)?;
    owned_certs(store, user_id, holder_id)?;
    store.set_holder_label(user_id, holder_id, &label)
}

/// Move a device to another namespace, FORCEFULLY: the old holder's certs are
/// revoked up front — each at its revocation authority, so the old
/// namespace's warrants stop applying within a status-cache window, not when
/// the device happens to come back online — and a PERMANENT redirect
/// `old → registry-assigned new holder` is recorded. The device completes the
/// move next time it's online: its next sign-in re-issues the same keys under
/// the target (clients check `holders/assignment`; a stale client supplying
/// the old holder at issuance is silently redirected). Returns the new holder.
///
/// Caveat (tracked): primary-issued certs carry no status ref today, so the
/// up-front revocation only bites certs with one; for primary-rooted devices
/// immediacy is bounded by the primary's own revocation story.
pub fn move_holder_core(
    store: &dyn RegistrarStore,
    host: &dyn RegistrarHost,
    own_domain: &str,
    user_id: u64,
    holder_id: &str,
    namespace: &str,
) -> Result<String> {
    let ns = validate_namespace_name(namespace)?;
    let certs = owned_certs(store, user_id, holder_id)?;
    // A foreign service holds its own cert; its holder is bound to the warrant,
    // so a move would revoke the grant with nothing to re-issue. Refuse — the
    // service must be re-authorized from the app if you want to relocate it.
    if certs.iter().any(|c| c.pubkey.is_empty()) {
        return Err(RegistrarError::Conflict {
            reason: "external_holder",
            message: "an external service can't be moved — re-authorize it from the app instead"
                .into(),
        });
    }
    let prefix = store.get_or_create_namespace(user_id, &ns)?;
    if holder_prefix(holder_id) == prefix {
        return Err(RegistrarError::Conflict {
            reason: "already_in_namespace",
            message: "holder is already in that namespace".into(),
        });
    }
    let new_holder = assign_holder_id(&prefix);

    // Revoke up front: the old namespace's warrants must stop applying to
    // this device NOW, not when it happens to come back online.
    for cert in &certs {
        store.revoke_device_cert(user_id, cert.id)?;
        revoke_at_authority(store, host, own_domain, cert)?;
    }
    store.set_holder_move(user_id, holder_id, &new_holder)?;
    // Carry the friendly label over so the device keeps its name in the UI.
    if let Some(label) = store.get_holder_labels(user_id)?.get(holder_id).cloned() {
        store.set_holder_label(user_id, &new_holder, &label)?;
    }
    Ok(new_holder)
}

/// Is `holder` still current, or has the account moved it? Clients check at
/// sign-in and re-issue the device's certs under the target when moved.
pub fn holder_assignment_core(
    store: &dyn RegistrarStore,
    user_id: u64,
    holder: &str,
) -> Result<Option<String>> {
    store.resolve_holder_move(user_id, holder)
}

/// Revoke + drop the warrants ISOLATED to `holder` (exact `<id>` matcher):
/// with the holder gone they can never be presented again, and leaving them
/// makes site listings show grants for "a removed device" forever. Group
/// (`<ns>.*`) matchers cover other holders and are left alone. Best-effort.
/// (The broker's `finish_holder_move` keeps a store-level copy of this for
/// issuance paths that have no registrar handle.)
pub fn cleanup_holder_warrants(store: &dyn RegistrarStore, user_id: u64, holder: &str) {
    let warrants = match store.list_warrants(user_id) {
        Ok(w) => w,
        Err(_) => return,
    };
    for w in warrants {
        if w.holder.as_deref() != Some(holder) {
            continue;
        }
        if let Some(idx) = w.status_idx {
            let _ = store.set_status_revoked_idx(idx);
        }
        if let Err(e) = store.delete_warrant(user_id, w.id) {
            tracing::warn!("dropping warrant {} for removed holder failed: {e}", w.id);
        }
    }
}

/// Remove a device/service from the account (§5.4): flip every one of the
/// holder's cert status bits at its revocation authority (outstanding access
/// certs fail-closed at verifiers — "log it out"), then delete the cert rows
/// + label so it leaves the account view. Revoke-then-delete: deletion alone
/// would leave live signed certs verifying at RPs that don't know the rows
/// are gone. Returns the deduped issuers whose certs could NOT be revoked
/// from here — the device can keep signing in with those until they expire;
/// only that issuer can cut them off, and the caller must say so.
pub fn forget_holder_core(
    store: &dyn RegistrarStore,
    host: &dyn RegistrarHost,
    own_domain: &str,
    user_id: u64,
    holder_id: &str,
) -> Result<Vec<String>> {
    let certs = owned_certs(store, user_id, holder_id)?;
    let mut unrevocable: Vec<String> = Vec::new();
    for cert in &certs {
        if !revoke_at_authority(store, host, own_domain, cert)? {
            unrevocable.push(cert.iss.clone());
        }
    }
    unrevocable.sort();
    unrevocable.dedup();
    cleanup_holder_warrants(store, user_id, holder_id);
    store.forget_holder(user_id, holder_id)?;
    Ok(unrevocable)
}

// ===========================================================================
// §5.4 — namespace mutations
// ===========================================================================

fn title_case(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// A new namespace: validated slug, generated prefix, defaulted label.
pub fn create_namespace_core(
    store: &dyn RegistrarStore,
    user_id: u64,
    name: &str,
    label: Option<&str>,
) -> Result<()> {
    let name = validate_namespace_name(name)?;
    let label = match label.map(str::trim).filter(|s| !s.is_empty()) {
        Some(l) => validate_label(l)?,
        None => title_case(&name),
    };
    store.create_namespace(user_id, &name, &label)
}

/// Relabel an existing namespace.
pub fn rename_namespace_core(
    store: &dyn RegistrarStore,
    user_id: u64,
    name: &str,
    label: &str,
) -> Result<()> {
    let label = validate_label(label)?;
    if !store.list_namespaces(user_id)?.iter().any(|n| n.name == name) {
        return Err(RegistrarError::NamespaceNotFound);
    }
    store.set_namespace_label(user_id, name, &label)
}

/// Delete an EMPTY namespace. Occupancy counts pending moves: a holder moving
/// INTO the namespace already lives there as far as the user's organization
/// is concerned (the view files it there), so it blocks deletion too.
pub fn delete_namespace_core(
    store: &dyn RegistrarStore,
    user_id: u64,
    name: &str,
) -> Result<()> {
    let ns = store
        .list_namespaces(user_id)?
        .into_iter()
        .find(|n| n.name == name)
        .ok_or(RegistrarError::NamespaceNotFound)?;
    let moves = store.list_holder_moves(user_id)?;
    let occupied = store.list_device_certs(user_id)?.iter().any(|c| {
        let target = moves
            .iter()
            .find(|(old, _)| *old == c.holder)
            .map(|(_, new)| new.as_str())
            .unwrap_or(&c.holder);
        holder_prefix(target) == ns.prefix
    });
    if occupied {
        return Err(RegistrarError::Conflict {
            reason: "namespace_not_empty",
            message: "the namespace still has holders".into(),
        });
    }
    store.delete_namespace(user_id, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_name_grammar() {
        assert_eq!(validate_namespace_name("Browsers ").unwrap(), "browsers");
        assert_eq!(validate_namespace_name("a1_b-c").unwrap(), "a1_b-c");
        assert!(validate_namespace_name("").is_err());
        assert!(validate_namespace_name("1abc").is_err(), "must start with a letter");
        assert!(validate_namespace_name("-abc").is_err());
        assert!(validate_namespace_name("a b").is_err());
        assert!(validate_namespace_name(&"a".repeat(33)).is_err());
        assert!(validate_namespace_name(&"a".repeat(32)).is_ok());
    }

    #[test]
    fn label_grammar() {
        assert_eq!(validate_label("  My Laptop  ").unwrap(), "My Laptop");
        assert!(validate_label("").is_err());
        assert!(validate_label("a\nb").is_err(), "single line");
        assert!(validate_label("a\tb").is_err(), "no control chars");
        // 64 Unicode characters, not bytes.
        assert!(validate_label(&"é".repeat(64)).is_ok());
        assert!(validate_label(&"é".repeat(65)).is_err());
    }

    #[test]
    fn assigned_holder_ids_carry_the_prefix() {
        let id = assign_holder_id("br1234ab");
        let (prefix, suffix) = id.split_once('.').unwrap();
        assert_eq!(prefix, "br1234ab");
        assert_eq!(suffix.len(), 10);
        assert!(suffix.bytes().all(|c| b"abcdefghijkmnpqrstuvwxyz23456789".contains(&c)));
        assert_ne!(assign_holder_id("p"), assign_holder_id("p"));
    }
}

/// A friendly holder label derived from a User-Agent, e.g. "Chrome on macOS".
/// Order matters: Edge ships "Chrome/" too, Chrome ships "Safari/", Android
/// ships "Linux". None when nothing recognizable — callers fall back to the
/// generic default label.
pub fn ua_label(ua: &str) -> Option<String> {
    let browser = if ua.contains("Edg/") {
        Some("Edge")
    } else if ua.contains("Chrome/") {
        Some("Chrome")
    } else if ua.contains("Firefox/") {
        Some("Firefox")
    } else if ua.contains("Safari/") {
        Some("Safari")
    } else {
        None
    };
    let os = if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        Some("iOS")
    } else if ua.contains("Mac OS X") {
        Some("macOS")
    } else if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    };
    match (browser, os) {
        (Some(b), Some(o)) => Some(format!("{b} on {o}")),
        (Some(b), None) => Some(b.to_string()),
        (None, Some(o)) => Some(format!("Browser on {o}")),
        // Not a browser UA: the product-token convention (bean lbla) — a
        // native client sending `Name/Version …` gets `Name` as its default
        // label, so wallets don't register as bare holder ids.
        (None, None) => product_token_label(ua),
    }
}

/// `Name/Version …` → `Name`, for non-browser clients (RFC 9110 product
/// tokens). `None` for anything that doesn't cleanly parse — callers keep
/// their generic default.
fn product_token_label(ua: &str) -> Option<String> {
    let first = ua.split_whitespace().next()?;
    let (name, _version) = first.split_once('/')?;
    let ok = !name.is_empty()
        && name.len() <= 64
        && name != "Mozilla"
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '+'));
    ok.then(|| name.to_string())
}

/// Best-effort: give `holder_id` a UA-derived default label if the user
/// hasn't labeled it yet. Never clobbers an existing label; never fails the
/// caller.
pub fn maybe_label_holder_from_ua(
    store: &dyn RegistrarStore,
    user_id: u64,
    holder_id: &str,
    user_agent: Option<&str>,
) {
    let Some(label) = user_agent.and_then(ua_label) else { return };
    match store.get_holder_labels(user_id) {
        Ok(labels) if labels.contains_key(holder_id) => {} // user/default already set — keep
        Ok(_) => {
            if let Err(e) = store.set_holder_label(user_id, holder_id, &label) {
                tracing::debug!("ua holder label skipped: {e}");
            }
        }
        Err(e) => tracing::debug!("ua holder label skipped: {e}"),
    }
}

#[cfg(test)]
mod ua_label_tests {
    use super::ua_label;

    #[test]
    fn ua_label_common_browsers() {
        let chrome_mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0 Safari/537.36";
        assert_eq!(ua_label(chrome_mac).as_deref(), Some("Chrome on macOS"));
        let ff_linux = "Mozilla/5.0 (X11; Linux x86_64; rv:141.0) Gecko/20100101 Firefox/141.0";
        assert_eq!(ua_label(ff_linux).as_deref(), Some("Firefox on Linux"));
        let safari_ios = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
        assert_eq!(ua_label(safari_ios).as_deref(), Some("Safari on iOS"));
        let edge_win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0 Safari/537.36 Edg/150.0";
        assert_eq!(ua_label(edge_win).as_deref(), Some("Edge on Windows"));
        let chrome_android = "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0 Mobile Safari/537.36";
        assert_eq!(ua_label(chrome_android).as_deref(), Some("Chrome on Android"));
    }

    #[test]
    fn ua_label_product_tokens() {
        assert_eq!(ua_label("BrowserID-Wallet/0.1").as_deref(), Some("BrowserID-Wallet"));
        assert_eq!(ua_label("BrowserID-Wallet/0.1 (macOS)").as_deref(), Some("BrowserID-Wallet"));
        assert_eq!(ua_label("curl/8.7.1").as_deref(), Some("curl"));
        // Browser detection still wins over the product-token fallback.
        assert_eq!(
            ua_label("Mozilla/5.0 (Windows NT 10.0) Chrome/150.0 Safari/537.36").as_deref(),
            Some("Chrome on Windows")
        );
        assert_eq!(ua_label("Mozilla/4.0"), None);
        assert_eq!(ua_label("no-slash-here"), None);
        assert_eq!(ua_label("we ird/1.0"), None);
        assert_eq!(ua_label(&format!("{}/1.0", "x".repeat(65))), None);
    }
}
