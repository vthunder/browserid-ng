//! The leaving cascade (registry-api-v1 §4.1 rule 3; bean 0c49 step 1),
//! run against BOTH stores — the sqlite one because memory-store tests
//! miss its constraints, the memory one because that is what the HTTP
//! tests run on.

use browserid_broker::membership::{
    detach, identity_leaves, sweep_holds, transfer_out, LeaveReason, HOLD_DAYS,
};
use browserid_broker::store::{
    DeviceCertRecord, EmailType, InMemoryUserStore, SqliteStore, SuspendedIdentity, UserId,
    UserStore, WarrantRecord,
};
use chrono::{Duration, Utc};

fn warrant(user: UserId, grantor: &str, audience: &str, idx: Option<u64>) -> WarrantRecord {
    // Records upsert on (account, grantee, audience, scopes): give each
    // fixture its own grantee so they stay distinct rows.
    WarrantRecord {
        id: 0,
        user_id: user,
        delegator_email: grantor.into(),
        agent_email: format!("bot-{}-{}@example.com", grantor.replace(['@', '+'], "-"), audience.replace("https://", "")),
        audience: audience.into(),
        scopes: vec!["read".into()],
        warrant: "jws".into(),
        status_idx: idx,
        holder: None,
        config_cert: None,
        binding_id: None,
        signed_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(30),
    }
}

fn agent_cert(user: UserId, identity: &str, idx: u64, pubkey: &str) -> DeviceCertRecord {
    DeviceCertRecord {
        id: 0,
        user_id: user,
        identities: vec![identity.into()],
        purpose: "authentication".into(),
        holder: "agents.x".into(),
        pubkey: pubkey.into(),
        iss: "localhost:3000".into(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(30),
        revoked_at: None,
        status_uri: None,
        status_idx: Some(idx),
        prov: "smtp".into(),
    }
}

struct World {
    a: UserId,
    b: UserId,
    w_dan: u64,      // dan's warrant bit (suspension sets it)
    w_agent: u64,    // dan+cal's warrant bit
    w_explicit: u64, // dan's warrant, revoked explicitly before the leave
    w_other: u64,    // other@'s warrant — untouched
    cert_agent: u64, // dan+cal's device cert bit
}

fn seed<U: UserStore>(store: &U) -> World {
    let a = store.create_user("hash").unwrap();
    let b = store.create_user("hash").unwrap();
    store.add_email(a, "dan@example.com", true).unwrap();
    store.add_email(a, "other@example.com", true).unwrap();
    store
        .add_email_with_type(a, "dan+cal@example.com", true, EmailType::Agent)
        .unwrap();
    store.set_parent_email("dan+cal@example.com", Some("dan@example.com")).unwrap();
    store.add_email(b, "bee@example.com", true).unwrap();

    let idx = |k: &str| store.get_or_allocate_status("warrant", k).unwrap();
    let w_dan = idx("a|dan|rp1");
    let w_agent = idx("a|dan+cal|rp1");
    let w_explicit = idx("a|dan|rp2");
    let w_other = idx("a|other|rp1");
    let cert_agent = idx("cert|dan+cal");
    store.upsert_warrant(warrant(a, "dan@example.com", "https://rp1", Some(w_dan))).unwrap();
    store.upsert_warrant(warrant(a, "dan+cal@example.com", "https://rp1", Some(w_agent))).unwrap();
    store.upsert_warrant(warrant(a, "dan@example.com", "https://rp2", Some(w_explicit))).unwrap();
    store.upsert_warrant(warrant(a, "other@example.com", "https://rp1", Some(w_other))).unwrap();
    store.set_status_revoked_idx(w_explicit).unwrap();
    store.insert_device_cert(agent_cert(a, "dan+cal@example.com", cert_agent, "pk-agent")).unwrap();
    World { a, b, w_dan, w_agent, w_explicit, w_other, cert_agent }
}

fn revoked<U: UserStore>(store: &U, idx: u64) -> bool {
    store.is_status_revoked_idx(idx).unwrap()
}

fn notices<U: UserStore>(store: &U, user: UserId) -> Vec<(String, String)> {
    store
        .list_pending_warrant_requests(user)
        .unwrap()
        .into_iter()
        .filter(|r| r.kind == "notice")
        .map(|r| {
            let meta: serde_json::Value = serde_json::from_str(r.meta.as_deref().unwrap()).unwrap();
            (
                meta["notice"]["identity"].as_str().unwrap().to_string(),
                meta["notice"]["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn scenario_transfer_and_return<U: UserStore>(store: &U) {
    let w = seed(store);

    // dan@ transfers A → B.
    let rep = transfer_out(store, w.a, w.b, "dan@example.com", LeaveReason::Transferred).unwrap();
    assert_eq!(rep.agents_suspended, 1);
    assert_eq!(rep.bits_set, 3, "dan's warrant, the agent's warrant, the agent's cert");

    // The row moved; A remembers the identity as suspended.
    assert_eq!(store.get_email("dan@example.com").unwrap().unwrap().user_id, w.b);
    let hold = store.get_suspended_identity(w.a, "dan@example.com").unwrap().expect("on hold at A");
    assert_eq!(hold.reason, "transferred");
    assert!(hold.hold_until > Utc::now() + Duration::days(HOLD_DAYS - 1));
    // The derived agent stayed on A, suspended (a93p: never left behind live).
    let agent = store.get_email("dan+cal@example.com").unwrap().unwrap();
    assert_eq!(agent.user_id, w.a);
    assert!(agent.is_suspended());
    // Bits: the identity's and its agent's set; the explicit one still set;
    // other@'s untouched.
    assert!(revoked(store, w.w_dan));
    assert!(revoked(store, w.w_agent));
    assert!(revoked(store, w.cert_agent));
    assert!(revoked(store, w.w_explicit));
    assert!(!revoked(store, w.w_other));
    // Certs, sessions, other identities untouched: other@ still active.
    assert!(!store.get_email("other@example.com").unwrap().unwrap().is_suspended());
    // A notice on A.
    assert_eq!(notices(store, w.a), vec![("dan@example.com".to_string(), "left".to_string())]);
    // Roster shows both states.
    let roster = browserid_broker::membership::roster(store, w.a).unwrap();
    assert!(roster.contains(&("other@example.com".to_string(), "active")));
    assert!(roster.contains(&("dan@example.com".to_string(), "suspended")));
    assert!(!roster.iter().any(|(e, _)| e == "dan+cal@example.com"), "agents are not roster entries");

    // Idempotent.
    let again = identity_leaves(store, w.a, "dan@example.com", LeaveReason::Transferred).unwrap();
    assert!(again.already_suspended);

    // dan@ comes back B → A within the hold: a return.
    transfer_out(store, w.b, w.a, "dan@example.com", LeaveReason::Transferred).unwrap();
    assert_eq!(store.get_email("dan@example.com").unwrap().unwrap().user_id, w.a);
    assert!(store.get_suspended_identity(w.a, "dan@example.com").unwrap().is_none());
    assert!(store.get_suspended_identity(w.b, "dan@example.com").unwrap().is_some(), "B now holds it suspended");
    assert!(!store.get_email("dan+cal@example.com").unwrap().unwrap().is_suspended());
    // Suspension-set bits cleared; the explicit revoke stays.
    assert!(!revoked(store, w.w_dan));
    assert!(!revoked(store, w.w_agent));
    assert!(!revoked(store, w.cert_agent));
    assert!(revoked(store, w.w_explicit));
    let n = notices(store, w.a);
    assert!(n.contains(&("dan@example.com".to_string(), "returned".to_string())), "{n:?}");
}

fn scenario_explicit_revoke_during_hold_sticks<U: UserStore>(store: &U) {
    let w = seed(store);
    transfer_out(store, w.a, w.b, "dan@example.com", LeaveReason::TakenOver).unwrap();
    // While on hold, the owner explicitly revokes one of the suspended bits.
    store.set_status_revoked_idx(w.w_dan).unwrap();
    transfer_out(store, w.b, w.a, "dan@example.com", LeaveReason::Transferred).unwrap();
    assert!(revoked(store, w.w_dan), "an explicit revoke during the hold is not undone by the return");
    assert!(!revoked(store, w.w_agent));
}

fn scenario_detach_and_sweep<U: UserStore>(store: &U) {
    let w = seed(store);
    detach(store, w.a, "dan@example.com").unwrap();
    assert!(store.get_email("dan@example.com").unwrap().is_none(), "nobody holds a detached identity");
    assert_eq!(store.get_suspended_identity(w.a, "dan@example.com").unwrap().unwrap().reason, "detached");
    assert!(store.get_email("dan+cal@example.com").unwrap().unwrap().is_suspended());

    // Nothing expired yet: the sweep is a no-op.
    let rep = sweep_holds(store, Utc::now()).unwrap();
    assert_eq!(rep.identities_dropped, 0);

    // Past the hold: records and the agent go; A stays (other@ is still there).
    let rep = sweep_holds(store, Utc::now() + Duration::days(HOLD_DAYS + 1)).unwrap();
    assert_eq!(rep.identities_dropped, 1);
    assert_eq!(rep.agents_dropped, 1);
    assert_eq!(rep.warrants_dropped, 3, "dan's two + the agent's one");
    assert_eq!(rep.accounts_dropped, 0);
    assert!(store.get_suspended_identity(w.a, "dan@example.com").unwrap().is_none());
    assert!(store.get_email("dan+cal@example.com").unwrap().is_none());
    assert!(store.get_user(w.a).unwrap().is_some());
    let left: Vec<String> = store.list_warrants(w.a).unwrap().into_iter().map(|r| r.delegator_email).collect();
    assert_eq!(left, vec!["other@example.com".to_string()]);
    // Bits of dropped records stay set (invariant 5).
    assert!(revoked(store, w.w_dan));
    assert!(revoked(store, w.w_agent));
    assert!(!revoked(store, w.w_other));

    // An account whose every identity has left is dropped with the hold.
    let c = store.create_user("hash").unwrap();
    store.add_email(c, "solo@example.com", true).unwrap();
    // remove_email refuses nothing at the store level; detach it.
    detach(store, c, "solo@example.com").unwrap();
    store
        .insert_suspended_identity(SuspendedIdentity {
            user_id: c,
            email: "solo@example.com".into(),
            suspended_at: Utc::now() - Duration::days(HOLD_DAYS + 2),
            hold_until: Utc::now() - Duration::days(1),
            reason: "detached".into(),
        })
        .unwrap();
    let rep = sweep_holds(store, Utc::now()).unwrap();
    assert_eq!(rep.accounts_dropped, 1);
    assert!(store.get_user(c).unwrap().is_none());
    assert!(store.list_pending_warrant_requests(c).unwrap().is_empty(), "its notices went with it");
}

fn sqlite() -> (SqliteStore, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("m.db");
    (SqliteStore::open(path.to_str().unwrap()).unwrap(), dir)
}

#[test]
fn transfer_and_return_sqlite() {
    let (s, _d) = sqlite();
    scenario_transfer_and_return(&s);
}
#[test]
fn transfer_and_return_memory() {
    scenario_transfer_and_return(&InMemoryUserStore::new());
}
#[test]
fn explicit_revoke_during_hold_sticks_sqlite() {
    let (s, _d) = sqlite();
    scenario_explicit_revoke_during_hold_sticks(&s);
}
#[test]
fn explicit_revoke_during_hold_sticks_memory() {
    scenario_explicit_revoke_during_hold_sticks(&InMemoryUserStore::new());
}
#[test]
fn detach_and_sweep_sqlite() {
    let (s, _d) = sqlite();
    scenario_detach_and_sweep(&s);
}
#[test]
fn detach_and_sweep_memory() {
    scenario_detach_and_sweep(&InMemoryUserStore::new());
}
