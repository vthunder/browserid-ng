<!-- This Source Code Form is subject to the terms of the Mozilla Public
     License, v. 2.0. If a copy of the MPL was not distributed with this
     file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

# Design note: an explicit account, one identity at the door, account data

> **Status: applied to the registry-api-v1 r5 draft, 2026-09-07 (revision 2c).**
> Kept as the rationale record for decision 12 (bean `1sb3`). Revision 1 asked whether
> naming the account on the wire removes rules; revision 2 adds two
> more moves from the same review: the door admits one identity at a
> time, and data belongs to the account rather than to the identity.

## 1. The problem in one paragraph

Every rule in r5 §4.4 and §5.6 is about the account, and no call ever
names one. The registry infers it from the identity a cert names, from
the session's certs, from whether an identity is owned, suspended, or
free. That inference is why attach needs two outcome tables, why the
restore path took three tries, why `mixed_accounts` exists. A second
inference sits under §4.3: because an issuer could mint certs for any
address it serves, authority was partitioned per identity, which put a
subject and a tier on every operation. The guard has since become the
thing that keeps an issuer out, and the partition is doing little.

## 2. Two constraints that must survive

1. **First use is one step.** New RP, click login, type an email, sign
   in at the IdP, logged in. No account step at the registry, ever.
2. **No oracle.** Nothing maps an address to an account for anyone who
   is not already in that account. A stranger learns only what r5
   already admits: "this address has been used here" (`prior_use`).

## 3. Three moves

### 3.1 The account has an id

Opaque, ≥ 128 bits, per registry, unguessable. It is not a secret:
knowing it proves nothing. It appears in three places: the session and
attach responses; the `session` request, where every proof must be a
key recorded on that account; and an OPTIONAL `account` field on
`attach`, the account being joined. Nothing else names it. A device
learns it only by being admitted: first attach creates the account and
returns the id; a new device passes the guard and gets the id; an old
device already has it. No oracle; first use unchanged.

### 3.2 The door admits one identity

A bare `attach` — no account named — carries certs for exactly one
identity (its auth cert, its config cert, or both). Everything with
more than one identity happens under a session on a named account, one
identity per call. `mixed_accounts` has nothing left to mean and is
deleted. The `additional_identities` guard kind, which needed several
identities in one bare call, moves to the guard endpoint like
`password`: the wallet posts fresh certs for the extra identities and
receives a token. Every guard kind then ends the same way — an
approval on file, or a token — and attach never reasons about more
than one identity.

### 3.3 Data belongs to the account

Warrants, requests, devices, holders: readable by any member at read
tier, writable by any member at write tier. The per-identity partition
of r5 §4.3 is dropped. What protects the user from an issuer that can
mint certs for one of their addresses is the guard: the issuer cannot
enter the account, and a takeover lands it in an empty one. What
remains per identity is what the cryptography enforces anyway — a
warrant is signed by a config cert that authorizes its grantor (the
warrant bar) — plus suspension, which marks one identity's rows when
it leaves, and detach, which names the identity removed.

Accepted consequences: a co-member sees and manages everything
("shared address means shared account"); detach and delete need write
on the account and nothing else, so the dead-issuer exception goes;
decision 11's rationale is restated — the answer to issuer power is
the guard, not partitioning.

## 4. The resulting §4.3

| Tier | Which sessions | Reaches |
|---|---|---|
| **lookup** | opened only by auth certs recorded without the guard | `warrants/lookup`; revoking its own cert |
| **read** | any member recorded past the guard; no config cert among the members | every read on the account |
| **write** | a config cert among the members | everything |

A session's tier is the highest among its members. That is the whole
authority model. Where an identity is still named:

| Where | Rule |
|---|---|
| `respond`, `register` | the config cert MUST be a recorded, unretired cert of the account and MUST authorize the warrant's grantor (§7.1 `grantor_not_authorized`) |
| a suspended identity (§4.4) | its rows are inert; no call acts on them except attach's restore row |
| `detach` | names the identity; write |
| `devices/revoke` | any tier for the session's own cert; write otherwise |

Gone: subject, `not_in_session`, per-identity tiers in the session
body (`identities[].tier` becomes one `tier`), the holder rule "every
identity holding a cert on the holder", and the account-shared /
write-on-any vocabulary.

## 5. The resulting §5.6.1

**Is an account named?**

### 5.1 No — the door (one identity)

| The identity is | Outcome |
|---|---|
| held by no account | A new account is created around the certs (a config cert required). Response names it. |
| held by account *a* | The guard for *a*: an approved device request, or a `guard` token from any kind the registry offers. Passed ⇒ recorded on *a*, response names *a*. Auth cert, no guard ⇒ lookup tier, no id returned. Config cert, no guard ⇒ `403 guard_required`, `prior_use: true`. |
| held by *a*, and `confirm_transfer` | **Takeover.** The identity leaves *a* (§4.4 hold) into a new account around this cert. |

### 5.2 Yes — membership

Naming an account means joining it, and joining is proven one of two
ways: a session on that account, or the account's guard (§5.6.4). The
guard is what a device uses when it has no session — a new device, or
the previous holder whose certs the issuer revoked after a takeover.
Then, for the identity the certs name:

| The identity is | Needs | Outcome |
|---|---|---|
| on this account | a session or the guard | Recorded. |
| suspended on this account | a session or the guard | **Restored**: leaves wherever it is now, returns, bits cleared, agents back. A holder with no other device and no password cannot restore — the D2 trade. |
| held by no account | write | Joins. |
| held by another account | write | Transfers: leaves there (hold), joins here. |

Freshness (300 s) applies to the last two rows and to takeover.

## 6. What this removes, counted

From r5: the session / no-session axis; `mixed_accounts` and its
precheck; the restore special pleading and the `recorded` proof kind
(no revoked key is ever used as proof; restore is an ordinary join
through the guard); the subject rule and its
table; `not_in_session`; per-identity tiers; the holder authority rule;
the dead-issuer detach exception; the §4.4 "two ways back" paragraph;
the `additional_identities` in-attach mechanics. Roughly a hundred
lines of normative text, and every one of the review's confusions
about "write on any" and "every identity the cert names".

## 7. What it keeps

The guard, every kind; the hold model and suspension; takeover with
`confirm_transfer`; device approval's two round trips; the lookup tier
as the one thing a stranger can reach; the warrant bar; tiers as
lookup / read / write.

## 8. Risks and open points

1. **Co-members.** Anyone admitted sees everything. That was already
   true of the roster and holders; now it is true of warrants. The
   guard is the only thing standing between an issuer and this, so the
   guard's strength matters more than before — device approval must
   never look low-stakes on screen.
2. **Id storage.** The wallet holds (registry, account id). Losing it
   is harmless: through the door again. Leaking it is harmless too;
   every use of it is proven by a session or the guard.
3. **Migration.** Every account already has an internal id; expose it.
   Old wallets keep working through the door for one release.
4. **Cookie lane.** Helped: both lanes now name the same explicit
   account, and the cookie lane's account-wide authority is no longer
   a parity gap (bean `zpbh` shrinks to session mechanics).
5. **Decision 11.** Its text says per-identity authority is the answer
   to issuer power. Rewrite: the guard is; account data is the
   simplification it permits.

## 9. Recommendation

Do all three. On the wire they are additive: one optional attach
field, one response field, one required `session` field, one guard
kind moved to the guard endpoint, one proof kind removed. The edits are confined to §4.2,
§4.3, §4.4, §5.6.1, §5.6.4, with matching trims in §5.2–§5.5 where
the subject rule was cited. The spec gets shorter.
