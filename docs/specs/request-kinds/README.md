# Request kinds

The vocabulary of things a page or a filer may ask the user's wallet to
sign. Referenced by the protocol spec §7.3 (the request mediator) and
registry-api-v1 §5.3 (the inbox). One JSON Schema per kind, next to this
file; the schema is the request's wire shape on both lanes.

Each kind fixes five things:

| kind | present-lane args | filed by, and proof | card shows | artefact | delivered to |
|---|---|---|---|---|---|
| [`login`](./login.json) | `acceptedFallbacks?` | nobody (present only) | identity picker | presentation bundle (§5) | page |
| [`warrant`](./warrant.json) | `grants[]`, `message?` (self-grant only) | agent: device-key signature | each grant, equal prominence; grantee, label, and deny-first when filed | warrants + config cert | page (inline) / poll (filed) |
| [`signature`](./signature.json) | `audience`, `object` | — (filed form is §5 labeled door 4) | the typed object | presentation + JWS over the object | page |
| [`admission`](./admission.json) | `code` | resource backend: audience proof, or page origin = audience origin | connection / authoring card | admission records + config cert | poll only |
| [`provision`](./provision.json) | `code` | agent: anonymous until the user binds | identity stage, then grants stage (the wallet hosts the registry's approval card) | device cert + warrants | poll only |
| `notice` | — | the registry | informational; nothing to sign | — | — |

Rules every kind shares:

- **Trusted origin.** The wallet uses the browser-attached origin of the
  message it received, never one the page claims (§7.3).
- **Card content is never requester-typed prose** beyond `message`, which
  is quoted, capped at 500 characters, and marked unverified. Scopes render
  through a wallet-owned label table; the raw scope is the fallback,
  monospace, length-capped, control and bidi characters stripped.
- **No signing without status refs.** A record the registry has not
  allocated an index for is malformed (§5); the wallet fails closed.
- **Unknown kind** answers `unsupported_kind`.
- **Results.** Present-lane calls return a promise of the kind's result;
  `login` additionally fires the login observer for compatibility.

## Error codes

`unsupported_kind`, `no_grant` (signature: no covering record; run a
`warrant` request first), `origin_mismatch` (admission present-lane check
failed; fall back to the audience proof), `denied`, `expired`.
