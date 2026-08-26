# Verifying BrowserID-NG presentations — RP quickstart

Adding identity verification to a relying party (RP) is one HTTPS call. Your
backend POSTs the presentation it received from the browser to a hosted `/verify`
service, which does all the cryptography (DNSSEC-rooted key resolution, signature
checks, the config-cert issuer binding, warrant validation, and the three
fail-closed revocation checks) and returns the verified identity.

The `presentation` field carries the client's **four-object bundle** —
`access_cert~assertion~warrant~config_cert`. As an RP you never parse it: the
spec "specifies what the RP receives, not how it verifies." You POST the blob
and read back the verified fields.

This is the **zero-dependency path** — it works from any language that can make
an HTTP request. For JavaScript/TypeScript there is a thin typed wrapper,
[`@browserid-ng/verify`](../sdk/js). For Rust there is `browserid-rp`
(in-process, no hosted call).

> **Trust model.** A hosted verifier is a party you trust to verify honestly. The
> default (`https://browserid.me/verify`) is the same broker you already discover
> keys through. To avoid trusting a third party, run your own `/verify` — the
> broker is open source — and point your calls at it.

## The endpoint

```
POST https://browserid.me/verify
Content-Type: application/json

{
  "presentation": "<the four-object bundle from the client>",
  "audience": "https://app.example.com",
  "accepted_fallbacks": ["fallback.example"]   // optional; see below
}
```

**Response** (HTTP 200 in both cases — inspect `status`):

```jsonc
// success
{ "status": "okay",
  "email": "user@example.com",          // the ATTRIBUTED identity (the human)
  "grantee": "user+agent@example.com",  // the ACTING identity; equals email for a human sign-in
  "holder": "br1a2b3c.x9y8z7",          // opaque id of the thing that acted (advisory)
  "scopes": ["post"],                   // what the warrant authorized at this audience
  "issuer": "example.com",              // IdP vouching for the attributed identity
  "grantee_issuer": "example.com",      // IdP vouching for the actor (differs on cross-issuer delegation)
  "status_refs": [{ "uri": "https://browserid.me/.well-known/browserid-status", "idx": 42 }] }

// failure
{ "status": "failure", "reason": "Assertion expired" }
```

### Fields

- **`audience`** — the exact origin you expect, e.g. `https://app.example.com`.
  Pin this **server-side**; never echo a client-supplied value. A mismatch fails.
- **`accepted_fallbacks`** *(optional)* — issuer domains you accept as fallback
  IdPs for emails that have **no primary IdP** (spec §8.1). The fallback IdP
  serves **only** no-primary domains: a fallback-issued cert (access *or* config)
  for a domain that **has** a primary fails verification, so a fallback can never
  override a domain's own IdP. Primary-IdP emails are always verified against
  their own primary regardless of this list. Omit to use the verifier's default
  (`{that broker}`).
- **`grantee`** *(response)* — the acting identity. For a human sign-in it
  equals `email`. When they **differ**, an agent acted on `email`'s behalf under
  a scoped, revocable warrant: `email` is who the action is attributed to,
  `grantee` is who performed it. If you run a plain human-login endpoint,
  **treat `grantee !== email` as a rejection** unless you intend to support
  agents.
- **`status_refs`** *(response)* — keep these and POST them to
  `https://browserid.me/status/check` on session activity to re-check
  revocation without retaining the (short-lived) presentation.

## Rules that keep you safe

1. **Verify on the server.** The presentation is a bearer credential for your
   origin — verifying it in the browser proves nothing.
2. **Success is `status === "okay"` AND a present `email`.** Treat everything
   else — any other status, a missing email, a non-2xx response, a network error,
   a non-JSON body — as failure. Fail closed.
3. **Decide your agent policy explicitly.** Ignoring `grantee` means you might
   accept an agent where you meant to accept only a human.

## Examples

### JavaScript / TypeScript (with the wrapper)

```js
import { createVerifier } from "@browserid-ng/verify";
const verifier = createVerifier();
const r = await verifier.verify(presentation, "https://app.example.com");
if (r.ok) login(r.email); else reject(r.reason);
// r.grantee !== r.email ⇒ an agent acted for r.email (decide your policy)
```

### JavaScript (no dependency)

```js
async function verify(presentation, audience) {
  const res = await fetch("https://browserid.me/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ presentation, audience }),
  });
  if (!res.ok) return { ok: false, reason: `HTTP ${res.status}` };
  const j = await res.json();
  if (j.status !== "okay" || !j.email) return { ok: false, reason: j.reason || "failed" };
  if (j.grantee && j.grantee !== j.email) return { ok: false, reason: "agent presentation not accepted" };
  return { ok: true, email: j.email };
}
```

### Python

```python
import requests

def verify(presentation: str, audience: str) -> str | None:
    r = requests.post("https://browserid.me/verify",
                      json={"presentation": presentation, "audience": audience},
                      timeout=10)
    if r.status_code != 200:
        return None
    j = r.json()
    if j.get("status") != "okay" or not j.get("email"):
        return None
    if j.get("grantee") and j["grantee"] != j["email"]:
        return None                 # reject agents on a human-login endpoint
    return j["email"]
```

### Go

```go
package browserid

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

type Result struct {
	Status  string `json:"status"`
	Email   string `json:"email"`
	Grantee string `json:"grantee"`
	Reason  string `json:"reason"`
}

var client = &http.Client{Timeout: 10 * time.Second}

// Verify returns the verified email, or "" on any failure (fail-closed).
func Verify(presentation, audience string) string {
	body, _ := json.Marshal(map[string]string{"presentation": presentation, "audience": audience})
	resp, err := client.Post("https://browserid.me/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var r Result
	if json.NewDecoder(resp.Body).Decode(&r) != nil {
		return ""
	}
	if r.Status != "okay" || r.Email == "" {
		return ""
	}
	if r.Grantee != "" && r.Grantee != r.Email { // reject agents here
		return ""
	}
	return r.Email
}
```

### curl (smoke test)

```sh
curl -s -X POST https://browserid.me/verify \
  -H 'content-type: application/json' \
  -d '{"presentation":"'"$PRESENTATION"'","audience":"https://app.example.com"}'
```

## Running your own verifier

The `/verify` route ships in the `browserid-broker` crate. Run the broker and
point `verifierUrl` (JS) or your POST URL at your own host. It is
self-contained — no broker *account* is needed to verify, since verification is
DNSSEC-rooted, not session-based.
