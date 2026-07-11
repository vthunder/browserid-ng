# Verifying BrowserID-NG assertions — RP quickstart

Adding identity verification to a relying party (RP) is one HTTPS call. Your
backend POSTs the assertion it received from the browser to a hosted `/verify`
service, which does all the cryptography (DNSSEC-rooted key resolution, signature
checks, agent-warrant validation, revocation) and returns the verified email.

This is the **zero-dependency path** — it works from any language that can make
an HTTP request. For JavaScript/TypeScript there is a thin typed wrapper,
[`@browserid/verify`](../sdk/js). Native (in-process, no hosted call) verifier
libraries are planned; until then, the hosted endpoint is the supported path.

> **Trust model.** A hosted verifier is a party you trust to verify honestly. The
> default (`https://browserid.me/verify`) is the same broker you already discover
> keys through. To avoid trusting a third party, run your own `/verify` — the
> broker is open source — and point your calls at it.

## The endpoint

```
POST https://browserid.me/verify
Content-Type: application/json

{
  "assertion": "<certificate~assertion string from the browser>",
  "audience": "https://app.example.com",
  "accepted_fallbacks": ["fallback.example"]   // optional; see below
}
```

**Response** (HTTP 200 in both cases — inspect `status`):

```jsonc
// success
{ "status": "okay", "email": "user@example.com", "issuer": "example.com",
  "expires": 1789000000,
  "agent": { "parent": "user@example.com", "scopes": ["post"] } }  // only if an agent

// failure
{ "status": "failure", "reason": "Assertion expired" }
```

### Fields

- **`audience`** — the exact origin you expect, e.g. `https://app.example.com`.
  Pin this **server-side**; never echo a client-supplied value. A mismatch fails.
- **`accepted_fallbacks`** *(optional)* — issuer domains you accept as fallback
  IdPs for emails that have **no primary IdP** (spec §8.1). Primary-IdP emails
  are always verified against their own primary regardless of this list. Omit to
  use the verifier's default (`{that broker}`).
- **`agent`** *(response, optional)* — present only when the presentation is an
  AI **agent** acting for a human via a warrant. `parent` is the human; `scopes`
  is what the human's warrant authorized at this audience. If you run a plain
  human-login endpoint, **treat a present `agent` as a rejection** unless you
  intend to support agents.

## Rules that keep you safe

1. **Verify on the server.** The assertion is a bearer credential for your
   origin — verifying it in the browser proves nothing.
2. **Success is `status === "okay"` AND a present `email`.** Treat everything
   else — any other status, a missing email, a non-2xx response, a network error,
   a non-JSON body — as failure. Fail closed.
3. **Decide your agent policy explicitly.** Ignoring the `agent` field means you
   might accept an agent where you meant to accept only a human.

## Examples

### JavaScript / TypeScript (with the wrapper)

```js
import { createVerifier } from "@browserid/verify";
const verifier = createVerifier();
const r = await verifier.verify(assertion, "https://app.example.com");
if (r.ok) login(r.email); else reject(r.reason);
```

### JavaScript (no dependency)

```js
async function verify(assertion, audience) {
  const res = await fetch("https://browserid.me/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ assertion, audience }),
  });
  if (!res.ok) return { ok: false, reason: `HTTP ${res.status}` };
  const j = await res.json();
  if (j.status !== "okay" || !j.email) return { ok: false, reason: j.reason || "failed" };
  if (j.agent) return { ok: false, reason: "agent presentation not accepted" };
  return { ok: true, email: j.email };
}
```

### Python

```python
import requests

def verify(assertion: str, audience: str) -> str | None:
    r = requests.post("https://browserid.me/verify",
                      json={"assertion": assertion, "audience": audience},
                      timeout=10)
    if r.status_code != 200:
        return None
    j = r.json()
    if j.get("status") != "okay" or not j.get("email"):
        return None
    if j.get("agent"):          # reject agents on a human-login endpoint
        return None
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
	Status string `json:"status"`
	Email  string `json:"email"`
	Reason string `json:"reason"`
	Agent  *struct {
		Parent string   `json:"parent"`
		Scopes []string `json:"scopes"`
	} `json:"agent"`
}

var client = &http.Client{Timeout: 10 * time.Second}

// Verify returns the verified email, or "" on any failure (fail-closed).
func Verify(assertion, audience string) string {
	body, _ := json.Marshal(map[string]string{"assertion": assertion, "audience": audience})
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
	if r.Status != "okay" || r.Email == "" || r.Agent != nil { // reject agents here
		return ""
	}
	return r.Email
}
```

### curl (smoke test)

```sh
curl -s -X POST https://browserid.me/verify \
  -H 'content-type: application/json' \
  -d '{"assertion":"'"$ASSERTION"'","audience":"https://app.example.com"}'
```

## Running your own verifier

The `/verify` route ships in the `browserid-broker` crate. Run the broker and
point `verifierUrl` (JS) or your POST URL at your own host. It is
self-contained — no broker *account* is needed to verify, since verification is
DNSSEC-rooted, not session-based.
