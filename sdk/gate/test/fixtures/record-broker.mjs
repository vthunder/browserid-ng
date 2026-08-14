// Shared mock-broker extension for the record flows (spec §6.5/§7.5):
// auto-approving authoring ceremonies + a validator that trusts its own fake
// records. Compose into a test's mock broker: call handle(url, body, reply)
// before your own routes; it returns true when it handled the request.
import { randomBytes } from "node:crypto";

const b64uJson = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJws = (claims) => `${b64uJson({ alg: "EdDSA", typ: "JWT" })}.${b64uJson(claims)}.sig`;
const nowS = () => Math.floor(Date.now() / 1000);

export function createRecordBroker({ brokerOrigin, adminEmail }) {
  const pending = new Map(); // request_id -> { type, grants, challenge }
  let idx = 100;

  const recordFor = (g) => `${fakeJws({
    typ: "browserid-warrant-v2",
    grantor: adminEmail,
    grantee: g.grantee,
    binding: { kind: "holder", matcher: "*" },
    audience: g.audience,
    scopes: g.scopes || [],
    status: { uri: `${brokerOrigin}/status-list`, idx: idx++ },
    iat: nowS(),
    exp: nowS() + 90 * 24 * 3600,
  })}~${fakeJws({ typ: "browserid-device-cert-v1", purpose: "authorization" })}`;

  function handle(url, body, reply) {
    if (url === "/warrant/record-request") {
      const id = `req_${randomBytes(6).toString("hex")}`;
      const challenge = randomBytes(24).toString("base64url");
      pending.set(id, { type: body.type, grants: body.grants || [], challenge });
      reply(200, {
        success: true, request_id: id, challenge,
        consent_uri: `${brokerOrigin}/consent/${id}`, expires_in: 900, interval: 0,
      });
      return true;
    }
    if (url === "/warrant/poll") {
      const r = pending.get(body.request_id || body.code);
      if (!r) { reply(404, { success: false, reason: "not found" }); return true; }
      pending.delete(body.request_id || body.code);
      // Auto-approve: the "admin signed the authoring card".
      reply(200, {
        success: true, status: "approved",
        grants: r.grants.map((g) => ({ audience: g.audience, warrant: recordFor(g) })),
      });
      return true;
    }
    if (url === "/validate-record") {
      // Trust our own fakes: decode the warrant payload and echo it back.
      try {
        const claims = JSON.parse(Buffer.from(body.record.split("~")[0].split(".")[1], "base64url").toString());
        if (claims.audience !== body.audience) {
          reply(200, { status: "failure", reason: "audience mismatch" });
          return true;
        }
        reply(200, {
          status: "okay", grantor: claims.grantor, grantee: claims.grantee,
          binding: claims.binding, scopes: claims.scopes || [], issuer: "example.com",
          status_refs: claims.status ? [claims.status] : [], expires_at: claims.exp,
        });
      } catch {
        reply(200, { status: "failure", reason: "unparseable record" });
      }
      return true;
    }
    return false;
  }

  return { handle };
}
