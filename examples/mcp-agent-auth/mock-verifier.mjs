// A stand-in for the hosted /verify, so the demo runs end-to-end with no network
// and no human consent. It maps fake assertion strings to canned verdicts:
//   "good-post"       → agent with scopes [post, read]
//   "good-read-only"  → agent with scopes [read]
//   "human"           → a plain human (no agent block)
//   anything else     → failure
// It also enforces the audience, exactly like the real endpoint.
import { createServer } from "node:http";

export function startMockVerifier(audience) {
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      let body = {};
      try {
        body = JSON.parse(raw);
      } catch {}
      const reply = (obj) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(obj));
      };
      if (body.audience !== audience) {
        return reply({ status: "failure", reason: `Audience mismatch: expected ${audience}` });
      }
      switch (body.assertion) {
        case "good-post":
          return reply({ status: "okay", email: "researcher@browserid.me", issuer: "browserid.me",
            agent: { parent: "alice@acme.com", scopes: ["post", "read"] } });
        case "good-read-only":
          return reply({ status: "okay", email: "researcher@browserid.me", issuer: "browserid.me",
            agent: { parent: "alice@acme.com", scopes: ["read"] } });
        case "human":
          return reply({ status: "okay", email: "alice@acme.com", issuer: "browserid.me" });
        default:
          return reply({ status: "failure", reason: "Invalid assertion" });
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}/verify`, close: () => server.close() });
    });
  });
}
