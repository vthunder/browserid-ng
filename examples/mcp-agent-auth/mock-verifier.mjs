// A stand-in for the hosted /verify-access, so the demo runs end-to-end with no
// network and no human consent. It maps fake presentation strings to canned
// verdicts:
//   "good-post"       → agent with scopes [post, read]
//   "good-read-only"  → agent with scopes [read]
//   "human"           → a plain user login (subject user)
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
        return reply({ status: "failure", reason: `audience mismatch: expected ${audience}` });
      }
      switch (body.presentation) {
        case "good-post":
          return reply({ status: "okay", email: "alice+researcher@acme.com", issuer: "browserid.me",
            subject: "agent", scopes: ["post", "read"] });
        case "good-read-only":
          return reply({ status: "okay", email: "alice+researcher@acme.com", issuer: "browserid.me",
            subject: "agent", scopes: ["read"] });
        case "human":
          return reply({ status: "okay", email: "alice@acme.com", issuer: "browserid.me",
            subject: "user", scopes: ["login"] });
        default:
          return reply({ status: "failure", reason: "invalid presentation" });
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}/verify-access`, close: () => server.close() });
    });
  });
}
