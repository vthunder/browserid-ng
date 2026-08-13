// Tailscale funnel detection/setup (browserid-ng-7uzd) — hermetic, via an
// injected `run` that returns canned `tailscale` output. No tailscale needed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { detectFunnel, ensureFunnel, claimFunnel, funnelOffHint, FUNNEL_PORTS } from "../src/tunnel.mjs";

const STATUS = {
  Web: {
    // 443 is a private serve (not in AllowFunnel) to a different port.
    "host.tail.ts.net:443": { Handlers: { "/": { Proxy: "http://localhost:8000" } } },
    // 8443 is a PUBLIC funnel to our gate's port.
    "host.tail.ts.net:8443": { Handlers: { "/": { Proxy: "http://127.0.0.1:8787" } } },
  },
  AllowFunnel: { "host.tail.ts.net:8443": true },
};

const runWith = (status, onFunnel) => async (args) => {
  if (args[0] === "serve" && args[1] === "status") return { stdout: JSON.stringify(status) };
  if (args[0] === "funnel") {
    onFunnel?.(args);
    return { stdout: "" };
  }
  throw new Error(`unexpected tailscale ${args.join(" ")}`);
};

test("detectFunnel finds the public funnel mapping to our port", async () => {
  const run = runWith(STATUS);
  assert.equal(await detectFunnel(8787, { run }), "https://host.tail.ts.net:8443");
});

test("detectFunnel ignores a private (non-funnel) serve on the same target", async () => {
  const run = runWith(STATUS);
  // 8000 is served on :443 but NOT in AllowFunnel → not public → null.
  assert.equal(await detectFunnel(8000, { run }), null);
});

test("detectFunnel returns null when tailscale is unavailable", async () => {
  const run = async () => { throw new Error("tailscale: command not found"); };
  assert.equal(await detectFunnel(8787, { run }), null);
});

test("ensureFunnel returns an existing funnel without creating one", async () => {
  let created = false;
  const run = runWith(STATUS, () => { created = true; });
  assert.equal(await ensureFunnel(8787, { run }), "https://host.tail.ts.net:8443");
  assert.equal(created, false, "must not create a funnel when one already exists");
});

test("ensureFunnel creates a funnel on the first free port when none exists", async () => {
  // No funnel yet for port 9000; 443 is taken (private serve), so it should pick 8443.
  const base = { Web: { "host.tail.ts.net:443": { Handlers: { "/": { Proxy: "http://localhost:8000" } } } }, AllowFunnel: {} };
  let funnelArgs = null;
  const run = async (args) => {
    if (args[0] === "serve") {
      // After the funnel call, report the new mapping so the URL resolves.
      return { stdout: JSON.stringify(funnelArgs ? {
        Web: { ...base.Web, "host.tail.ts.net:8443": { Handlers: { "/": { Proxy: "http://127.0.0.1:9000" } } } },
        AllowFunnel: { "host.tail.ts.net:8443": true },
      } : base) };
    }
    if (args[0] === "funnel") { funnelArgs = args; return { stdout: "" }; }
    throw new Error("unexpected");
  };
  const url = await ensureFunnel(9000, { run });
  assert.equal(url, "https://host.tail.ts.net:8443");
  assert.deepEqual(funnelArgs, ["funnel", "--bg", "--https=8443", "9000"]);
});

test("claimFunnel is idempotent when 443 already maps to our port", async () => {
  const status = {
    Web: { "host.tail.ts.net:443": { Handlers: { "/": { Proxy: "http://127.0.0.1:9000" } } } },
    AllowFunnel: { "host.tail.ts.net:443": true },
  };
  let claimed = null;
  const run = runWith(status, (args) => { claimed = args; });
  const { url, warning } = await claimFunnel(9000, { run, probe: async () => "other" });
  assert.equal(url, "https://host.tail.ts.net");
  assert.equal(warning, null);
  assert.equal(claimed, null, "must not re-claim when already mapped to our port");
});

test("claimFunnel re-points 443 from a STALE (dead) target — our own previous run", async () => {
  // 443 currently maps to a dead previous-run port; we want it on 9000.
  let repointed = false;
  let probed = null;
  const run = async (args) => {
    if (args[0] === "serve") {
      return { stdout: JSON.stringify({
        Web: { "host.tail.ts.net:443": { Handlers: { "/": { Proxy: `http://127.0.0.1:${repointed ? 9000 : 55555}` } } } },
        AllowFunnel: { "host.tail.ts.net:443": true },
      }) };
    }
    if (args[0] === "funnel") { repointed = true; return { stdout: "" }; }
    throw new Error("unexpected");
  };
  const { url, warning } = await claimFunnel(9000, { run, probe: async (p) => { probed = p; return "dead"; } });
  assert.equal(url, "https://host.tail.ts.net");
  assert.equal(warning, null, "reclaiming our own stale mapping is silent");
  assert.equal(probed, 55555, "the current 443 target was probed first");
  assert.ok(repointed, "must re-point 443 to the current local port");
});

test("claimFunnel never steals 443 from a LIVE app — takes 8443 and warns about claude.ai", async () => {
  let funnelArgs = null;
  const run = async (args) => {
    if (args[0] === "serve") {
      return { stdout: JSON.stringify({
        Web: {
          "host.tail.ts.net:443": { Handlers: { "/": { Proxy: "http://127.0.0.1:3000" } } },
          ...(funnelArgs ? { "host.tail.ts.net:8443": { Handlers: { "/": { Proxy: "http://127.0.0.1:9000" } } } } : {}),
        },
        AllowFunnel: { "host.tail.ts.net:443": true, ...(funnelArgs ? { "host.tail.ts.net:8443": true } : {}) },
      }) };
    }
    if (args[0] === "funnel") { funnelArgs = args; return { stdout: "" }; }
    throw new Error("unexpected");
  };
  const { url, warning } = await claimFunnel(9000, { run, probe: async () => "other" });
  assert.equal(url, "https://host.tail.ts.net:8443");
  assert.deepEqual(funnelArgs, ["funnel", "--bg", "--https=8443", "9000"], "claimed the next free port, not 443");
  assert.match(warning, /already serving another live app/);
  assert.match(warning, /claude\.ai requires port 443/);
  assert.match(warning, /tailscale funnel --https=443 off/);
});

test("claimFunnel recognizes ANOTHER RUNNING GATE on 443 and says so", async () => {
  let claimed = false;
  const run = async (args) => {
    if (args[0] === "serve") {
      return { stdout: JSON.stringify({
        Web: {
          "host.tail.ts.net:443": { Handlers: { "/": { Proxy: "http://127.0.0.1:3000" } } },
          ...(claimed ? { "host.tail.ts.net:8443": { Handlers: { "/": { Proxy: "http://127.0.0.1:9000" } } } } : {}),
        },
        AllowFunnel: { "host.tail.ts.net:443": true, ...(claimed ? { "host.tail.ts.net:8443": true } : {}) },
      }) };
    }
    if (args[0] === "funnel") { claimed = true; return { stdout: "" }; }
    throw new Error("unexpected");
  };
  const { warning } = await claimFunnel(9000, { run, probe: async () => "gate" });
  assert.match(warning, /another running gate instance/);
});

test("claimFunnel throws when 443 is live and every other funnel port is taken", async () => {
  const run = runWith({
    Web: {
      "host.tail.ts.net:443": { Handlers: { "/": { Proxy: "http://127.0.0.1:3000" } } },
      "host.tail.ts.net:8443": { Handlers: { "/": { Proxy: "http://127.0.0.1:3001" } } },
      "host.tail.ts.net:10000": { Handlers: { "/": { Proxy: "http://127.0.0.1:3002" } } },
    },
    AllowFunnel: { "host.tail.ts.net:443": true },
  });
  await assert.rejects(
    () => claimFunnel(9000, { run, probe: async () => "other" }),
    /every other funnel port .* is taken/
  );
});

test("funnelOffHint derives the teardown command port", () => {
  assert.equal(funnelOffHint("https://host.tail.ts.net:8443"), "tailscale funnel --https=8443 off");
  assert.equal(funnelOffHint("https://host.tail.ts.net"), "tailscale funnel --https=443 off");
});

test("443 (no port suffix) formats correctly", async () => {
  const status = {
    Web: { "host.tail.ts.net:443": { Handlers: { "/": { Proxy: "http://127.0.0.1:8787" } } } },
    AllowFunnel: { "host.tail.ts.net:443": true },
  };
  assert.equal(await detectFunnel(8787, { run: runWith(status) }), "https://host.tail.ts.net");
  assert.deepEqual(FUNNEL_PORTS, [443, 8443, 10000]);
});
