// Central config. This service is deliberately third-party-shaped: it knows
// the guestbook API URL and the wallet's public URLs, nothing privileged.
const trim = (u) => String(u).replace(/\/$/, "");

export const PORT = Number(process.env.PORT || 3200);
export const BROKER = trim(process.env.BROWSERID_BROKER || "https://browserid.me");
export const GUESTBOOK_URL = trim(process.env.GUESTBOOK_URL || `${BROKER}/guestbook`);
/** The audience agents must mint assertions for — the guestbook API itself. */
export const AUDIENCE = GUESTBOOK_URL;
export const SCOPES = ["guestbook-sign"];
export const WALLET_MCP_URL = trim(process.env.WALLET_MCP_URL || "https://wallet.browserid.me/mcp");
export const WALLET_INFO_URL = trim(process.env.WALLET_INFO_URL || "https://wallet.browserid.me");
export const SERVICE_ORIGIN = trim(process.env.SERVICE_ORIGIN || `http://localhost:${PORT}`);
