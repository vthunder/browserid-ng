"use client";
import { signIn, signOut, useSession } from "next-auth/react";
import { signInWithBrowserID } from "@browserid-ng/nextauth/client";

// Minimal reference page: a BrowserID sign-in button + the session state.
export default function Home() {
  const { data: session } = useSession();

  async function login() {
    // 1) open the BrowserID dialog and get a presentation, then
    // 2) hand it to Auth.js — the Credentials provider verifies it server-side.
    const presentation = await signInWithBrowserID({ siteName: "NextAuth + BrowserID demo" });
    await signIn("browserid", { presentation, redirectTo: "/" });
  }

  if (session?.user) {
    return (
      <main style={{ font: "16px system-ui", maxWidth: 560, margin: "10vh auto" }}>
        <p>Signed in as <b>{session.user.email}</b> ✓</p>
        <button onClick={() => signOut()}>Sign out</button>
      </main>
    );
  }
  return (
    <main style={{ font: "16px system-ui", maxWidth: 560, margin: "10vh auto" }}>
      <h1>NextAuth + BrowserID</h1>
      <p>Sign in with a BrowserID-verified identity — no password stored here.</p>
      <button onClick={login}>Sign in with BrowserID</button>
    </main>
  );
}
