// Auth.js v5 config wiring "Sign in with BrowserID" (reference example).
import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { BrowserID } from "@browserid-ng/nextauth";

const AUDIENCE = process.env.BROWSERID_AUDIENCE || "http://localhost:3000";

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    Credentials(
      BrowserID({
        // Pin to this app's canonical origin. In production set
        // BROWSERID_AUDIENCE to e.g. https://app.example.com.
        audience: AUDIENCE,
        broker: process.env.BROWSERID_BROKER || "https://browserid.me",
      })
    ),
  ],
  callbacks: {
    async jwt({ token, user }) {
      // Carry BrowserID claims (incl. statusRefs) so we can re-check revocation.
      if ((user as any)?.browserid) token.browserid = (user as any).browserid;
      return token;
    },
    async session({ session, token }) {
      (session as any).browserid = (token as any).browserid;
      return session;
    },
  },
});
