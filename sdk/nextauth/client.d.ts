// Types for @browserid-ng/nextauth/client (browser entry).

export function loadBrowserID(broker?: string): Promise<void>;

export function watchBrowserID(opts: {
  broker?: string;
  onlogin?: (presentation: string) => void;
  onlogout?: () => void;
  onready?: () => void;
}): Promise<void>;

export function requestBrowserID(opts?: {
  broker?: string;
  siteName?: string;
  siteLogo?: string;
}): Promise<void>;

export function logoutBrowserID(opts?: { broker?: string }): Promise<void>;

export function signInWithBrowserID(opts?: {
  broker?: string;
  siteName?: string;
  siteLogo?: string;
}): Promise<string>;
