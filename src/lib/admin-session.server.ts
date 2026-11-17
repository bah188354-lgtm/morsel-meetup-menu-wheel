import { getCookie, setCookie, getRequestHeader, getRequestIP } from "@tanstack/react-start/server";

export const ADMIN_COOKIE = "admin_session";
export const ADMIN_SESSION_SECONDS = 12 * 60 * 60;
const encoder = new TextEncoder();

function hex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hmac(key: string, message: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", encoder.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, encoder.encode(message)));
}
export async function sha256(value: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
/** Signing key includes the PIN, so changing ADMIN_PIN signs everyone out. */
function signingKey(): { pin: string; key: string } | null {
  const pin = process.env["ADMIN_PIN"];
  const secret = process.env["ADMIN_SESSION_SECRET"];
  if (!pin || !secret) return null;
  return { pin, key: `${secret}:${pin}` };
}

export function adminConfigured(): boolean {
  return signingKey() !== null;
}
export async function pinMatches(pin: string): Promise<boolean> {
  const k = signingKey();
  if (!k) return false;
  const [given, expected] = await Promise.all([hmac(k.key, `pin:${pin}`), hmac(k.key, `pin:${k.pin}`)]);
  return safeEqual(given, expected);
}
export async function createAdminToken(now = Date.now()): Promise<string> {
  const k = signingKey();
  if (!k) throw new Error("Yönetici PIN'i henüz ayarlanmadı.");
  const exp = now + ADMIN_SESSION_SECONDS * 1000;
  return `${exp}.${await hmac(k.key, `admin:${exp}`)}`;
}
export async function verifyAdminToken(token: string | undefined, now = Date.now()): Promise<boolean> {
  const k = signingKey();
  if (!k || !token) return false;
  const [exp, sig] = token.split(".");
  if (!exp || !sig || !/^\d+$/.test(exp) || Number(exp) <= now) return false;
  return safeEqual(sig, await hmac(k.key, `admin:${exp}`));
}

export async function isAdminRequest(): Promise<boolean> {
  return verifyAdminToken(getCookie(ADMIN_COOKIE));
}
export async function assertAdmin(): Promise<void> {
  if (!(await isAdminRequest())) throw new Error("Yönetici girişi gerekli. Sayfayı yenileyip PIN'i girin.");
}
export function setAdminCookie(token: string): void {
  setCookie(ADMIN_COOKIE, token, { httpOnly: true, secure: true, sameSite: "lax", path: "/", maxAge: ADMIN_SESSION_SECONDS });
}
export function requestIp(): string {
  return getRequestHeader("cf-connecting-ip") || getRequestIP({ xForwardedFor: true }) || "unknown";
}
