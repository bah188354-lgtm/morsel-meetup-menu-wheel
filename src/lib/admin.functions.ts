import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

export const PIN_MAX_FAILURES = 5;
export const PIN_WINDOW_MINUTES = 15;

export const getAdminStatus = createServerFn({ method: "GET" }).handler(async () => {
  const { isAdminRequest, adminConfigured } = await import("./admin-session.server");
  return { authed: await isAdminRequest(), configured: adminConfigured() };
});

export const adminLogin = createServerFn({ method: "POST" })
  .inputValidator((input) => z.object({ pin: z.string().trim().min(1).max(64) }).parse(input))
  .handler(async ({ data }) => {
    const session = await import("./admin-session.server");
    if (!session.adminConfigured()) return { ok: false as const, message: "Yönetici PIN'i henüz ayarlanmadı." };
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const ip = await session.sha256(session.requestIp());
    const since = new Date(Date.now() - PIN_WINDOW_MINUTES * 60_000).toISOString();
    const { count, error } = await supabaseAdmin.from("admin_pin_attempts").select("id", { count: "exact", head: true }).eq("ip_hash", ip).gte("created_at", since);
    if (error) throw new Error("Giriş şu anda yapılamıyor.");
    if ((count ?? 0) >= PIN_MAX_FAILURES) return { ok: false as const, message: `Çok fazla yanlış deneme. ${PIN_WINDOW_MINUTES} dakika sonra tekrar deneyin.` };
    if (!(await session.pinMatches(data.pin))) {
      await supabaseAdmin.from("admin_pin_attempts").insert({ ip_hash: ip });
      await supabaseAdmin.from("admin_pin_attempts").delete().lt("created_at", new Date(Date.now() - 86_400_000).toISOString());
      const left = PIN_MAX_FAILURES - (count ?? 0) - 1;
      return { ok: false as const, message: left > 0 ? `PIN yanlış. ${left} deneme hakkınız kaldı.` : `Çok fazla yanlış deneme. ${PIN_WINDOW_MINUTES} dakika sonra tekrar deneyin.` };
    }
    await supabaseAdmin.from("admin_pin_attempts").delete().eq("ip_hash", ip);
    session.setAdminCookie(await session.createAdminToken());
    return { ok: true as const, message: "" };
  });
