import { createMiddleware } from "@tanstack/react-start";

/** Every management server function: valid PIN cookie first, then the service-role client. */
export const requireAdmin = createMiddleware({ type: "function" }).server(async ({ next }) => {
  const { assertAdmin } = await import("./admin-session.server");
  await assertAdmin();
  const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
  return next({ context: { db: supabaseAdmin } });
});
