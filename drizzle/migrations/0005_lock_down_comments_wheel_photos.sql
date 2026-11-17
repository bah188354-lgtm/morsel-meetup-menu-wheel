-- 1) Guest comments: guests may only insert
DROP POLICY IF EXISTS "Passwordless panel reads comments" ON public.guest_comments;
DROP POLICY IF EXISTS "Passwordless panel marks comments" ON public.guest_comments;
DROP POLICY IF EXISTS "Passwordless panel deletes comments" ON public.guest_comments;
DROP POLICY IF EXISTS "Guests send comments as unread" ON public.guest_comments;
REVOKE ALL ON public.guest_comments FROM anon, authenticated;
GRANT INSERT ON public.guest_comments TO anon, authenticated;
GRANT ALL ON public.guest_comments TO service_role;
CREATE POLICY "Guests send comments as unread" ON public.guest_comments FOR INSERT TO anon, authenticated
  WITH CHECK (is_read = false AND char_length(message) BETWEEN 1 AND 1000);

-- Deprecated reviews table: no public access at all
DROP POLICY IF EXISTS "Anyone can read reviews" ON public.menu_reviews;
DROP POLICY IF EXISTS "Guests add reviews pending approval" ON public.menu_reviews;
DROP POLICY IF EXISTS "Passwordless review deletion" ON public.menu_reviews;
DROP POLICY IF EXISTS "Passwordless review moderation" ON public.menu_reviews;
REVOKE ALL ON public.menu_reviews FROM anon, authenticated;
COMMENT ON TABLE public.menu_reviews IS 'DEPRECATED: replaced by guest_comments; no public access';

-- 2) Lucky wheel
DROP POLICY IF EXISTS "Passwordless panel edits wheel settings" ON public.wheel_settings;
REVOKE ALL ON public.wheel_settings FROM anon, authenticated;
GRANT SELECT ON public.wheel_settings TO anon, authenticated;

DROP POLICY IF EXISTS "Anyone can read wheel wins" ON public.wheel_wins;
DROP POLICY IF EXISTS "Passwordless panel resets wheel wins" ON public.wheel_wins;
REVOKE ALL ON public.wheel_wins FROM anon, authenticated;

REVOKE ALL ON FUNCTION public.spin_wheel() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.spin_wheel() TO service_role;

CREATE TABLE public.wheel_spins (
  device_id text NOT NULL CHECK (char_length(device_id) BETWEEN 32 AND 128),
  day date NOT NULL,
  count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (device_id, day)
);
GRANT ALL ON public.wheel_spins TO service_role;
ALTER TABLE public.wheel_spins ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.wheel_ip_spins (
  ip_hash text NOT NULL,
  hour timestamptz NOT NULL,
  count integer NOT NULL DEFAULT 0,
  PRIMARY KEY (ip_hash, hour)
);
GRANT ALL ON public.wheel_ip_spins TO service_role;
ALTER TABLE public.wheel_ip_spins ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.wheel_claims (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code text NOT NULL UNIQUE CHECK (code ~ '^[A-HJ-NP-Z2-9]{6}$'),
  prize text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  redeemed_at timestamptz
);
GRANT ALL ON public.wheel_claims TO service_role;
ALTER TABLE public.wheel_claims ENABLE ROW LEVEL SECURITY;
CREATE INDEX wheel_claims_created_at_idx ON public.wheel_claims (created_at DESC);

CREATE TABLE public.admin_pin_attempts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ip_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT ALL ON public.admin_pin_attempts TO service_role;
ALTER TABLE public.admin_pin_attempts ENABLE ROW LEVEL SECURITY;
CREATE INDEX admin_pin_attempts_ip_idx ON public.admin_pin_attempts (ip_hash, created_at);

-- One spin for one device: enforces the per-device daily limit and a loose
-- per-network hourly cap, picks the prize and stores its code in one transaction.
CREATE OR REPLACE FUNCTION public.spin_wheel_guest(p_device text, p_ip text, p_code text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_today date := (now() AT TIME ZONE 'Europe/Istanbul')::date;
  v_hour timestamptz := date_trunc('hour', now());
  v_max integer;
  v_used integer;
  v_ip integer;
  v_idx integer;
  v_prize jsonb;
  v_code text := NULL;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('wheel_device:' || p_device));
  SELECT max_spins INTO v_max FROM public.wheel_settings WHERE id = 1;
  SELECT count INTO v_used FROM public.wheel_spins WHERE device_id = p_device AND day = v_today;
  v_used := COALESCE(v_used, 0);
  IF COALESCE(v_max, 0) > 0 AND v_used >= v_max THEN
    RETURN jsonb_build_object('status', 'device_limit', 'used', v_used);
  END IF;
  SELECT count INTO v_ip FROM public.wheel_ip_spins WHERE ip_hash = p_ip AND hour = v_hour;
  IF COALESCE(v_ip, 0) >= 60 THEN
    RETURN jsonb_build_object('status', 'ip_limit', 'used', v_used);
  END IF;

  v_idx := public.spin_wheel();
  IF v_idx IS NULL THEN
    RETURN jsonb_build_object('status', 'unavailable');
  END IF;
  SELECT prizes -> v_idx INTO v_prize FROM public.wheel_settings WHERE id = 1;

  INSERT INTO public.wheel_ip_spins (ip_hash, hour, count) VALUES (p_ip, v_hour, 1)
    ON CONFLICT (ip_hash, hour) DO UPDATE SET count = public.wheel_ip_spins.count + 1;
  INSERT INTO public.wheel_spins (device_id, day, count) VALUES (p_device, v_today, 1)
    ON CONFLICT (device_id, day) DO UPDATE SET count = public.wheel_spins.count + 1;
  DELETE FROM public.wheel_ip_spins WHERE hour < now() - interval '2 days';

  IF NOT COALESCE((v_prize ->> 'x')::boolean, false) THEN
    INSERT INTO public.wheel_claims (code, prize, expires_at)
      VALUES (p_code, v_prize ->> 't', ((v_today + 1)::timestamp AT TIME ZONE 'Europe/Istanbul'));
    v_code := p_code;
  END IF;

  RETURN jsonb_build_object('status', 'ok', 'index', v_idx, 'code', v_code, 'used', v_used + 1);
END;
$$;
REVOKE ALL ON FUNCTION public.spin_wheel_guest(text, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.spin_wheel_guest(text, text, text) TO service_role;

-- 3) Photo uploads: no public write rule on storage
DROP POLICY IF EXISTS "Passwordless menu photo upload" ON storage.objects;