-- Paid access: only trusted payment/admin systems may change subscription records.
DROP POLICY IF EXISTS "Users can insert own subscription" ON public.user_subscriptions;
DROP POLICY IF EXISTS "Users can update own subscription" ON public.user_subscriptions;
REVOKE INSERT, UPDATE, DELETE ON public.user_subscriptions FROM PUBLIC, anon, authenticated;

-- Course lesson rows contain media URLs/resources, so expose only previews or entitled content.
DROP POLICY IF EXISTS "Published lessons are public" ON public.course_lessons;
CREATE POLICY "Published preview lessons are public"
ON public.course_lessons FOR SELECT TO anon
USING (is_published AND is_preview);
CREATE POLICY "Entitled users can view published lessons"
ON public.course_lessons FOR SELECT TO authenticated
USING (is_published AND (is_preview OR public.user_has_course_access(auth.uid())));

-- Bind course-entitlement checks to the signed-in caller, not a caller-chosen account ID.
CREATE OR REPLACE FUNCTION public.user_has_course_access(p_user_id uuid)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF auth.uid() IS NULL OR p_user_id IS NULL THEN
    RETURN false;
  END IF;
  IF auth.uid() <> p_user_id AND NOT public.is_admin() THEN
    RETURN false;
  END IF;
  RETURN EXISTS (
    SELECT 1 FROM public.course_access WHERE user_id = p_user_id
  ) OR EXISTS (
    SELECT 1 FROM public.user_subscriptions
    WHERE user_id = p_user_id
      AND is_active = true
      AND plan_type IN ('vip', 'vip_lifetime')
      AND (expires_at IS NULL OR expires_at > now())
  );
END;
$$;
REVOKE ALL ON FUNCTION public.user_has_course_access(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.user_has_course_access(uuid) TO authenticated, service_role;

-- Subscription and payment-grant RPCs must not be callable by browser users.
CREATE OR REPLACE FUNCTION public.get_user_plan(p_user_id uuid)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_plan text;
  v_expires timestamptz;
  v_is_active boolean;
BEGIN
  IF auth.uid() IS NULL OR (auth.uid() <> p_user_id AND NOT public.is_admin()) THEN
    RAISE EXCEPTION 'Not authorized' USING ERRCODE = '42501';
  END IF;
  SELECT plan_type, expires_at, is_active
  INTO v_plan, v_expires, v_is_active
  FROM public.user_subscriptions
  WHERE user_id = p_user_id;
  IF NOT FOUND THEN RETURN 'free'; END IF;
  IF v_expires IS NOT NULL AND v_expires < now() THEN
    UPDATE public.user_subscriptions
    SET plan_type = 'free', is_active = false, payment_status = 'expired'
    WHERE user_id = p_user_id;
    RETURN 'free';
  END IF;
  IF NOT v_is_active THEN RETURN 'free'; END IF;
  RETURN COALESCE(v_plan, 'free');
END;
$$;
REVOKE ALL ON FUNCTION public.get_user_plan(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_user_plan(uuid) TO authenticated, service_role;
REVOKE ALL ON FUNCTION public.grant_ketopia_subscription(text, text, numeric, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.grant_ketopia_subscription(text, text, numeric, text, text) TO service_role;
REVOKE ALL ON FUNCTION public.grant_course_access(text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.grant_course_access(text, text) TO service_role;

-- Make public profile projections limited to identity and explicitly shared weight only.
CREATE OR REPLACE VIEW public.public_profiles WITH (security_barrier = true) AS
SELECT user_id, display_name, username, avatar_url, follower_count, following_count,
       NULL::text AS diet_type,
       NULL::text AS diet_preference,
       NULL::text AS country,
       NULL::text AS state,
       NULL::text AS city,
       NULL::text AS town,
       share_progress_publicly,
       CASE WHEN share_progress_publicly THEN current_weight ELSE NULL::numeric END AS current_weight,
       created_at
FROM public.profiles;

-- Restrict relationship and engagement records to users involved in them.
DROP POLICY IF EXISTS "Authenticated users can view memberships" ON public.community_members;
CREATE POLICY "Users can view their own community memberships"
ON public.community_members FOR SELECT TO authenticated
USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Anyone can view follows" ON public.user_follows;
CREATE POLICY "Users can view follows involving themselves"
ON public.user_follows FOR SELECT TO authenticated
USING (auth.uid() = follower_id OR auth.uid() = following_id);

DROP POLICY IF EXISTS "Anyone can view likes" ON public.challenge_post_likes;
CREATE POLICY "Users can view their own challenge likes"
ON public.challenge_post_likes FOR SELECT TO authenticated
USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Authenticated users can view likes" ON public.community_likes;
CREATE POLICY "Users can view their own community likes"
ON public.community_likes FOR SELECT TO authenticated
USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Authenticated users can view votes" ON public.recipe_votes;
CREATE POLICY "Users can view their own recipe votes"
ON public.recipe_votes FOR SELECT TO authenticated
USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Signed-in users can view badges" ON public.user_badges;
CREATE POLICY "Users can view their own earned badges"
ON public.user_badges FOR SELECT TO authenticated
USING (auth.uid() = user_id OR public.is_admin());
DROP POLICY IF EXISTS "Users can earn badges" ON public.user_badges;
REVOKE INSERT ON public.user_badges FROM anon, authenticated;

-- Users' custom meal copies are private; only approved community recipes are public.
DROP POLICY IF EXISTS "Anyone can view meals" ON public.meals;
CREATE POLICY "Users can view their own meals"
ON public.meals FOR SELECT TO authenticated
USING (auth.uid() = user_id OR public.is_admin());

DROP POLICY IF EXISTS "Anyone can view user recipes" ON public.user_recipes;
CREATE POLICY "Anyone can view approved user recipes"
ON public.user_recipes FOR SELECT TO anon, authenticated
USING (is_approved = true);
CREATE POLICY "Users can view their own unapproved recipes"
ON public.user_recipes FOR SELECT TO authenticated
USING (auth.uid() = user_id);

-- Only the public VIP video setting is readable without an admin role.
DROP POLICY IF EXISTS "site_settings public read" ON public.site_settings;
CREATE POLICY "Public can read the VIP video setting"
ON public.site_settings FOR SELECT TO anon, authenticated
USING (key = 'vip_video_url' OR public.is_admin());

-- Allow the public contact form to be handled by a validated server function.
ALTER TABLE public.user_messages ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE public.user_messages ADD COLUMN IF NOT EXISTS contact_email text;

-- Reward ledger: each saved activity can earn its fixed reward only once.
CREATE TABLE public.user_point_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  action text NOT NULL,
  reference_id uuid NOT NULL,
  points integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, action, reference_id)
);
GRANT SELECT ON public.user_point_events TO authenticated;
GRANT ALL ON public.user_point_events TO service_role;
ALTER TABLE public.user_point_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can view their own point history"
ON public.user_point_events FOR SELECT TO authenticated
USING (auth.uid() = user_id OR public.is_admin());

CREATE OR REPLACE FUNCTION public.award_activity_points(p_action text, p_reference_id uuid)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_points integer := 0;
  v_reward integer;
  v_required_days integer;
  v_completed_days integer;
  v_inserted integer;
  v_total integer;
  v_level integer;
BEGIN
  IF v_user_id IS NULL OR p_reference_id IS NULL THEN
    RAISE EXCEPTION 'Sign in required' USING ERRCODE = '42501';
  END IF;

  CASE p_action
    WHEN 'log_weight' THEN
      IF EXISTS (SELECT 1 FROM public.weight_logs WHERE id = p_reference_id AND user_id = v_user_id) THEN v_points := 10; END IF;
    WHEN 'complete_keto_day' THEN
      IF EXISTS (SELECT 1 FROM public.keto_streaks WHERE id = p_reference_id AND user_id = v_user_id AND completed) THEN v_points := 15; END IF;
    WHEN 'complete_fast' THEN
      IF EXISTS (SELECT 1 FROM public.fasting_sessions WHERE id = p_reference_id AND user_id = v_user_id AND completed AND end_time IS NOT NULL AND end_time >= start_time + make_interval(hours => target_duration_hours)) THEN v_points := 20; END IF;
    WHEN 'log_workout' THEN
      IF EXISTS (SELECT 1 FROM public.workout_logs WHERE id = p_reference_id AND user_id = v_user_id) THEN v_points := 10; END IF;
    WHEN 'complete_water_goal' THEN
      IF EXISTS (SELECT 1 FROM public.water_logs WHERE id = p_reference_id AND user_id = v_user_id AND cups_consumed >= daily_goal) THEN v_points := 10; END IF;
    WHEN 'create_post' THEN
      IF EXISTS (SELECT 1 FROM public.community_posts WHERE id = p_reference_id AND user_id = v_user_id) THEN v_points := 5; END IF;
    WHEN 'like_post' THEN
      IF EXISTS (SELECT 1 FROM public.community_likes WHERE id = p_reference_id AND user_id = v_user_id) THEN v_points := 2; END IF;
    WHEN 'complete_challenge' THEN
      SELECT c.reward_points, c.duration_days INTO v_reward, v_required_days
      FROM public.user_challenges uc
      JOIN public.challenges c ON c.id = uc.challenge_id
      WHERE uc.id = p_reference_id AND uc.user_id = v_user_id AND uc.is_completed = true;
      IF FOUND THEN
        SELECT count(DISTINCT log_date)::integer INTO v_completed_days
        FROM public.challenge_daily_logs
        WHERE user_challenge_id = p_reference_id AND user_id = v_user_id AND completed = true AND log_date <= CURRENT_DATE;
        IF v_completed_days >= v_required_days THEN v_points := LEAST(GREATEST(COALESCE(v_reward, 0), 0), 500); END IF;
      END IF;
    ELSE
      RAISE EXCEPTION 'Unsupported reward action' USING ERRCODE = '22023';
  END CASE;

  IF v_points <= 0 THEN
    RAISE EXCEPTION 'Activity is not eligible for points' USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.user_point_events (user_id, action, reference_id, points)
  VALUES (v_user_id, p_action, p_reference_id, v_points)
  ON CONFLICT (user_id, action, reference_id) DO NOTHING;
  GET DIAGNOSTICS v_inserted = ROW_COUNT;
  IF v_inserted = 0 THEN RETURN 0; END IF;

  INSERT INTO public.user_progress (user_id, total_points, current_level)
  VALUES (v_user_id, v_points, 1)
  ON CONFLICT (user_id) DO UPDATE
  SET total_points = public.user_progress.total_points + v_points, updated_at = now();
  SELECT total_points INTO v_total FROM public.user_progress WHERE user_id = v_user_id;
  v_level := GREATEST(1, (v_total / 100) + 1);
  UPDATE public.user_progress SET current_level = v_level, updated_at = now() WHERE user_id = v_user_id;
  RETURN v_points;
END;
$$;
REVOKE ALL ON FUNCTION public.award_activity_points(text, uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.award_activity_points(text, uuid) TO authenticated;
REVOKE ALL ON FUNCTION public.award_points(integer) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.award_points(integer) TO service_role;

CREATE OR REPLACE FUNCTION public.award_challenge_badges(p_user_challenge_id uuid)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_user_id uuid := auth.uid();
  v_days integer;
  v_badges integer;
BEGIN
  IF v_user_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM public.user_challenges uc
    JOIN public.challenges c ON c.id = uc.challenge_id
    WHERE uc.id = p_user_challenge_id AND uc.user_id = v_user_id AND uc.is_completed = true
      AND (SELECT count(DISTINCT l.log_date) FROM public.challenge_daily_logs l
           WHERE l.user_challenge_id = uc.id AND l.user_id = v_user_id AND l.completed = true AND l.log_date <= CURRENT_DATE) >= c.duration_days
  ) THEN
    RAISE EXCEPTION 'Challenge completion is not verified' USING ERRCODE = '42501';
  END IF;
  SELECT count(*)::integer INTO v_days FROM public.user_challenges WHERE user_id = v_user_id AND is_completed = true;
  INSERT INTO public.user_badges (user_id, badge_id)
  SELECT v_user_id, b.id FROM public.badges b
  WHERE b.requirement_type = 'challenges_completed' AND b.requirement_value <= v_days
  ON CONFLICT (user_id, badge_id) DO NOTHING;
  GET DIAGNOSTICS v_badges = ROW_COUNT;
  RETURN v_badges;
END;
$$;
REVOKE ALL ON FUNCTION public.award_challenge_badges(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.award_challenge_badges(uuid) TO authenticated;