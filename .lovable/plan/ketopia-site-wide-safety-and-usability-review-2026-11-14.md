# Ketopia site-wide safety and usability review

## Goal
Make Ketopia safer, more dependable, easier to navigate, and more useful for keto beginners without exposing private health or account data.

## Work plan
1. **Close high-risk access gaps first.** Use the completed security scans to harden user subscription writes, paid course lesson/media access, admin-only article generation and publishing, notification email sending, and points/reward grants. Review the flagged database policies one by one: keep genuinely public recipes and reference content public, while limiting personal, account, and member activity to its owner or intended audience. Replace email-based admin shortcuts with the existing role checks.
2. **Fix confirmed user-facing bugs.** Make the public contact form submit safely without inventing an account owner, return signed-in visitors to the page they originally requested, and make hydration updates report save failures and handle a new day correctly.
3. **Protect privacy in tracking.** Associate signed-in product activity only with that user, keep guest activity anonymous, minimize retained attribution, and exclude health inputs, tracker pages, and sensitive URL data from marketing events. Keep server-side purchase events tied only to verified payment notifications; do not broaden collection of personal data.
4. **Simplify the experience.** Review the existing header and home screen and organize the main actions into a short beginner-friendly path (start here, meals, progress, community), keeping the full toolkit accessible without duplicate navigation. Use public keto-community discussions only as high-level topic inspiration—no member data or copied personal posts.
5. **Verify before finishing.** Re-run the security scan after changes, exercise the affected public and signed-in flows, inspect browser errors, and check the resulting build. Report any external account settings or full purchase flows that cannot be verified here.

## Technical details
- Database access changes will use a Supabase migration and preserve deliberate public read paths; owner-scoped records will stay tied to `auth.uid()`.
- Admin and payment entitlements will be checked using server-side roles and verified payment data, not client-visible email or local state.
- Tracking will use allowlisted event fields and clean page paths; private health data will not be sent to advertising platforms.
- Visual changes will use Ketopia's existing semantic design tokens and shadcn controls.

## Scope note
This is a broad review, so changes will prioritize confirmed breakage and high-impact security/privacy risks. A literal audit of every third-party account setting, deployed database state, and paid checkout cannot be completed without the relevant external access and credentials.