-- =====================================================================
-- حساب المالك (واحد فقط) — نفّذه بعد supabase-schema.sql
-- الخطوة 1 (من لوحة Supabase، وليس من هنا):
--   Authentication ← Users ← Add user ← Create new user
--   Email:    ali7assansa3id@maktaby.app
--   Password: كلمة مرورك (لا تكتبها في أي ملف داخل GitHub)
--   فعّل خيار Auto Confirm User
-- الخطوة 2: نفّذ هذا الاستعلام:
-- =====================================================================
insert into public.profiles (user_id, office_id, username, full_name, role, permissions)
select id, null, 'ali7assansa3id', 'مالك النظام', 'owner', '[]'::jsonb
from auth.users
where lower(email) = 'ali7assansa3id@maktaby.app'
on conflict (user_id) do nothing;

-- للتأكد: يجب أن يظهر صف واحد بدور owner
select username, role from public.profiles where role = 'owner';
