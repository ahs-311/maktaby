-- =====================================================================
-- مكتبي الإلكتروني — مخطط قاعدة بيانات Supabase
-- نفّذه مرة واحدة: Supabase ← SQL Editor ← New query ← الصق ← Run
-- كل مكتب معزول عن الآخر عبر Row Level Security.
-- =====================================================================

-- ---------- 1) الجداول ----------
create table if not exists public.offices (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (char_length(btrim(name)) between 2 and 120),
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);

create table if not exists public.profiles (
  user_id     uuid primary key references auth.users(id) on delete cascade,
  office_id   uuid references public.offices(id) on delete cascade,
  username    text not null check (username ~ '^[a-z0-9._-]{3,30}$'),
  full_name   text not null check (char_length(btrim(full_name)) between 1 and 120),
  role        text not null check (role in ('owner','manager','lawyer','client')),
  permissions jsonb not null default '[]'::jsonb,
  client_id   text,
  extra       jsonb not null default '{}'::jsonb,
  active      boolean not null default true,
  created_at  timestamptz not null default now(),
  constraint office_required check (
    (role = 'owner' and office_id is null) or (role <> 'owner' and office_id is not null)
  )
);
create unique index if not exists profiles_username_uq on public.profiles (lower(username));
-- مالك واحد فقط في النظام كله
create unique index if not exists profiles_one_owner on public.profiles ((true)) where role = 'owner';
-- مدير واحد لكل مكتب (حساب المكتب = حساب المدير)
create unique index if not exists profiles_one_manager_per_office on public.profiles (office_id) where role = 'manager';
create index if not exists profiles_office_idx on public.profiles (office_id);

create table if not exists public.records (
  office_id   uuid not null references public.offices(id) on delete cascade,
  collection  text not null check (collection in (
    'attachments','bailiffs','cases','clients','docs','events','fin_entries','invoices',
    'ld_cases','ld_checklist','notes','poas','sessions','tasks','workdays','_meta'
  )),
  id          text not null,
  data        jsonb not null default '{}'::jsonb,
  deleted     boolean not null default false,
  updated_at  timestamptz not null default clock_timestamp(),
  updated_by  uuid,
  primary key (office_id, collection, id)
);
create index if not exists records_office_updated_idx on public.records (office_id, updated_at);

create or replace function public.mk_touch() returns trigger
language plpgsql as $$
begin
  new.updated_at := clock_timestamp();
  new.updated_by := auth.uid();
  return new;
end $$;

drop trigger if exists records_touch on public.records;
create trigger records_touch before insert or update on public.records
for each row execute function public.mk_touch();

-- ---------- 2) دوال مساعدة (تُستعمل داخل السياسات) ----------
create or replace function public.mk_role() returns text
language sql stable security definer set search_path = public as $$
  select p.role from public.profiles p where p.user_id = auth.uid() and p.active
$$;

create or replace function public.mk_office_id() returns uuid
language sql stable security definer set search_path = public as $$
  select p.office_id from public.profiles p where p.user_id = auth.uid() and p.active
$$;

create or replace function public.mk_client_id() returns text
language sql stable security definer set search_path = public as $$
  select p.client_id from public.profiles p where p.user_id = auth.uid() and p.active and p.role = 'client'
$$;

create or replace function public.mk_office_active(o uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select active from public.offices where id = o), false)
$$;

-- الموكّل يرى فقط السجلات المرتبطة بسجله
create or replace function public.mk_client_can_read(o uuid, c text, i text, d jsonb) returns boolean
language sql stable security definer set search_path = public as $$
  select case
    when public.mk_client_id() is null then false
    when c = 'clients' then i = public.mk_client_id()
    when c in ('cases','invoices','poas') then d->>'clientId' = public.mk_client_id()
    when c in ('sessions','events','tasks','notes','docs','attachments','bailiffs') then
      d->>'clientId' = public.mk_client_id()
      or exists (
        select 1 from public.records r
        where r.office_id = o and r.collection = 'cases' and r.id = d->>'caseId'
          and not r.deleted and r.data->>'clientId' = public.mk_client_id()
      )
    else false
  end
$$;

-- ---------- 3) الأمان (RLS) ----------
alter table public.offices  enable row level security;
alter table public.profiles enable row level security;
alter table public.records  enable row level security;

revoke all on public.offices, public.profiles, public.records from anon, authenticated;
grant select on public.offices, public.profiles to authenticated;
grant select, insert, update on public.records to authenticated;

drop policy if exists offices_select on public.offices;
create policy offices_select on public.offices for select to authenticated
using ( public.mk_role() = 'owner' or id = public.mk_office_id() );

drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
using (
  user_id = auth.uid()
  or public.mk_role() = 'owner'
  or ( office_id is not null and office_id = public.mk_office_id()
       and public.mk_role() in ('manager','lawyer') )
);

drop policy if exists records_select on public.records;
create policy records_select on public.records for select to authenticated
using (
  office_id = public.mk_office_id()
  and public.mk_office_active(office_id)
  and (
    public.mk_role() in ('manager','lawyer')
    or (public.mk_role() = 'client' and public.mk_client_can_read(office_id, collection, id, data))
  )
);

drop policy if exists records_insert on public.records;
create policy records_insert on public.records for insert to authenticated
with check (
  office_id = public.mk_office_id()
  and public.mk_office_active(office_id)
  and public.mk_role() in ('manager','lawyer')
);

drop policy if exists records_update on public.records;
create policy records_update on public.records for update to authenticated
using (
  office_id = public.mk_office_id()
  and public.mk_office_active(office_id)
  and public.mk_role() in ('manager','lawyer')
)
with check (
  office_id = public.mk_office_id()
  and public.mk_office_active(office_id)
  and public.mk_role() in ('manager','lawyer')
);
-- لا توجد سياسة حذف: الحذف يتم بعلامة deleted=true حتى تصل لكل الأجهزة.

-- ---------- 4) إجراءات الحسابات (RPC) ----------
-- إنشاء مكتب جديد + حساب المدير (يُستدعى بعد تسجيل المستخدم في Auth)
create or replace function public.create_office(
  p_office_name text, p_full_name text, p_username text, p_permissions jsonb default '[]'::jsonb
) returns uuid
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  v_office uuid;
  v_user text := lower(btrim(p_username));
begin
  if v_uid is null then raise exception 'not_authenticated'; end if;
  if exists (select 1 from public.profiles where user_id = v_uid) then raise exception 'profile_exists'; end if;
  if v_user !~ '^[a-z0-9._-]{3,30}$' then raise exception 'bad_username'; end if;
  if not exists (select 1 from auth.users where id = v_uid and lower(email) = v_user || '@maktaby.app') then
    raise exception 'username_mismatch';
  end if;
  insert into public.offices(name) values (btrim(p_office_name)) returning id into v_office;
  insert into public.profiles(user_id, office_id, username, full_name, role, permissions)
  values (v_uid, v_office, v_user, btrim(p_full_name), 'manager', coalesce(p_permissions, '[]'::jsonb));
  return v_office;
end $$;

-- إضافة محامٍ/موكّل (المدير فقط، داخل مكتبه فقط)
create or replace function public.add_member(
  p_user_id uuid, p_username text, p_full_name text, p_role text,
  p_permissions jsonb default '[]'::jsonb, p_client_id text default null, p_extra jsonb default '{}'::jsonb
) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_me public.profiles;
  v_user text := lower(btrim(p_username));
begin
  select * into v_me from public.profiles where user_id = auth.uid() and active;
  if v_me.role is distinct from 'manager' then raise exception 'forbidden'; end if;
  if not public.mk_office_active(v_me.office_id) then raise exception 'office_inactive'; end if;
  if p_role not in ('lawyer','client') then raise exception 'bad_role'; end if;
  if p_role = 'client' and coalesce(p_client_id,'') = '' then raise exception 'client_required'; end if;
  if v_user !~ '^[a-z0-9._-]{3,30}$' then raise exception 'bad_username'; end if;
  if not exists (
    select 1 from auth.users
    where id = p_user_id and lower(email) = v_user || '@maktaby.app'
      and created_at > now() - interval '10 minutes'
  ) then raise exception 'invalid_target'; end if;
  if exists (select 1 from public.profiles where user_id = p_user_id) then raise exception 'profile_exists'; end if;
  insert into public.profiles(user_id, office_id, username, full_name, role, permissions, client_id, extra)
  values (p_user_id, v_me.office_id, v_user, btrim(p_full_name), p_role,
          coalesce(p_permissions,'[]'::jsonb), nullif(p_client_id,''), coalesce(p_extra,'{}'::jsonb));
end $$;

-- تعديل بيانات/صلاحيات/تفعيل عضو
create or replace function public.update_member(
  p_user_id uuid, p_full_name text, p_permissions jsonb, p_client_id text,
  p_extra jsonb, p_active boolean
) returns void
language plpgsql security definer set search_path = public as $$
declare v_me public.profiles; v_n int;
begin
  select * into v_me from public.profiles where user_id = auth.uid() and active;
  if v_me.role is distinct from 'manager' then raise exception 'forbidden'; end if;
  update public.profiles
     set full_name = coalesce(nullif(btrim(p_full_name),''), full_name),
         permissions = coalesce(p_permissions, permissions),
         client_id = case when role = 'client' then nullif(p_client_id,'') else null end,
         extra = coalesce(p_extra, extra),
         active = coalesce(p_active, active)
   where user_id = p_user_id and office_id = v_me.office_id and role in ('lawyer','client');
  get diagnostics v_n = row_count;
  if v_n = 0 then raise exception 'not_found'; end if;
end $$;

-- حذف عضو (يحذف حساب الدخول أيضًا)
create or replace function public.delete_member(p_user_id uuid) returns void
language plpgsql security definer set search_path = public as $$
declare v_me public.profiles;
begin
  select * into v_me from public.profiles where user_id = auth.uid() and active;
  if v_me.role is distinct from 'manager' then raise exception 'forbidden'; end if;
  if not exists (select 1 from public.profiles
                 where user_id = p_user_id and office_id = v_me.office_id and role in ('lawyer','client')) then
    raise exception 'not_found';
  end if;
  delete from auth.users where id = p_user_id;
end $$;

-- إيقاف/تفعيل مكتب (المالك فقط)
create or replace function public.set_office_active(p_office_id uuid, p_active boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.mk_role() is distinct from 'owner' then raise exception 'forbidden'; end if;
  update public.offices set active = p_active where id = p_office_id;
end $$;

-- صلاحيات التنفيذ: للمستخدمين المسجلين فقط
revoke execute on all functions in schema public from public, anon;
grant execute on function
  public.mk_role(), public.mk_office_id(), public.mk_client_id(), public.mk_office_active(uuid),
  public.mk_client_can_read(uuid, text, text, jsonb),
  public.create_office(text, text, text, jsonb),
  public.add_member(uuid, text, text, text, jsonb, text, jsonb),
  public.update_member(uuid, text, jsonb, text, jsonb, boolean),
  public.delete_member(uuid),
  public.set_office_active(uuid, boolean)
to authenticated;
