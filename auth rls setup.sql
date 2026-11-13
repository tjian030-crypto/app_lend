-- ============================================================
-- 帳號、角色與權限設定（可重複執行）
-- 在 Supabase SQL Editor 整份貼上執行
--
-- 做了什麼：
--  1. 收回先前「未登入可查詢」的測試規則
--  2. 建立 profiles（角色與學號）與 admin_allowlist（授權管理者信箱）
--  3. 註冊時由資料庫強制驗證：學校信箱格式、學號一致；角色一律為 user
--  4. 一般使用者只能存取自己的經期紀錄；管理者另有管理權限
--  5. 使用者無法直接修改自己的角色；改角色只能透過管理者專用函式
-- ============================================================


-- ------------------------------------------------------------
-- 1. 收回測試用的開放規則
-- ------------------------------------------------------------
drop policy if exists "測試用：未登入可讀取指定使用者的紀錄" on public.period_records;
drop policy if exists "測試用：未登入可讀取所有紀錄" on public.period_records;
revoke all on public.period_records from anon;


-- ------------------------------------------------------------
-- 2. 資料表
-- ------------------------------------------------------------
create table if not exists public.profiles (
  id          uuid primary key references auth.users (id) on delete cascade,
  email       text not null,
  student_id  text unique,
  role        text not null default 'user' check (role in ('user', 'admin')),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  -- 一般使用者一定要有學號；管理者可以沒有
  constraint profiles_user_needs_student_id
    check (role = 'admin' or student_id is not null)
);

comment on table public.profiles is '使用者個人資料與角色（角色只能由後端或管理者函式變更）';

-- 授權成為管理者的信箱（一次性，建立帳號後自動移除）
create table if not exists public.admin_allowlist (
  email       text primary key,
  created_by  uuid references auth.users (id) on delete set null,
  created_at  timestamptz not null default now(),
  constraint admin_allowlist_email_lower check (email = lower(email))
);

alter table public.profiles enable row level security;
alter table public.admin_allowlist enable row level security;
alter table public.period_records enable row level security;

-- 前端角色一律不能直接寫入 profiles / admin_allowlist
revoke all on public.profiles from anon, authenticated;
revoke all on public.admin_allowlist from anon, authenticated;
grant select on public.profiles to authenticated;

-- 經期紀錄：只有登入者能操作，實際範圍由下方 RLS 決定
grant select, insert, update, delete on public.period_records to authenticated;


-- ------------------------------------------------------------
-- 3. 判斷是否為管理者（以 profiles 為準，不信任使用者可改的 metadata）
-- ------------------------------------------------------------
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = (select auth.uid()) and role = 'admin'
  );
$$;

revoke execute on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;


-- ------------------------------------------------------------
-- 4. 註冊驗證：新使用者建立時自動建立 profiles
--    - 信箱在 admin_allowlist → 角色 admin（由後端授權）
--    - 否則必須是「學號@o365.au.edu.tw」，且學號與信箱一致 → 角色固定為 user
--    驗證失敗會讓註冊整個失敗，直接呼叫 API 也無法繞過
-- ------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_email text := lower(trim(coalesce(new.email, '')));
  v_sid   text := lower(trim(coalesce(new.raw_user_meta_data ->> 'student_id', '')));
begin
  if exists (select 1 from public.admin_allowlist where email = v_email) then
    insert into public.profiles (id, email, student_id, role)
    values (new.id, v_email, null, 'admin');
    delete from public.admin_allowlist where email = v_email;
    return new;
  end if;

  if v_email !~ '^[a-z0-9]+@o365\.au\.edu\.tw$' then
    raise exception '註冊必須使用學校信箱（學號@o365.au.edu.tw）';
  end if;

  if v_sid = '' or v_sid <> split_part(v_email, '@', 1) then
    raise exception '學號與學校信箱不一致';
  end if;

  -- 角色一律為 user，不讀取任何使用者提供的角色資料
  insert into public.profiles (id, email, student_id, role)
  values (new.id, v_email, v_sid, 'user');

  return new;
end;
$$;

revoke execute on function public.handle_new_user() from public, anon, authenticated;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();


-- 一般使用者之後也不能把信箱改成非學校信箱
create or replace function public.handle_user_email_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_email text := lower(trim(coalesce(new.email, '')));
  v_role  text;
  v_sid   text;
begin
  select role, student_id into v_role, v_sid from public.profiles where id = new.id;

  if found then
    if v_role = 'user' and v_email <> v_sid || '@o365.au.edu.tw' then
      raise exception '一般使用者的信箱必須維持為 學號@o365.au.edu.tw';
    end if;
    update public.profiles set email = v_email, updated_at = now() where id = new.id;
  end if;

  return new;
end;
$$;

revoke execute on function public.handle_user_email_change() from public, anon, authenticated;

drop trigger if exists on_auth_user_email_changed on auth.users;
create trigger on_auth_user_email_changed
  after update of email on auth.users
  for each row
  when (old.email is distinct from new.email)
  execute function public.handle_user_email_change();


-- 幫已存在、且符合學校信箱格式的使用者補上 profiles（角色為 user）
insert into public.profiles (id, email, student_id, role)
select u.id, lower(u.email), split_part(lower(u.email), '@', 1), 'user'
from auth.users u
where lower(u.email) ~ '^[a-z0-9]+@o365\.au\.edu\.tw$'
on conflict (id) do nothing;


-- ------------------------------------------------------------
-- 5. RLS：profiles
-- ------------------------------------------------------------
drop policy if exists "使用者可查看自己的個人資料" on public.profiles;
drop policy if exists "管理者可查看所有個人資料" on public.profiles;

create policy "使用者可查看自己的個人資料"
  on public.profiles for select
  to authenticated
  using (id = (select auth.uid()));

create policy "管理者可查看所有個人資料"
  on public.profiles for select
  to authenticated
  using (public.is_admin());

-- profiles 沒有 insert / update / delete 規則：前端無法直接寫入，
-- 角色只能透過下方管理者函式或後台 SQL 變更


-- ------------------------------------------------------------
-- 6. RLS：period_records
-- ------------------------------------------------------------
drop policy if exists "使用者可讀取自己的紀錄" on public.period_records;
drop policy if exists "使用者可新增自己的紀錄" on public.period_records;
drop policy if exists "使用者可修改自己的紀錄" on public.period_records;
drop policy if exists "使用者可刪除自己的紀錄" on public.period_records;
drop policy if exists "管理者可讀取所有紀錄" on public.period_records;
drop policy if exists "管理者可新增紀錄" on public.period_records;
drop policy if exists "管理者可修改所有紀錄" on public.period_records;
drop policy if exists "管理者可刪除所有紀錄" on public.period_records;

create policy "使用者可讀取自己的紀錄"
  on public.period_records for select
  to authenticated
  using ((select auth.uid()) = user_id);

create policy "使用者可新增自己的紀錄"
  on public.period_records for insert
  to authenticated
  with check ((select auth.uid()) = user_id);

create policy "使用者可修改自己的紀錄"
  on public.period_records for update
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy "使用者可刪除自己的紀錄"
  on public.period_records for delete
  to authenticated
  using ((select auth.uid()) = user_id);

create policy "管理者可讀取所有紀錄"
  on public.period_records for select
  to authenticated
  using (public.is_admin());

create policy "管理者可新增紀錄"
  on public.period_records for insert
  to authenticated
  with check (public.is_admin());

create policy "管理者可修改所有紀錄"
  on public.period_records for update
  to authenticated
  using (public.is_admin())
  with check (public.is_admin());

create policy "管理者可刪除所有紀錄"
  on public.period_records for delete
  to authenticated
  using (public.is_admin());


-- ------------------------------------------------------------
-- 7. 管理者專用函式（函式內會再檢查呼叫者是否為管理者）
-- ------------------------------------------------------------

-- 授權：把既有使用者設為管理者，或改回一般使用者
create or replace function public.admin_set_role(p_user_id uuid, p_role text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception '沒有管理者權限' using errcode = '42501';
  end if;
  if p_role not in ('user', 'admin') then
    raise exception '無效的角色';
  end if;
  if p_user_id = (select auth.uid()) then
    raise exception '不能變更自己的角色';
  end if;

  update public.profiles
     set role = p_role, updated_at = now()
   where id = p_user_id;

  if not found then
    raise exception '找不到該使用者';
  end if;
end;
$$;

-- 建立：授權一個尚未註冊的信箱成為管理者（之後在後台邀請該信箱）
create or replace function public.admin_add_admin_email(p_email text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_email text := lower(trim(coalesce(p_email, '')));
begin
  if not public.is_admin() then
    raise exception '沒有管理者權限' using errcode = '42501';
  end if;
  if v_email !~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' then
    raise exception 'Email 格式不正確';
  end if;
  if exists (select 1 from auth.users where lower(email) = v_email) then
    raise exception '此信箱已註冊，請在使用者列表中將它設為管理者';
  end if;

  insert into public.admin_allowlist (email, created_by)
  values (v_email, (select auth.uid()))
  on conflict (email) do nothing;
end;
$$;

revoke execute on function public.admin_set_role(uuid, text) from public, anon;
revoke execute on function public.admin_add_admin_email(text) from public, anon;
grant execute on function public.admin_set_role(uuid, text) to authenticated;
grant execute on function public.admin_add_admin_email(text) to authenticated;


-- ------------------------------------------------------------
-- 8. 建立「第一位管理者」（只做一次，需要先有人能授權）
--    移除下面每行開頭的 --，把信箱換成你的，單獨執行；
--    再到 Dashboard → Authentication → Users → Invite user 邀請同一個信箱
-- ------------------------------------------------------------
-- insert into public.admin_allowlist (email) values ('管理者信箱@example.com')
-- on conflict do nothing;


-- ------------------------------------------------------------
-- 9. 建議刪除測試帳號（密碼已公開在文件中）
--    會連同該帳號的所有紀錄一併刪除。需要時移除開頭的 -- 再單獨執行
-- ------------------------------------------------------------
-- delete from auth.users where email = 'test@example.com';


-- ------------------------------------------------------------
-- 10. 檢查結果
--     預期：anon規則數 0、已開啟RLS資料表數 3、anon可查詢紀錄 false、
--           anon可執行管理函式 false
-- ------------------------------------------------------------
select
  (select count(*) from pg_policies
     where schemaname = 'public' and 'anon' = any (roles))                as anon規則數,
  (select count(*) from public.profiles)                                  as 個人資料數,
  (select count(*) from pg_tables
     where schemaname = 'public'
       and tablename in ('period_records', 'profiles', 'admin_allowlist')
       and rowsecurity)                                                   as 已開啟RLS資料表數,
  has_table_privilege('anon', 'public.period_records', 'select')          as anon可查詢紀錄,
  has_function_privilege('anon', 'public.admin_set_role(uuid, text)', 'execute') as anon可執行管理函式;
