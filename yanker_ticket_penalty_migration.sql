-- YANKER: جدا کردن تیکت کافه از تیکت اعضا + پنل جریمه
-- این فایل را یک‌بار در Supabase SQL Editor اجرا کنید.

alter table if exists public.tickets
  add column if not exists category text not null default 'member';

update public.tickets
set category = 'member'
where category is null or trim(category) = '';

create index if not exists tickets_category_idx on public.tickets(category);
create index if not exists tickets_username_category_idx on public.tickets(username, category);

create table if not exists public.penalties (
  id uuid primary key,
  username text not null,
  name text not null default '',
  reason text not null,
  amount numeric not null default 0,
  issued_by text not null default '',
  created_at bigint not null
);

create index if not exists penalties_username_idx on public.penalties(username);
create index if not exists penalties_created_at_idx on public.penalties(created_at desc);

-- سرویس API با Service Role به این جدول دسترسی دارد؛ RLS را می‌توانید مطابق سیاست امنیتی فعلی پروژه تنظیم کنید.


create table if not exists public.site_users (
  id uuid primary key,
  username text unique not null,
  display_name text not null default '',
  password_hash text not null,
  role text not null default 'user',
  created_at bigint not null
);
create index if not exists site_users_username_idx on public.site_users(username);
