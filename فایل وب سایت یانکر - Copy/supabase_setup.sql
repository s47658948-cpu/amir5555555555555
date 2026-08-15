-- Run this once in Supabase SQL Editor.
-- The existing members/requests tables remain unchanged.

create table if not exists public.announcements (
  id text primary key,
  title text not null,
  body text not null,
  author text not null default 'owner',
  created_at bigint not null,
  published boolean not null default true
);

create table if not exists public.tickets (
  id text primary key,
  username text not null,
  name text not null,
  subject text not null,
  status text not null default 'open' check (status in ('open','answered','closed')),
  created_at bigint not null,
  updated_at bigint not null
);

create table if not exists public.ticket_messages (
  id text primary key,
  ticket_id text not null references public.tickets(id) on delete cascade,
  sender text not null check (sender in ('user','admin')),
  sender_name text not null,
  body text not null,
  created_at bigint not null
);

create index if not exists announcements_created_at_idx on public.announcements(created_at desc);
create index if not exists tickets_username_idx on public.tickets(username);
create index if not exists tickets_updated_at_idx on public.tickets(updated_at desc);
create index if not exists ticket_messages_ticket_id_idx on public.ticket_messages(ticket_id, created_at);

alter table public.announcements enable row level security;
alter table public.tickets enable row level security;
alter table public.ticket_messages enable row level security;

-- The Netlify function uses the Supabase service-role key, so it bypasses RLS.
-- No public policies are needed for these tables.
