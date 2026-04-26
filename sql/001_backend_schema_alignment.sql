-- Align Supabase/Postgres schema with the current Go backend repositories.
-- Safe to run on an empty or partially provisioned database.

create extension if not exists pgcrypto;

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  username text not null unique,
  first_name text,
  last_name text,
  password_hash text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_login timestamptz
);

create table if not exists public.user_sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  session_token text not null unique,
  ip_address inet,
  user_agent text,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  last_accessed timestamptz not null default now(),
  is_active boolean not null default true
);

create index if not exists idx_user_sessions_user_id
  on public.user_sessions(user_id);

create index if not exists idx_user_sessions_active
  on public.user_sessions(user_id, is_active, last_accessed desc);

create table if not exists public.passwords (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  category_id uuid,
  website text not null,
  username text,
  email text,
  password_encrypted text not null,
  notes_encrypted text,
  url text,
  is_favorite boolean not null default false,
  password_strength integer not null default 0,
  tags text[] not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  accessed_at timestamptz not null default now(),
  access_count integer not null default 0
);

create index if not exists idx_passwords_user_id
  on public.passwords(user_id);

create index if not exists idx_passwords_user_updated
  on public.passwords(user_id, updated_at desc, created_at desc);

create table if not exists public.wifi_passwords (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  network_name text not null,
  password_encrypted text not null,
  security_type text not null,
  notes_encrypted text,
  location text,
  is_favorite boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  accessed_at timestamptz not null default now(),
  access_count integer not null default 0
);

create index if not exists idx_wifi_passwords_user_id
  on public.wifi_passwords(user_id);

create index if not exists idx_wifi_passwords_user_updated
  on public.wifi_passwords(user_id, updated_at desc, created_at desc);

alter table if exists public.audit_logs
  add column if not exists ip_address inet,
  add column if not exists user_agent text;

alter table if exists public.profiles
  add column if not exists password_hash text,
  add column if not exists last_login timestamptz;
