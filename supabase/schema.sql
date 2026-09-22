-- Анкета AD Bridal: одна запись с ответами, файлы, пароль.
-- Таблицы закрыты RLS без политик: читать и писать можно только через функции ниже, и только с паролем.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.brief (
  id int primary key default 1 check (id = 1),
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);
insert into public.brief (id) values (1) on conflict (id) do nothing;

create table if not exists public.brief_secret (
  id int primary key default 1 check (id = 1),
  pass_hash text not null
);

create table if not exists public.brief_file (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  mime text not null,
  data bytea not null,
  created_at timestamptz not null default now()
);

alter table public.brief enable row level security;
alter table public.brief_secret enable row level security;
alter table public.brief_file enable row level security;

create or replace function public._brief_check(p_pass text) returns void
language plpgsql stable security definer set search_path = public, extensions as $$
begin
  if p_pass is null or not exists (select 1 from brief_secret where pass_hash = crypt(p_pass, pass_hash)) then
    raise exception 'bad_password' using errcode = '28P01';
  end if;
end $$;

-- jsonb_set, который создаёт недостающие вложенные объекты
create or replace function public._brief_jset(target jsonb, path text[], val jsonb) returns jsonb
language plpgsql immutable set search_path = public as $$
declare i int;
begin
  for i in 1 .. coalesce(array_length(path, 1), 0) - 1 loop
    if jsonb_typeof(target #> path[1:i]) is distinct from 'object' then
      target := jsonb_set(target, path[1:i], '{}'::jsonb, true);
    end if;
  end loop;
  return jsonb_set(target, path, coalesce(val, 'null'::jsonb), true);
end $$;

create or replace function public.brief_load(p_pass text) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _brief_check(p_pass);
  return (select data from brief where id = 1);
end $$;

-- p_patch: [{"p": ["m","sign","on"], "v": true}, ...]
create or replace function public.brief_save(p_pass text, p_patch jsonb) returns timestamptz
language plpgsql security definer set search_path = public, extensions as $$
declare d jsonb; e jsonb; t timestamptz;
begin
  perform _brief_check(p_pass);
  if jsonb_typeof(p_patch) is distinct from 'array' or jsonb_array_length(p_patch) > 500 then
    raise exception 'bad_patch';
  end if;
  select data into d from brief where id = 1 for update;
  for e in select * from jsonb_array_elements(p_patch) loop
    d := _brief_jset(d, array(select jsonb_array_elements_text(e -> 'p')), e -> 'v');
  end loop;
  if pg_column_size(d) > 2000000 then raise exception 'too_big'; end if;
  update brief set data = d, updated_at = now() where id = 1 returning updated_at into t;
  return t;
end $$;

create or replace function public.brief_file_put(p_pass text, p_name text, p_mime text, p_b64 text) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare new_id uuid;
begin
  perform _brief_check(p_pass);
  if length(p_b64) > 11500000 then raise exception 'file_too_big'; end if;
  insert into brief_file (name, mime, data) values (left(p_name, 200), left(p_mime, 100), decode(p_b64, 'base64'))
    returning id into new_id;
  return new_id;
end $$;

create or replace function public.brief_file_get(p_pass text, p_id uuid) returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform _brief_check(p_pass);
  return (select jsonb_build_object('name', name, 'mime', mime, 'b64', replace(encode(data, 'base64'), E'\n', '')) from brief_file where id = p_id);
end $$;

revoke all on function public._brief_check(text) from public, anon, authenticated;
revoke all on function public._brief_jset(jsonb, text[], jsonb) from public, anon, authenticated;
revoke all on function public.brief_load(text) from public, anon, authenticated;
revoke all on function public.brief_save(text, jsonb) from public, anon, authenticated;
revoke all on function public.brief_file_put(text, text, text, text) from public, anon, authenticated;
revoke all on function public.brief_file_get(text, uuid) from public, anon, authenticated;
grant execute on function public.brief_load(text) to anon;
grant execute on function public.brief_save(text, jsonb) to anon;
grant execute on function public.brief_file_put(text, text, text, text) to anon;
grant execute on function public.brief_file_get(text, uuid) to anon;

-- Пароль задаётся отдельно, не в этом файле:
-- insert into public.brief_secret (id, pass_hash) values (1, extensions.crypt('ПАРОЛЬ', extensions.gen_salt('bf')))
--   on conflict (id) do update set pass_hash = excluded.pass_hash;
