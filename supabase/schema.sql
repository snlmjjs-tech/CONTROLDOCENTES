-- =====================================================================
-- Control de permisos INCOSAF · esquema Supabase
-- Pegar completo en Supabase > SQL Editor > Run (una sola vez).
-- =====================================================================

-- ---------- Tablas ----------
create table if not exists public.usuarios (
  user_id uuid primary key references auth.users(id) on delete cascade,
  nombre  text not null,
  rol     text not null check (rol in ('inspector','kiosco'))
);

create table if not exists public.staff (
  rut        text primary key,
  nombre     text not null,
  cargo      text not null default '',
  area       text not null default '',
  activo     boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.perms (
  id         bigint generated always as identity primary key,
  rut        text not null references public.staff(rut) on update cascade,
  nombre     text not null,
  cargo      text not null default '',
  area       text not null default '',
  motivo     text not null check (motivo in ('personal','cometido','gremial')),
  detalle    text not null default '',
  destino    text not null default '',
  tarea      text not null default '',
  vuelta     text not null default '',
  t_out      timestamptz not null default now(),
  t_in       timestamptz,
  exc        boolean not null default false,
  auth       text not null default '',
  cierre_auto boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists perms_t_out_idx on public.perms (t_out desc);
create index if not exists perms_rut_idx   on public.perms (rut, t_out desc);
create index if not exists perms_open_idx  on public.perms (rut) where t_in is null;

create table if not exists public.settings (
  id          int primary key default 1 check (id = 1),
  limit_hours numeric not null default 6 check (limit_hours >= 0)
);
insert into public.settings (id) values (1) on conflict do nothing;

create table if not exists public.audit_log (
  id      bigint generated always as identity primary key,
  at      timestamptz not null default now(),
  usuario text not null,
  tabla   text not null,
  accion  text not null,
  fila_id text,
  antes   jsonb,
  despues jsonb
);
create index if not exists audit_at_idx on public.audit_log (at desc);

-- ---------- Funciones ----------
create or replace function public.es_usuario() returns boolean
language sql stable security definer set search_path = public as
$$ select exists (select 1 from public.usuarios where user_id = auth.uid()) $$;

create or replace function public.es_inspector() returns boolean
language sql stable security definer set search_path = public as
$$ select exists (select 1 from public.usuarios where user_id = auth.uid() and rol = 'inspector') $$;

-- Hora de salida/regreso: para el kiosco la fija el servidor (no el reloj del kiosco).
-- Los inspectores pueden corregir fecha y horas desde Administración (se valida y queda en la auditoría).
create or replace function public.fijar_regreso() returns trigger
language plpgsql as $$
begin
  if public.es_inspector() then
    if new.t_in is not null and new.t_in < new.t_out then raise exception 'El regreso no puede ser anterior a la salida'; end if;
    if new.t_out > now() + interval '5 minutes' then raise exception 'La salida no puede estar en el futuro'; end if;
    if new.t_in is not null and new.t_in > now() + interval '5 minutes' then raise exception 'El regreso no puede estar en el futuro'; end if;
    return new;
  end if;
  new.t_out := old.t_out;
  if old.t_in is not null then
    new.t_in := old.t_in; new.cierre_auto := old.cierre_auto;
  elsif new.t_in is not null then
    if new.cierre_auto then new.t_in := least(greatest(new.t_in, old.t_out), now());
    else new.t_in := now(); new.cierre_auto := false; end if;
  end if;
  return new;
end $$;
drop trigger if exists perms_fijar_regreso on public.perms;
create trigger perms_fijar_regreso before update on public.perms
for each row execute function public.fijar_regreso();

-- Bitácora: registra quién, cuándo y qué cambió.
create or replace function public.auditar() returns trigger
language plpgsql security definer set search_path = public as $$
declare j jsonb := case when tg_op = 'DELETE' then to_jsonb(old) else to_jsonb(new) end;
begin
  insert into public.audit_log (usuario, tabla, accion, fila_id, antes, despues)
  values (coalesce(auth.jwt() ->> 'email', current_user), tg_table_name, tg_op,
          coalesce(j ->> 'id', j ->> 'rut'),
          case when tg_op <> 'INSERT' then to_jsonb(old) end,
          case when tg_op <> 'DELETE' then to_jsonb(new) end);
  return null;
end $$;
drop trigger if exists staff_auditar    on public.staff;
drop trigger if exists perms_auditar    on public.perms;
drop trigger if exists settings_auditar on public.settings;
create trigger staff_auditar    after insert or update or delete on public.staff    for each row execute function public.auditar();
create trigger perms_auditar    after insert or update or delete on public.perms    for each row execute function public.auditar();
create trigger settings_auditar after insert or update or delete on public.settings for each row execute function public.auditar();

-- ---------- Permisos de acceso a la API ----------
-- Funciona con "Automatically expose new tables" desactivado (recomendado):
-- solo usuarios autenticados acceden, y las políticas RLS filtran qué filas.
revoke all on public.usuarios, public.staff, public.perms, public.settings, public.audit_log from anon;
grant usage on schema public to authenticated;
grant select on public.usuarios, public.audit_log to authenticated;
grant select, insert, update, delete on public.staff, public.perms to authenticated;
grant select, update on public.settings to authenticated;
grant usage, select on all sequences in schema public to authenticated;
revoke execute on function public.es_usuario(), public.es_inspector() from public, anon;
grant execute on function public.es_usuario(), public.es_inspector() to authenticated;

-- ---------- Seguridad (RLS) ----------
alter table public.usuarios  enable row level security;
alter table public.staff     enable row level security;
alter table public.perms     enable row level security;
alter table public.settings  enable row level security;
alter table public.audit_log enable row level security;

drop policy if exists usuarios_propio   on public.usuarios;
drop policy if exists staff_leer        on public.staff;
drop policy if exists staff_escribir    on public.staff;
drop policy if exists perms_leer        on public.perms;
drop policy if exists perms_insertar    on public.perms;
drop policy if exists perms_actualizar  on public.perms;
drop policy if exists perms_borrar      on public.perms;
drop policy if exists settings_leer     on public.settings;
drop policy if exists settings_editar   on public.settings;
drop policy if exists audit_leer        on public.audit_log;

create policy usuarios_propio  on public.usuarios for select to authenticated using (user_id = auth.uid());
create policy staff_leer       on public.staff    for select to authenticated using (public.es_usuario());
create policy staff_escribir   on public.staff    for all    to authenticated using (public.es_inspector()) with check (public.es_inspector());
create policy perms_leer       on public.perms    for select to authenticated using (public.es_usuario());
create policy perms_insertar   on public.perms    for insert to authenticated with check (public.es_usuario());
create policy perms_actualizar on public.perms    for update to authenticated using (public.es_usuario()) with check (public.es_usuario());
create policy perms_borrar     on public.perms    for delete to authenticated using (public.es_inspector());
create policy settings_leer    on public.settings for select to authenticated using (public.es_usuario());
create policy settings_editar  on public.settings for update to authenticated using (public.es_inspector()) with check (public.es_inspector());
create policy audit_leer       on public.audit_log for select to authenticated using (public.es_inspector());
-- audit_log no tiene políticas de escritura: solo los triggers escriben.

-- =====================================================================
-- Después de correr lo anterior: crear usuarios en Authentication > Users
-- (con "Auto Confirm User") y registrarlos así (cambiar correos/nombres):
--
-- insert into public.usuarios (user_id, nombre, rol)
-- select id, 'Nombre Inspector 1', 'inspector' from auth.users where email = 'inspector1@ejemplo.cl';
-- insert into public.usuarios (user_id, nombre, rol)
-- select id, 'Kiosco', 'kiosco' from auth.users where email = 'kiosco@ejemplo.cl';
-- =====================================================================

-- =====================================================================
-- Cambio de contraseñas desde la página (Administración > Configuración).
-- Solo inspectores. Queda registrado en la bitácora.
-- =====================================================================
drop policy if exists usuarios_leer_inspector on public.usuarios;
create policy usuarios_leer_inspector on public.usuarios for select to authenticated using (public.es_inspector());

create or replace function public.cambiar_clave(p_user uuid, p_nueva text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare v_nombre text;
begin
  if not public.es_inspector() then raise exception 'Sin permiso'; end if;
  if length(coalesce(p_nueva, '')) < 6 then raise exception 'La contraseña debe tener al menos 6 caracteres'; end if;
  select nombre into v_nombre from public.usuarios where user_id = p_user;
  if v_nombre is null then raise exception 'Cuenta no válida'; end if;
  update auth.users set encrypted_password = crypt(p_nueva, gen_salt('bf')), updated_at = now() where id = p_user;
  insert into public.audit_log (usuario, tabla, accion, fila_id, despues)
  values (coalesce(auth.jwt() ->> 'email', 'sistema'), 'usuarios', 'CAMBIO_CLAVE', p_user::text, jsonb_build_object('nombre', v_nombre));
end $$;
revoke all on function public.cambiar_clave(uuid, text) from public, anon;
grant execute on function public.cambiar_clave(uuid, text) to authenticated;

-- =====================================================================
-- Migración para bases ya creadas: horario laboral / cierre automático.
-- =====================================================================
alter table public.perms add column if not exists cierre_auto boolean not null default false;
create or replace function public.fijar_regreso() returns trigger
language plpgsql as $$
begin
  new.t_out := old.t_out;
  if old.t_in is not null then
    new.t_in := old.t_in; new.cierre_auto := old.cierre_auto;
  elsif new.t_in is not null then
    if new.cierre_auto then new.t_in := least(greatest(new.t_in, old.t_out), now());
    else new.t_in := now(); new.cierre_auto := false; end if;
  end if;
  return new;
end $$;

-- =====================================================================
-- Migración: los inspectores pueden corregir fecha y horas de un permiso.
-- =====================================================================
-- Hora de salida/regreso: para el kiosco la fija el servidor (no el reloj del kiosco).
-- Los inspectores pueden corregir fecha y horas desde Administración (se valida y queda en la auditoría).
create or replace function public.fijar_regreso() returns trigger
language plpgsql as $$
begin
  if public.es_inspector() then
    if new.t_in is not null and new.t_in < new.t_out then raise exception 'El regreso no puede ser anterior a la salida'; end if;
    if new.t_out > now() + interval '5 minutes' then raise exception 'La salida no puede estar en el futuro'; end if;
    if new.t_in is not null and new.t_in > now() + interval '5 minutes' then raise exception 'El regreso no puede estar en el futuro'; end if;
    return new;
  end if;
  new.t_out := old.t_out;
  if old.t_in is not null then
    new.t_in := old.t_in; new.cierre_auto := old.cierre_auto;
  elsif new.t_in is not null then
    if new.cierre_auto then new.t_in := least(greatest(new.t_in, old.t_out), now());
    else new.t_in := now(); new.cierre_auto := false; end if;
  end if;
  return new;
end $$;
