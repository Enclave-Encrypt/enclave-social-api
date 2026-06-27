-- Native DM packet encryption (AES-GCM envelope + shared epoch keys per MLS DM group).

alter table public.direct_messages
  add column if not exists msg_packet jsonb;

create table if not exists public.dm_key_epochs (
  id bigint generated always as identity primary key,
  mls_group_id bigint not null references public.mls_groups (id) on delete cascade,
  key_base64 text not null,
  created_by_user_id uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists dm_key_epochs_group_idx
  on public.dm_key_epochs (mls_group_id, id);

alter table public.direct_messages
  add column if not exists key_epoch_id bigint
    references public.dm_key_epochs (id) on delete set null;

alter table public.dm_key_epochs enable row level security;

drop policy if exists "DM group members can read dm key epochs" on public.dm_key_epochs;
create policy "DM group members can read dm key epochs"
  on public.dm_key_epochs
  for select
  to authenticated
  using (
    exists (
      select 1
      from public.mls_group_members mgm
      where mgm.mls_group_id = dm_key_epochs.mls_group_id
        and mgm.user_id = auth.uid()
        and mgm.membership_status = 'active'
    )
  );

create or replace function public.init_dm_key_epoch(
  p_mls_group_id bigint,
  p_key_base64 text
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  v_epoch_id bigint;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  if not exists (
    select 1
    from public.mls_group_members mgm
    where mgm.mls_group_id = p_mls_group_id
      and mgm.user_id = auth.uid()
      and mgm.membership_status = 'active'
  ) then
    raise exception 'Not a member of this DM group';
  end if;

  insert into public.dm_key_epochs (mls_group_id, key_base64, created_by_user_id)
  values (p_mls_group_id, p_key_base64, auth.uid())
  returning id into v_epoch_id;

  return v_epoch_id;
end;
$$;

grant execute on function public.init_dm_key_epoch(bigint, text) to authenticated;
