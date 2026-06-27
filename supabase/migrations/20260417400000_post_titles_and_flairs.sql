-- ─── Post Flairs ─────────────────────────────────────────────────────────────

create table if not exists post_flairs (
  id         uuid primary key default gen_random_uuid(),
  server_id  bigint not null references servers(id) on delete cascade,
  name       text not null,
  color      text,
  created_at timestamptz not null default now()
);

create index if not exists post_flairs_server_id_idx on post_flairs(server_id);

alter table post_flairs enable row level security;

do $$ begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'post_flairs' and policyname = 'post_flairs_select'
  ) then
    create policy "post_flairs_select" on post_flairs for select using (
      exists (
        select 1 from servers s
        where s.id = post_flairs.server_id
          and (
            s.visibility = 'public'
            or exists (
              select 1 from server_members sm
              where sm.server_id = s.id and sm.user_id = auth.uid()
            )
          )
      )
    );
  end if;
end $$;

do $$ begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'post_flairs' and policyname = 'post_flairs_insert'
  ) then
    create policy "post_flairs_insert" on post_flairs for insert with check (
      exists (
        select 1 from server_members sm
        where sm.server_id = post_flairs.server_id and sm.user_id = auth.uid()
      )
    );
  end if;
end $$;

do $$ begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'public' and tablename = 'post_flairs' and policyname = 'post_flairs_delete'
  ) then
    create policy "post_flairs_delete" on post_flairs for delete using (
      exists (
        select 1 from server_members sm
        where sm.server_id = post_flairs.server_id and sm.user_id = auth.uid()
      )
    );
  end if;
end $$;

-- ─── Extend posts ─────────────────────────────────────────────────────────────

alter table posts add column if not exists title   text not null default '';
alter table posts add column if not exists flair_id uuid references post_flairs(id) on delete set null;

create index if not exists posts_flair_id_idx on posts(flair_id) where flair_id is not null;
