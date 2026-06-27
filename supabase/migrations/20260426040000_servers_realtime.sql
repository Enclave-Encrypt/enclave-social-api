alter table public.servers replica identity full;

do $$
begin
  begin
    alter publication supabase_realtime add table public.servers;
  exception
    when duplicate_object then null;
  end;
end
$$;
