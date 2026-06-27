alter table public.user_devices enable row level security;
alter table public.device_bundles enable row level security;
alter table public.device_one_time_prekeys enable row level security;
alter table public.direct_message_device_envelopes enable row level security;

create policy "Users can read their own devices"
on public.user_devices
for select
to authenticated
using (user_id = auth.uid());

create policy "Users can create their own devices"
on public.user_devices
for insert
to authenticated
with check (user_id = auth.uid());

create policy "Users can update their own devices"
on public.user_devices
for update
to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());

create policy "Authenticated users can see active recipient devices"
on public.user_devices
for select
to authenticated
using (is_active = true);

create policy "Owners can read their own device bundles"
on public.device_bundles
for select
to authenticated
using (
  exists (
    select 1
    from public.user_devices ud
    where ud.id = user_device_id
      and ud.user_id = auth.uid()
  )
);

create policy "Authenticated users can read published bundles"
on public.device_bundles
for select
to authenticated
using (
  exists (
    select 1
    from public.user_devices ud
    where ud.id = user_device_id
      and ud.is_active = true
  )
);

create policy "Owners can insert their own device bundles"
on public.device_bundles
for insert
to authenticated
with check (
  exists (
    select 1
    from public.user_devices ud
    where ud.id = user_device_id
      and ud.user_id = auth.uid()
  )
);

create policy "Owners can update their own device bundles"
on public.device_bundles
for update
to authenticated
using (
  exists (
    select 1
    from public.user_devices ud
    where ud.id = user_device_id
      and ud.user_id = auth.uid()
  )
)
with check (
  exists (
    select 1
    from public.user_devices ud
    where ud.id = user_device_id
      and ud.user_id = auth.uid()
  )
);

create policy "Owners can read their own one-time prekeys"
on public.device_one_time_prekeys
for select
to authenticated
using (
  exists (
    select 1
    from public.user_devices ud
    where ud.id = user_device_id
      and ud.user_id = auth.uid()
  )
);

create policy "Owners can insert their own one-time prekeys"
on public.device_one_time_prekeys
for insert
to authenticated
with check (
  exists (
    select 1
    from public.user_devices ud
    where ud.id = user_device_id
      and ud.user_id = auth.uid()
  )
);

create policy "Owners can update their own one-time prekeys"
on public.device_one_time_prekeys
for update
to authenticated
using (
  exists (
    select 1
    from public.user_devices ud
    where ud.id = user_device_id
      and ud.user_id = auth.uid()
  )
)
with check (
  exists (
    select 1
    from public.user_devices ud
    where ud.id = user_device_id
      and ud.user_id = auth.uid()
  )
);

create policy "Users can read their DM envelopes"
on public.direct_message_device_envelopes
for select
to authenticated
using (
  sender_user_id = auth.uid()
  or recipient_user_id = auth.uid()
);

create policy "Users can insert envelopes from their own devices"
on public.direct_message_device_envelopes
for insert
to authenticated
with check (
  sender_user_id = auth.uid()
  and exists (
    select 1
    from public.user_devices ud
    where ud.id = sender_device_pk
      and ud.user_id = auth.uid()
      and ud.is_active = true
  )
);

create policy "Recipients can update delivery state"
on public.direct_message_device_envelopes
for update
to authenticated
using (recipient_user_id = auth.uid())
with check (recipient_user_id = auth.uid());
