create or replace function public.account_attachment_upload_limit_bytes(p_tier text)
returns bigint
language sql
immutable
as $$
  select case lower(coalesce(p_tier, 'bronze'))
    when 'silver' then 100 * 1024 * 1024
    when 'gold' then 500 * 1024 * 1024
    when 'platinum' then 1024 * 1024 * 1024
    else 25 * 1024 * 1024
  end::bigint;
$$;

create or replace function public.server_attachment_upload_limit_bytes(p_server_type text)
returns bigint
language sql
immutable
as $$
  select case lower(coalesce(p_server_type, 'stone'))
    when 'community' then 25 * 1024 * 1024
    when 'emerald' then 100 * 1024 * 1024
    when 'business_lite' then 100 * 1024 * 1024
    when 'ruby' then 500 * 1024 * 1024
    when 'business' then 500 * 1024 * 1024
    when 'diamond' then 1024 * 1024 * 1024
    when 'business_pro' then 1024 * 1024 * 1024
    else 25 * 1024 * 1024
  end::bigint;
$$;
