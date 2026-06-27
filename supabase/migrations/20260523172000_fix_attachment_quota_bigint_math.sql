create or replace function public.account_attachment_upload_limit_bytes(p_tier text)
returns bigint
language sql
immutable
as $$
  select case lower(coalesce(p_tier, 'bronze'))
    when 'silver' then 100::bigint * 1024 * 1024
    when 'gold' then 500::bigint * 1024 * 1024
    when 'platinum' then 1024::bigint * 1024 * 1024
    else 25::bigint * 1024 * 1024
  end;
$$;

create or replace function public.server_attachment_upload_limit_bytes(p_server_type text)
returns bigint
language sql
immutable
as $$
  select case lower(coalesce(p_server_type, 'stone'))
    when 'community' then 25::bigint * 1024 * 1024
    when 'emerald' then 100::bigint * 1024 * 1024
    when 'business_lite' then 100::bigint * 1024 * 1024
    when 'ruby' then 500::bigint * 1024 * 1024
    when 'business' then 500::bigint * 1024 * 1024
    when 'diamond' then 1024::bigint * 1024 * 1024
    when 'business_pro' then 1024::bigint * 1024 * 1024
    else 25::bigint * 1024 * 1024
  end;
$$;

create or replace function public.account_attachment_storage_quota_bytes(p_tier text)
returns bigint
language sql
immutable
as $$
  select case lower(coalesce(p_tier, 'bronze'))
    when 'silver' then 2::bigint * 1024 * 1024 * 1024
    when 'gold' then 10::bigint * 1024 * 1024 * 1024
    when 'platinum' then 25::bigint * 1024 * 1024 * 1024
    else 250::bigint * 1024 * 1024
  end;
$$;

create or replace function public.server_attachment_storage_quota_bytes(p_server_type text)
returns bigint
language sql
immutable
as $$
  select case lower(coalesce(p_server_type, 'stone'))
    when 'community' then 5::bigint * 1024 * 1024 * 1024
    when 'emerald' then 25::bigint * 1024 * 1024 * 1024
    when 'business_lite' then 25::bigint * 1024 * 1024 * 1024
    when 'ruby' then 100::bigint * 1024 * 1024 * 1024
    when 'business' then 100::bigint * 1024 * 1024 * 1024
    when 'diamond' then 250::bigint * 1024 * 1024 * 1024
    when 'business_pro' then 250::bigint * 1024 * 1024 * 1024
    else 5::bigint * 1024 * 1024 * 1024
  end;
$$;
