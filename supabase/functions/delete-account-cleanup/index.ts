import Stripe from 'https://esm.sh/stripe@13.10.0?target=deno';
import { createClient, type SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2';

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY') ?? '', {
  apiVersion: '2023-10-16',
  httpClient: Stripe.createFetchHttpClient(),
});

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers':
    'authorization, x-client-info, apikey, content-type, x-account-deletion-secret',
};

type StorageObjectRef = {
  bucket: string;
  path: string;
};

function uniqueStrings(values: unknown): string[] {
  if (!Array.isArray(values)) return [];
  return [...new Set(values.filter((value): value is string => typeof value === 'string' && value.length > 0))];
}

function parseStorageObjects(values: unknown): StorageObjectRef[] {
  if (!Array.isArray(values)) return [];
  const seen = new Set<string>();
  const objects: StorageObjectRef[] = [];
  for (const entry of values) {
    if (!entry || typeof entry !== 'object') continue;
    const bucket = (entry as StorageObjectRef).bucket;
    const path = (entry as StorageObjectRef).path;
    if (typeof bucket !== 'string' || typeof path !== 'string') continue;
    const trimmedBucket = bucket.trim();
    const trimmedPath = path.trim();
    if (!trimmedBucket || !trimmedPath) continue;
    const key = `${trimmedBucket}:${trimmedPath}`;
    if (seen.has(key)) continue;
    seen.add(key);
    objects.push({ bucket: trimmedBucket, path: trimmedPath });
  }
  return objects;
}

async function cancelSubscription(subscriptionId: string) {
  try {
    const subscription = await stripe.subscriptions.retrieve(subscriptionId);
    if (subscription.status === 'canceled') return;
    await stripe.subscriptions.cancel(subscriptionId);
  } catch (error: any) {
    const message = String(error?.message ?? error);
    if (message.includes('No such subscription')) return;
    console.warn(`Failed to cancel subscription ${subscriptionId}:`, message);
  }
}

async function deleteCustomer(customerId: string) {
  try {
    await stripe.customers.del(customerId);
  } catch (error: any) {
    const message = String(error?.message ?? error);
    if (message.includes('No such customer')) return;
    console.warn(`Failed to delete customer ${customerId}:`, message);
  }
}

async function removeStorageObjects(supabase: SupabaseClient, objects: StorageObjectRef[]) {
  const pathsByBucket = new Map<string, string[]>();
  for (const object of objects) {
    const paths = pathsByBucket.get(object.bucket) ?? [];
    paths.push(object.path);
    pathsByBucket.set(object.bucket, paths);
  }

  for (const [bucket, paths] of pathsByBucket) {
    if (paths.length === 0) continue;
    const { error } = await supabase.storage.from(bucket).remove(paths);
    if (error) {
      console.warn(`Failed to remove ${paths.length} object(s) from ${bucket}:`, error.message);
    }
  }
}

async function removeAvatarBucketFiles(supabase: SupabaseClient, userId: string) {
  const paths: string[] = [];

  const { data: rootFiles, error: rootError } = await supabase.storage.from('avatars').list('', {
    limit: 1000,
  });
  if (rootError) {
    console.warn(`Failed to list avatar root files for ${userId}:`, rootError.message);
  } else {
    for (const file of rootFiles ?? []) {
      if (file.name?.startsWith(`${userId}-`)) {
        paths.push(file.name);
      }
    }
  }

  const { data: bannerFiles, error: bannerError } = await supabase.storage
    .from('avatars')
    .list('banners', { limit: 1000 });
  if (bannerError) {
    console.warn(`Failed to list avatar banners for ${userId}:`, bannerError.message);
  } else {
    for (const file of bannerFiles ?? []) {
      if (file.name?.startsWith(`${userId}-`)) {
        paths.push(`banners/${file.name}`);
      }
    }
  }

  if (paths.length === 0) return 0;

  const uniquePaths = [...new Set(paths)];
  const { error } = await supabase.storage.from('avatars').remove(uniquePaths);
  if (error) {
    console.warn(`Failed to remove avatar files for ${userId}:`, error.message);
    return 0;
  }
  return uniquePaths.length;
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  const expectedSecret = Deno.env.get('ACCOUNT_DELETION_SECRET') ?? '';
  const providedSecret = req.headers.get('x-account-deletion-secret') ?? '';
  if (!expectedSecret || providedSecret !== expectedSecret) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }

  try {
    const body = await req.json();
    const userId = typeof body?.user_id === 'string' ? body.user_id : null;
    if (!userId) {
      return new Response(JSON.stringify({ error: 'user_id is required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
    );

    const subscriptionIds = uniqueStrings(body?.stripe_subscription_ids);
    const customerIds = uniqueStrings(body?.stripe_customer_ids);
    const storageObjects = parseStorageObjects(body?.storage_objects);

    for (const subscriptionId of subscriptionIds) {
      await cancelSubscription(subscriptionId);
    }

    for (const customerId of customerIds) {
      await deleteCustomer(customerId);
    }

    await removeStorageObjects(supabase, storageObjects);
    const removedAvatarFiles = await removeAvatarBucketFiles(supabase, userId);

    return new Response(
      JSON.stringify({
        ok: true,
        user_id: userId,
        canceled_subscriptions: subscriptionIds.length,
        deleted_customers: customerIds.length,
        removed_storage_objects: storageObjects.length,
        removed_avatar_files: removedAvatarFiles,
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  } catch (error: any) {
    console.error('delete-account-cleanup failed:', error);
    return new Response(
      JSON.stringify({ error: error?.message ?? 'Cleanup failed' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  }
});
