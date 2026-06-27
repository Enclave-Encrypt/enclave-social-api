import Stripe from 'https://esm.sh/stripe@13.10.0?target=deno';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY') ?? '', {
  apiVersion: '2023-10-16',
  httpClient: Stripe.createFetchHttpClient(),
});

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get('Authorization') ?? '';
    const token = authHeader.replace(/^Bearer\s+/i, '');
    if (!token) {
      return new Response(
        JSON.stringify({ error: 'Missing auth token' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    const supabase = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      { global: { headers: { Authorization: `Bearer ${token}` } } },
    );
    const serviceSupabase = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
    );

    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    const { returnUrl, refreshUrl } = await req.json();
    const safeReturnUrl = String(returnUrl ?? 'https://social.enclave.talk/web/?connect_return=1');
    const safeRefreshUrl = String(refreshUrl ?? safeReturnUrl);

    const { data: accountRow, error: accountError } = await supabase.rpc('get_my_account');
    if (accountError) {
      throw new Error(accountError.message);
    }

    const existingAccountId =
      typeof accountRow?.creator_stripe_account_id === 'string'
        ? accountRow.creator_stripe_account_id.trim()
        : '';

    let stripeAccountId = existingAccountId;

    if (!stripeAccountId) {
      const created = await stripe.accounts.create({
        type: 'express',
        country: 'US',
        email: user.email ?? undefined,
        capabilities: {
          transfers: { requested: true },
        },
        metadata: {
          enclave_user_id: user.id,
          product: 'enclave-social',
        },
      });

      stripeAccountId = created.id;

      const { error: linkError } = await serviceSupabase.rpc('set_creator_stripe_account', {
        p_user_id: user.id,
        p_stripe_account_id: stripeAccountId,
      });
      if (linkError) {
        throw new Error(linkError.message);
      }
    }

    const account = await stripe.accounts.retrieve(stripeAccountId);
    const payoutsEnabled = Boolean(account.payouts_enabled);
    const detailsSubmitted = Boolean(account.details_submitted);

    if (payoutsEnabled && detailsSubmitted) {
      return new Response(
        JSON.stringify({
          connected: true,
          stripe_account_id: stripeAccountId,
        }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    const link = await stripe.accountLinks.create({
      account: stripeAccountId,
      refresh_url: safeRefreshUrl,
      return_url: safeReturnUrl,
      type: 'account_onboarding',
    });

    return new Response(
      JSON.stringify({
        url: link.url,
        connected: false,
        stripe_account_id: stripeAccountId,
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  } catch (error: any) {
    return new Response(
      JSON.stringify({ error: error.message ?? 'Connect onboarding failed' }),
      { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  }
});
