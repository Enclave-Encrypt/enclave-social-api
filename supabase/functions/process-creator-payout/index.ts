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

type CreatorPayoutRow = {
  id: number;
  creator_user_id: string;
  amount_tokens: number;
  amount_usd_cents: number;
  status: string;
  stripe_account_id: string | null;
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

    const { payoutId } = await req.json();
    const safePayoutId = Number(payoutId);
    if (!Number.isFinite(safePayoutId) || safePayoutId <= 0) {
      return new Response(
        JSON.stringify({ error: 'Invalid payout id' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    const { data: payout, error: payoutError } = await supabase
      .from('creator_payouts')
      .select('id, creator_user_id, amount_tokens, amount_usd_cents, status, stripe_account_id')
      .eq('id', safePayoutId)
      .maybeSingle<CreatorPayoutRow>();

    if (payoutError || !payout) {
      return new Response(
        JSON.stringify({ error: 'Payout not found' }),
        { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    if (payout.creator_user_id !== user.id) {
      return new Response(
        JSON.stringify({ error: 'Forbidden' }),
        { status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    if (payout.status !== 'requested') {
      return new Response(
        JSON.stringify({ error: 'Payout is already processing or completed' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    const destination = payout.stripe_account_id?.trim();
    if (!destination) {
      return new Response(
        JSON.stringify({ error: 'Connect a payout account before cashing out' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    const account = await stripe.accounts.retrieve(destination);
    if (!account.payouts_enabled) {
      return new Response(
        JSON.stringify({ error: 'Finish Stripe payout setup before cashing out' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    const { error: processingError } = await serviceSupabase.rpc('mark_creator_payout_processing', {
      p_payout_id: safePayoutId,
    });
    if (processingError) {
      throw new Error(processingError.message);
    }

    try {
      const transfer = await stripe.transfers.create({
        amount: payout.amount_usd_cents,
        currency: 'usd',
        destination,
        metadata: {
          payout_id: String(safePayoutId),
          creator_user_id: user.id,
          product: 'enclave-social',
        },
      });

      const { error: completeError } = await serviceSupabase.rpc('complete_creator_payout', {
        p_payout_id: safePayoutId,
        p_stripe_transfer_id: transfer.id,
      });
      if (completeError) {
        throw new Error(completeError.message);
      }

      return new Response(
        JSON.stringify({
          ok: true,
          payout_id: safePayoutId,
          transfer_id: transfer.id,
        }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    } catch (transferError: any) {
      await serviceSupabase.rpc('fail_creator_payout', {
        p_payout_id: safePayoutId,
        p_reason: transferError?.message ?? 'transfer_failed',
      });
      throw transferError;
    }
  } catch (error: any) {
    return new Response(
      JSON.stringify({ error: error.message ?? 'Payout processing failed' }),
      { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  }
});
