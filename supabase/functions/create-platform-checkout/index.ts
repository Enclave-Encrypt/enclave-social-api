import Stripe from 'https://esm.sh/stripe@13.10.0?target=deno';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY') ?? '', {
  apiVersion: '2023-10-16',
  httpClient: Stripe.createFetchHttpClient(),
});

const TOKEN_PACKS: Record<string, { label: string; cents: number; quantity: number }> = {
  token_pack_100: { label: '100 Enclave Social Tokens', cents: 100, quantity: 100 },
  token_pack_500: { label: '500 Enclave Social Tokens', cents: 500, quantity: 500 },
  token_pack_2500: { label: '2,500 Enclave Social Tokens', cents: 2500, quantity: 2500 },
};

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
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized' }),
        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    const { kind, planKey, quantity, successUrl, cancelUrl } = await req.json();
    const originSuccess = successUrl ?? 'https://enclave.talk/?billing_success=1';
    const originCancel = cancelUrl ?? 'https://enclave.talk/?billing_cancel=1';

    if (kind === 'platform_token_pack') {
      const requestedQuantity = Number(quantity);
      const customQuantity =
        String(planKey) === 'custom_token_pack' && Number.isFinite(requestedQuantity)
          ? Math.round(requestedQuantity)
          : null;
      const pack = customQuantity
        ? { label: `${customQuantity.toLocaleString()} Enclave Social Tokens`, cents: customQuantity, quantity: customQuantity }
        : TOKEN_PACKS[String(planKey)];
      if (!pack) {
        return new Response(
          JSON.stringify({ error: 'Invalid token pack' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
        );
      }
      if (pack.quantity < 100 || pack.quantity > 100000) {
        return new Response(
          JSON.stringify({ error: 'Token purchases must be between 100 and 100,000 tokens' }),
          { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
        );
      }

      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        mode: 'payment',
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: {
                name: pack.label,
              },
              unit_amount: pack.cents,
            },
            quantity: 1,
          },
        ],
        client_reference_id: user.id,
        success_url: originSuccess,
        cancel_url: originCancel,
        metadata: {
          kind: 'platform_token_pack',
          plan_key: String(planKey),
          quantity: String(pack.quantity),
          user_id: user.id,
        },
      });

      return new Response(
        JSON.stringify({ url: session.url }),
        { headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
      );
    }

    return new Response(
      JSON.stringify({ error: 'Invalid billing kind' }),
      { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  } catch (error: any) {
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
    );
  }
});
