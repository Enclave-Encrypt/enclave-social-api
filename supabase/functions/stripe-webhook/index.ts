import Stripe from 'https://esm.sh/stripe@13.10.0?target=deno';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY') ?? '', {
  apiVersion: '2023-10-16',
  httpClient: Stripe.createFetchHttpClient(),
});

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, stripe-signature',
};

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  const signature = req.headers.get('stripe-signature');
  const webhookSecret = Deno.env.get('STRIPE_WEBHOOK_SECRET') ?? '';

  let event: Stripe.Event;
  try {
    const body = await req.text();
    event = await stripe.webhooks.constructEventAsync(body, signature!, webhookSecret);
  } catch (err: any) {
    console.error('Webhook signature verification failed:', err.message);
    return new Response(
      JSON.stringify({ error: `Webhook Error: ${err.message}` }),
      { status: 400, headers: corsHeaders },
    );
  }

  const supabase = createClient(
    Deno.env.get('SUPABASE_URL') ?? '',
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
  );

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object as Stripe.Checkout.Session;
      const metadata = session.metadata as Record<string, string | undefined>;

      if (
        session.mode === 'payment' &&
        (metadata.kind === 'platform_token_pack' || metadata.kind === 'platform_key_pack')
      ) {
        if (session.payment_status !== 'paid') {
          console.warn('Token checkout completed before payment was paid:', session.id, session.payment_status);
        } else {
          const authId = session.client_reference_id;
          const customerId = typeof session.customer === 'string' ? session.customer : null;
          const quantity = Number(metadata.quantity);

          if (authId && Number.isFinite(quantity) && quantity > 0) {
            await supabase.rpc('apply_platform_token_purchase', {
              p_user_id: authId,
              p_quantity: quantity,
              p_stripe_customer_id: customerId,
              p_checkout_session_id: session.id,
            });
          }
        }
      }

    }

    if (event.type === 'account.updated') {
      const account = event.data.object as Stripe.Account;
      const userId = account.metadata?.enclave_user_id?.trim();
      const accountId = account.id?.trim();

      if (userId && accountId) {
        await supabase.rpc('set_creator_stripe_account', {
          p_user_id: userId,
          p_stripe_account_id: accountId,
        });
      }
    }
  } catch (err: any) {
    console.error('Handler error:', err);
    return new Response(
      JSON.stringify({ error: 'Internal handler error' }),
      { status: 500, headers: corsHeaders },
    );
  }

  return new Response(
    JSON.stringify({ received: true }),
    { headers: { ...corsHeaders, 'Content-Type': 'application/json' } },
  );
});
