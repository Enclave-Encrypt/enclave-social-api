import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import * as jose from "https://deno.land/x/jose@v4.14.4/index.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

const DEFAULT_ACCOUNT_URL = "https://eyqaeigblulbtnorqyts.supabase.co";
const ACCOUNT_PROJECT_REF = "eyqaeigblulbtnorqyts";
const SOCIAL_DATA_PROJECT_REF = "kltykhkcvdwhfjgvevbt";

type AccountUser = {
  id: string;
  email?: string | null;
  user_metadata?: Record<string, unknown> | null;
};

function resolveAccountEmail(user: AccountUser): string {
  const direct = user.email?.trim();
  if (direct) {
    return direct;
  }

  const metadataEmail = String(user.user_metadata?.email ?? "").trim();
  if (metadataEmail) {
    return metadataEmail;
  }

  return `${user.id}@account.enclave.internal`;
}

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }

  try {
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    const json = atob(padded);
    return JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function readJwtProjectRef(token: string): string | null {
  const payload = decodeJwtPayload(token);
  const iss = typeof payload?.iss === "string" ? payload.iss : "";
  const match = iss.match(/https:\/\/([^.]+)\.supabase\.co/);
  return match?.[1] ?? null;
}

function accountAuthIssuer(accountUrl: string): string {
  return `${accountUrl.replace(/\/$/, "")}/auth/v1`;
}

async function verifyAccountAccessTokenWithJwks(
  accountUrl: string,
  accountToken: string,
): Promise<AccountUser | null> {
  try {
    const issuer = accountAuthIssuer(accountUrl);
    const jwks = jose.createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
    const { payload } = await jose.jwtVerify(accountToken, jwks, { issuer });
    const id = typeof payload.sub === "string" ? payload.sub : "";
    if (!id) {
      return null;
    }

    return {
      id,
      email: typeof payload.email === "string" ? payload.email : null,
      user_metadata:
        payload.user_metadata && typeof payload.user_metadata === "object"
          ? (payload.user_metadata as Record<string, unknown>)
          : {},
    };
  } catch {
    return null;
  }
}

async function verifyAccountAccessTokenWithApi(
  accountUrl: string,
  accountAnonKey: string,
  accountToken: string,
): Promise<AccountUser | null> {
  const accountClient = createClient(accountUrl, accountAnonKey, {
    global: { headers: { Authorization: `Bearer ${accountToken}` } },
  });

  const { data: userData, error: userError } = await accountClient.auth.getUser(
    accountToken,
  );
  const user = userData.user as AccountUser | null;
  if (userError || !user?.id) {
    return null;
  }

  return user;
}

async function verifyAccountAccessToken(
  accountUrl: string,
  accountAnonKey: string,
  accountToken: string,
): Promise<{ user: AccountUser } | { error: string }> {
  const projectRef = readJwtProjectRef(accountToken);
  if (projectRef === SOCIAL_DATA_PROJECT_REF) {
    return {
      error:
        "Bearer token is a Social JWT, not an Account JWT. Sign out and sign in again through account.enclave.talk.",
    };
  }

  if (projectRef && projectRef !== ACCOUNT_PROJECT_REF) {
    return {
      error: `Bearer token issuer is unexpected (${projectRef}). Sign in again through account.enclave.talk.`,
    };
  }

  const jwksUser = await verifyAccountAccessTokenWithJwks(accountUrl, accountToken);
  if (jwksUser) {
    return { user: jwksUser };
  }

  const apiUser = await verifyAccountAccessTokenWithApi(
    accountUrl,
    accountAnonKey,
    accountToken,
  );
  if (apiUser) {
    return { user: apiUser };
  }

  return { error: "Invalid Account session: token expired or not issued by Enclave Account" };
}

function readServiceRoleKey(): string {
  const direct = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")?.trim();
  if (direct) return direct;

  const secretKeysJson = Deno.env.get("SUPABASE_SECRET_KEYS");
  if (!secretKeysJson) return "";

  try {
    const parsed = JSON.parse(secretKeysJson) as Record<string, string>;
    return parsed.default?.trim() ?? parsed.service_role?.trim() ?? "";
  } catch {
    return "";
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const authHeader = req.headers.get("Authorization") ?? "";
    const accountToken = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!accountToken) {
      return new Response(JSON.stringify({ error: "Missing bearer token" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const accountUrl = Deno.env.get("ACCOUNT_SUPABASE_URL") ?? DEFAULT_ACCOUNT_URL;
    const accountAnonKey = Deno.env.get("ACCOUNT_SUPABASE_ANON_KEY") ?? "";
    const socialUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const serviceRoleKey = readServiceRoleKey();

    if (!accountAnonKey || !socialUrl || !serviceRoleKey) {
      return new Response(
        JSON.stringify({
          error:
            "Server missing ACCOUNT_SUPABASE_ANON_KEY or Social service role configuration",
        }),
        {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        },
      );
    }

    const verified = await verifyAccountAccessToken(
      accountUrl,
      accountAnonKey,
      accountToken,
    );
    if ("error" in verified) {
      return new Response(JSON.stringify({ error: verified.error }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const user = verified.user;

    const accountEmail = resolveAccountEmail(user);

    const socialAdmin = createClient(socialUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const { error: createError } = await socialAdmin.auth.admin.createUser({
      id: user.id,
      email: accountEmail,
      email_confirm: true,
      user_metadata: user.user_metadata ?? {},
      app_metadata: user.app_metadata ?? {},
    });

    if (createError && !createError.message.toLowerCase().includes("already")) {
      return new Response(
        JSON.stringify({ error: `Social user sync failed: ${createError.message}` }),
        {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        },
      );
    }

    const { data: linkData, error: linkError } = await socialAdmin.auth.admin.generateLink({
      type: "magiclink",
      email: accountEmail,
    });

    const tokenHash = linkData?.properties?.hashed_token;
    if (linkError || !tokenHash) {
      return new Response(
        JSON.stringify({
          error: linkError?.message ?? "Failed to create Social session link",
        }),
        {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        },
      );
    }

    const { data: sessionData, error: sessionError } = await socialAdmin.auth.verifyOtp({
      token_hash: tokenHash,
      type: "email",
    });

    const accessToken = sessionData?.session?.access_token;
    if (sessionError || !accessToken) {
      return new Response(
        JSON.stringify({
          error: sessionError?.message ?? "Failed to mint Social session",
        }),
        {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        },
      );
    }

    return new Response(
      JSON.stringify({
        access_token: accessToken,
        refresh_token: sessionData.session?.refresh_token ?? null,
        token_type: "bearer",
        expires_in: sessionData.session?.expires_in ?? 3600,
        user_id: user.id,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
