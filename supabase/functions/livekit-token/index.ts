import { AccessToken } from "livekit-server-sdk";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
};

const DEFAULT_LIVEKIT_URL = "wss://enclave-social-nwgzvm4x.livekit.cloud";

type LiveKitTokenRequest = {
  roomName?: string;
  participantName?: string;
  participantIdentity?: string;
};

function jsonResponse(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  try {
    const authHeader = req.headers.get("Authorization") ?? "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!token) {
      return jsonResponse({ error: "Missing auth token" }, 401);
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: `Bearer ${token}` } } },
    );
    const {
      data: { user },
      error: authError,
    } = await supabase.auth.getUser(token);
    if (authError || !user?.id) {
      return jsonResponse({ error: "Unauthorized" }, 401);
    }

    const body = (await req.json()) as LiveKitTokenRequest;
    const roomName = String(body.roomName ?? "").trim();
    const participantName = String(body.participantName ?? "").trim() || "Participant";
    const participantIdentity = String(body.participantIdentity ?? "").trim();

    if (!roomName) {
      return jsonResponse({ error: "roomName is required" }, 400);
    }
    if (!participantIdentity) {
      return jsonResponse({ error: "participantIdentity is required" }, 400);
    }
    if (participantIdentity !== user.id) {
      return jsonResponse({ error: "participantIdentity must match authenticated user" }, 403);
    }

    const apiKey = Deno.env.get("LIVEKIT_API_KEY") ?? "";
    const apiSecret = Deno.env.get("LIVEKIT_API_SECRET") ?? "";
    if (!apiKey || !apiSecret) {
      console.error("livekit-token: LIVEKIT_API_KEY or LIVEKIT_API_SECRET is not configured");
      return jsonResponse({ error: "LiveKit is not configured" }, 503);
    }

    const livekitUrl = Deno.env.get("LIVEKIT_URL") ?? DEFAULT_LIVEKIT_URL;
    const accessToken = new AccessToken(apiKey, apiSecret, {
      identity: participantIdentity,
      name: participantName,
    });
    accessToken.addGrant({
      roomJoin: true,
      room: roomName,
      canPublish: true,
      canSubscribe: true,
    });

    const jwt = await accessToken.toJwt();
    return jsonResponse({ token: jwt, url: livekitUrl });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("livekit-token error:", message);
    return jsonResponse({ error: message }, 400);
  }
});
