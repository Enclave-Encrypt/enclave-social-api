import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.8";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-webhooks-secret",
};

function memberIsMentioned(
  memberId: string,
  mentionUserIds: string[],
  mentionRoleIds: number[],
  mentionEveryone: boolean,
  mentionHere: boolean,
  memberRoleIds: number[],
): boolean {
  if (mentionUserIds.includes(memberId)) return true;
  if (mentionEveryone || mentionHere) return true;
  if (mentionRoleIds.length > 0 && memberRoleIds.some((id) => mentionRoleIds.includes(id))) {
    return true;
  }
  return false;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const expectedWebhookSecret = Deno.env.get("MESSAGE_NOTIFICATION_WEBHOOK_SECRET") ?? "";
  if (!expectedWebhookSecret) {
    return new Response(JSON.stringify({ error: "MESSAGE_NOTIFICATION_WEBHOOK_SECRET is not configured" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  const providedWebhookSecret = req.headers.get("x-webhooks-secret") ?? "";
  if (providedWebhookSecret !== expectedWebhookSecret) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const payload = await req.json();

    const record = payload.record;
    if (!record) {
      return new Response(JSON.stringify({ error: "No record in payload" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const {
      channel_id,
      sender_id,
      mention_user_ids = [],
      mention_role_ids = [],
      mention_everyone = false,
      mention_here = false,
    } = record;

    const mentionUserIds: string[] = Array.isArray(mention_user_ids)
      ? mention_user_ids.map(String)
      : [];
    const mentionRoleIds: number[] = Array.isArray(mention_role_ids)
      ? mention_role_ids.map((id: unknown) => Number(id)).filter(Number.isFinite)
      : [];
    const mentionEveryone = Boolean(mention_everyone);
    const mentionHere = Boolean(mention_here);
    const hasMentionMetadata =
      mentionUserIds.length > 0 ||
      mentionRoleIds.length > 0 ||
      mentionEveryone ||
      mentionHere;

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    const { data: channel, error: channelError } = await supabase
      .from("channels")
      .select("server_id, name")
      .eq("id", channel_id)
      .single();

    if (channelError || !channel) {
      return new Response(JSON.stringify({ error: "Channel not found" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { data: members } = await supabase
      .from("server_members")
      .select("user_id")
      .eq("server_id", channel.server_id)
      .neq("user_id", sender_id);

    if (!members || members.length === 0) {
      return new Response(JSON.stringify({ sent: 0 }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const memberIds = members.map((m) => m.user_id);

    const memberRolesByUser = new Map<string, number[]>();
    if (mentionRoleIds.length > 0) {
      const { data: memberRoles } = await supabase
        .from("server_member_roles")
        .select("user_id, role_id")
        .eq("server_id", channel.server_id)
        .in("user_id", memberIds)
        .in("role_id", mentionRoleIds);

      for (const row of memberRoles ?? []) {
        const existing = memberRolesByUser.get(row.user_id) ?? [];
        existing.push(Number(row.role_id));
        memberRolesByUser.set(row.user_id, existing);
      }
    }

    const { data: settingsRows } = await supabase
      .from("user_settings")
      .select("user_id, notify_push_enabled, notify_server_messages, presence")
      .in("user_id", memberIds);

    const { data: serverSettings } = await supabase
      .from("server_notification_settings")
      .select(
        "user_id, notify_messages, notification_level, muted_until, suppress_everyone_here, suppress_role_mentions",
      )
      .eq("server_id", channel.server_id)
      .in("user_id", memberIds);

    const now = Date.now();
    const eligibleMemberIds = memberIds.filter((memberId) => {
      const settings = settingsRows?.find((row) => row.user_id === memberId);
      if (settings?.presence === "dnd") return false;
      if (settings?.notify_push_enabled === false) return false;
      if (settings?.notify_server_messages === false) return false;

      const serverSetting = serverSettings?.find((row) => row.user_id === memberId);
      const level =
        serverSetting?.notification_level ??
        (serverSetting?.notify_messages === false ? "nothing" : "all");

      if (level === "nothing") return false;

      const mentioned = hasMentionMetadata
        ? memberIsMentioned(
            memberId,
            mentionUserIds,
            mentionRoleIds,
            mentionEveryone && !serverSetting?.suppress_everyone_here,
            mentionHere && !serverSetting?.suppress_everyone_here,
            memberRolesByUser.get(memberId) ?? [],
          )
        : false;

      if (level === "mentions" && !mentioned) return false;

      if (serverSetting?.muted_until) {
        const mutedUntil = new Date(serverSetting.muted_until).getTime();
        if (!Number.isNaN(mutedUntil) && mutedUntil > now) {
          if (!mentioned) return false;
        }
      }

      if (
        serverSetting?.suppress_role_mentions &&
        mentionRoleIds.length > 0 &&
        !mentionUserIds.includes(memberId) &&
        !mentionEveryone &&
        !mentionHere
      ) {
        const roleIds = memberRolesByUser.get(memberId) ?? [];
        if (roleIds.some((id) => mentionRoleIds.includes(id))) return false;
      }

      return true;
    });

    if (eligibleMemberIds.length === 0) {
      return new Response(JSON.stringify({ sent: 0 }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { data: sender } = await supabase
      .from("users")
      .select("username, display_name")
      .eq("auth_id", sender_id)
      .single();

    const senderName =
      sender?.display_name || sender?.username || "Someone";

    const { data: tokenRows } = await supabase
      .from("users")
      .select("push_token")
      .in("auth_id", eligibleMemberIds)
      .not("push_token", "is", null);

    if (!tokenRows || tokenRows.length === 0) {
      return new Response(JSON.stringify({ sent: 0 }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const body =
      hasMentionMetadata && (mentionUserIds.length > 0 || mentionEveryone || mentionHere)
        ? `${senderName} mentioned you in #${channel.name}`
        : `New message from ${senderName}`;

    const messages = tokenRows.map(({ push_token }) => ({
      to: push_token,
      sound: "default",
      title: `#${channel.name}`,
      body,
      data: { channel_id, channel_name: channel.name, server_id: channel.server_id },
    }));

    const expoResponse = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "Accept-Encoding": "gzip, deflate",
      },
      body: JSON.stringify(messages),
    });

    const expoResult = await expoResponse.json();
    console.log("[push] expoResult", expoResult);

    return new Response(JSON.stringify({ sent: messages.length }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: err.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
