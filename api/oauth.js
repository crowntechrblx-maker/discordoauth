import { createClient } from "@supabase/supabase-js";
import crypto from "node:crypto";

const AUTHORIZE = "https://apis.roblox.com/oauth/v1/authorize";
const TOKEN = "https://apis.roblox.com/oauth/v1/token";
const USERINFO = "https://apis.roblox.com/oauth/v1/userinfo";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

function supabase() {
  return createClient(required("SUPABASE_URL"), required("SUPABASE_SECRET_KEY"), {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false }
  });
}

function b64url(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function random(bytes = 32) {
  return b64url(crypto.randomBytes(bytes));
}

function challenge(verifier) {
  return b64url(crypto.createHash("sha256").update(verifier).digest());
}

function signature(discordId) {
  return b64url(crypto.createHmac("sha256", required("DISCORD_OAUTH_SECRET")).update(discordId).digest());
}

function validSignature(a, b) {
  if (!a || !b) return false;
  try {
    const x = Buffer.from(String(a));
    const y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  } catch {
    return false;
  }
}

function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(body));
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export default async function handler(req, res) {
  try {
    const url = new URL(req.url, `https://${req.headers.host}`);
    const action = url.searchParams.get("action") || "start";
    const db = supabase();

    if (action === "start") {
      const discordId = url.searchParams.get("discord_user_id");
      const sig = url.searchParams.get("sig");

      if (!discordId || !validSignature(sig, signature(discordId))) {
        return sendJson(res, 401, { error: "Invalid authorization." });
      }

      const state = random();
      const verifier = random(64);
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

      const { error } = await db.from("oauth_states").insert({
        state,
        discord_id: String(discordId),
        code_verifier: verifier,
        expires_at: expiresAt
      });

      if (error) throw error;

      const params = new URLSearchParams({
        client_id: required("ROBLOX_CLIENT_ID"),
        redirect_uri: required("ROBLOX_REDIRECT_URI"),
        response_type: "code",
        scope: "openid profile",
        state,
        code_challenge: challenge(verifier),
        code_challenge_method: "S256"
      });

      res.statusCode = 302;
      res.setHeader("Location", `${AUTHORIZE}?${params.toString()}`);
      return res.end();
    }

    if (action === "callback") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const oauthError = url.searchParams.get("error");

      if (oauthError) return sendJson(res, 400, { error: "Roblox OAuth was cancelled or denied." });
      if (!code || !state) return sendJson(res, 400, { error: "Missing OAuth parameters." });

      const { data: saved, error: stateError } = await db
        .from("oauth_states")
        .select("discord_id, code_verifier, expires_at")
        .eq("state", state)
        .maybeSingle();

      if (stateError) throw stateError;
      if (!saved || new Date(saved.expires_at).getTime() < Date.now()) {
        await db.from("oauth_states").delete().eq("state", state);
        return sendJson(res, 400, { error: "OAuth session expired or invalid." });
      }

      await db.from("oauth_states").delete().eq("state", state);

      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: required("ROBLOX_CLIENT_ID"),
        client_secret: required("ROBLOX_CLIENT_SECRET"),
        redirect_uri: required("ROBLOX_REDIRECT_URI"),
        code_verifier: saved.code_verifier
      });

      const tokenRes = await fetch(TOKEN, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
      });

      if (!tokenRes.ok) {
        console.error("Roblox token exchange failed:", await tokenRes.text());
        return sendJson(res, 502, { error: "Roblox token exchange failed." });
      }

      const token = await tokenRes.json();
      const userRes = await fetch(USERINFO, { headers: { Authorization: `Bearer ${token.access_token}` } });

      if (!userRes.ok) {
        console.error("Roblox userinfo failed:", await userRes.text());
        return sendJson(res, 502, { error: "Could not retrieve Roblox account." });
      }

      const user = await userRes.json();
      const robloxId = String(user.sub);
      const username = user.preferred_username || user.nickname || "";
      const displayName = user.name || username;
      const discordId = String(saved.discord_id);

      const { data: existingRoblox, error: existingError } = await db
        .from("oauth_links")
        .select("discord_id")
        .eq("roblox_id", robloxId)
        .maybeSingle();

      if (existingError) throw existingError;
      if (existingRoblox && String(existingRoblox.discord_id) !== discordId) {
        return sendJson(res, 409, { error: "That Roblox account is already linked." });
      }

      const { data: oldLink, error: oldError } = await db
        .from("oauth_links")
        .select("roblox_id")
        .eq("discord_id", discordId)
        .maybeSingle();

      if (oldError) throw oldError;

      if (oldLink && String(oldLink.roblox_id) !== robloxId) {
        await db.from("oauth_links").delete().eq("discord_id", discordId);
      }

      const { error: upsertError } = await db.from("oauth_links").upsert({
        discord_id: discordId,
        roblox_id: robloxId,
        roblox_username: username,
        display_name: displayName,
        linked_at: new Date().toISOString()
      }, { onConflict: "discord_id" });

      if (upsertError) throw upsertError;

      res.statusCode = 200;
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.end(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Roblox Linked</title><style>body{font-family:system-ui;background:#111;color:#fff;display:grid;place-items:center;min-height:100vh;margin:0}main{text-align:center;max-width:560px;padding:30px}p{color:#aaa}</style></head><body><main><h1>Roblox account linked</h1><p>You can return to Discord.</p><p><strong>${escapeHtml(displayName)}</strong> (@${escapeHtml(username)})</p></main></body></html>`);
    }

    if (action === "lookup" || action === "unlink") {
      const discordId = url.searchParams.get("discord_user_id");
      const sig = req.headers["x-discord-oauth-signature"];

      if (!discordId || !validSignature(sig, signature(discordId))) {
        return sendJson(res, 401, { error: "Unauthorized." });
      }

      if (action === "lookup") {
        const { data: record, error } = await db.from("oauth_links")
          .select("discord_id, roblox_id, roblox_username, display_name, linked_at")
          .eq("discord_id", String(discordId))
          .maybeSingle();
        if (error) throw error;
        return sendJson(res, 200, { linked: Boolean(record), account: record || null });
      }

      const { error } = await db.from("oauth_links").delete().eq("discord_id", String(discordId));
      if (error) throw error;
      return sendJson(res, 200, { success: true });
    }

    return sendJson(res, 404, { error: "Unknown action." });
  } catch (error) {
    console.error(error);
    return sendJson(res, 500, { error: "Internal server error." });
  }
}
