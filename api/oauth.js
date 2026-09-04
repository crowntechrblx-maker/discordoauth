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
  return b64url(crypto.createHmac("sha256", required("DISCORD_OAUTH_SECRET")).update(String(discordId)).digest());
}

function legacyHexSignature(discordId) {
  return crypto.createHmac("sha256", required("DISCORD_OAUTH_SECRET")).update(String(discordId)).digest("hex");
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

function validDiscordSignature(discordId, supplied) {
  return validSignature(supplied, signature(discordId)) || validSignature(supplied, legacyHexSignature(discordId));
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

function sendEntryPage(res) {
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>[PS] SIS Activity System</title><style>body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#111;color:#fff;display:grid;place-items:center;min-height:100vh;margin:0;padding:24px;box-sizing:border-box}main{max-width:650px;width:100%;background:#191919;border:1px solid #303030;border-radius:16px;padding:36px;box-sizing:border-box;box-shadow:0 20px 60px rgba(0,0,0,.35)}h1{margin:0 0 10px;font-size:30px}h2{margin:28px 0 10px;font-size:18px}p,li{color:#bdbdbd;line-height:1.6}ul{padding-left:22px}.badge{display:inline-block;color:#fff;background:#2b2b2b;border:1px solid #3b3b3b;border-radius:999px;padding:6px 10px;font-size:13px;margin-bottom:18px}.notice{background:#202020;border-left:3px solid #777;padding:14px 16px;border-radius:8px;margin-top:24px}</style></head><body><main><div class="badge">Blume Corporation</div><h1>[PS] SIS Activity System</h1><p>Secure Roblox account linking for the SIS Activity System.</p><h2>What does this application do?</h2><p>This service allows members to securely associate their Roblox account with their Discord account for SIS Activity System features.</p><h2>Information accessed</h2><ul><li>Roblox User ID</li><li>Roblox username</li><li>Roblox display name</li></ul><p>We do not request or store your Roblox password.</p><div class="notice"><strong>How to link your account</strong><p>Start the linking process using the <strong>/link</strong> command in the SIS Activity System Discord server.</p></div></main></body></html>`);
}

function accountResponse(record) {
  return {
    linked: Boolean(record),
    account: record || null,
    roblox_id: record?.roblox_id || null,
    roblox_username: record?.roblox_username || null,
    display_name: record?.display_name || null,
    linked_at: record?.linked_at || null
  };
}

export default async function handler(req, res) {
  try {
    const url = new URL(req.url, `https://${req.headers.host}`);
    const action = url.searchParams.get("action") || "start";
    const db = supabase();

    if (action === "start") {
      const discordId = url.searchParams.get("discord_user_id");
      const sig = url.searchParams.get("sig");

      // The public Roblox OAuth Entry Link must be reviewable on its own.
      // Only a Discord-generated signed URL is allowed to start an OAuth flow.
      if (!discordId && !sig) {
        return sendEntryPage(res);
      }

      if (!discordId || !validDiscordSignature(discordId, sig)) {
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

    if (action === "lookup" || action === "lookup-roblox" || action === "unlink") {
      const discordId = url.searchParams.get("discord_user_id");
      const sig = req.headers["x-discord-oauth-signature"];

      if (!discordId || !validDiscordSignature(discordId, sig)) {
        return sendJson(res, 401, { error: "Unauthorized." });
      }

      if (action === "lookup") {
        const { data: record, error } = await db.from("oauth_links")
          .select("discord_id, roblox_id, roblox_username, display_name, linked_at")
          .eq("discord_id", String(discordId))
          .maybeSingle();
        if (error) throw error;
        return sendJson(res, 200, accountResponse(record));
      }

      if (action === "lookup-roblox") {
        const username = url.searchParams.get("roblox_username");
        if (!username) return sendJson(res, 400, { error: "Missing roblox_username." });

        const { data: record, error } = await db.from("oauth_links")
          .select("discord_id, roblox_id, roblox_username, display_name, linked_at")
          .ilike("roblox_username", username)
          .maybeSingle();
        if (error) throw error;
        return sendJson(res, 200, accountResponse(record));
      }

      const { error } = await db.from("oauth_links").delete().eq("discord_id", String(discordId));
      if (error) throw error;
      return sendJson(res, 200, { success: true, deleted: true });
    }

    return sendJson(res, 404, { error: "Unknown action." });
  } catch (error) {
    console.error(error);
    return sendJson(res, 500, { error: "Internal server error." });
  }
}
