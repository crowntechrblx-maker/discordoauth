import { Redis } from "@upstash/redis";
import crypto from "node:crypto";

const redis = Redis.fromEnv();

const AUTHORIZE = "https://apis.roblox.com/oauth/v1/authorize";
const TOKEN = "https://apis.roblox.com/oauth/v1/token";
const USERINFO = "https://apis.roblox.com/oauth/v1/userinfo";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

function b64url(buffer) {
  return buffer.toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function random(bytes = 32) {
  return b64url(crypto.randomBytes(bytes));
}

function challenge(verifier) {
  return b64url(crypto.createHash("sha256").update(verifier).digest());
}

function signature(discordId) {
  return b64url(
    crypto.createHmac("sha256", required("DISCORD_OAUTH_SECRET"))
      .update(discordId)
      .digest()
  );
}

function validSignature(a, b) {
  if (!a || !b) return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(body));
}

export default async function handler(req, res) {
  try {
    const url = new URL(req.url, `https://${req.headers.host}`);
    const action = url.searchParams.get("action") || "start";

    if (action === "start") {
      const discordId = url.searchParams.get("discord_user_id");
      const sig = url.searchParams.get("sig");

      if (!discordId || !validSignature(sig, signature(discordId))) {
        return sendJson(res, 401, { error: "Invalid authorization." });
      }

      const state = random();
      const verifier = random(64);

      await redis.set(
        `oauth-state:${state}`,
        JSON.stringify({ discordId, verifier }),
        { ex: 600 }
      );

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
      res.setHeader("Location", `${AUTHORIZE}?${params}`);
      return res.end();
    }

    if (action === "callback") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");

      if (!code || !state) {
        return sendJson(res, 400, { error: "Missing OAuth parameters." });
      }

      const savedRaw = await redis.get(`oauth-state:${state}`);
      if (!savedRaw) {
        return sendJson(res, 400, { error: "OAuth session expired or invalid." });
      }

      await redis.del(`oauth-state:${state}`);

      const saved = typeof savedRaw === "string" ? JSON.parse(savedRaw) : savedRaw;

      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: required("ROBLOX_CLIENT_ID"),
        client_secret: required("ROBLOX_CLIENT_SECRET"),
        redirect_uri: required("ROBLOX_REDIRECT_URI"),
        code_verifier: saved.verifier
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

      const userRes = await fetch(USERINFO, {
        headers: { Authorization: `Bearer ${token.access_token}` }
      });

      if (!userRes.ok) {
        console.error("Roblox userinfo failed:", await userRes.text());
        return sendJson(res, 502, { error: "Could not retrieve Roblox account." });
      }

      const user = await userRes.json();
      const robloxId = String(user.sub);
      const username = user.preferred_username || user.nickname || "";
      const displayName = user.name || username;

      const alreadyLinked = await redis.get(`roblox-link:${robloxId}`);
      if (alreadyLinked && String(alreadyLinked) !== String(saved.discordId)) {
        return sendJson(res, 409, {
          error: "That Roblox account is already linked."
        });
      }

      const oldRaw = await redis.get(`discord-link:${saved.discordId}`);
      if (oldRaw) {
        const old = typeof oldRaw === "string" ? JSON.parse(oldRaw) : oldRaw;
        if (old.robloxId && old.robloxId !== robloxId) {
          await redis.del(`roblox-link:${old.robloxId}`);
        }
      }

      const record = {
        discordId: String(saved.discordId),
        robloxId,
        username,
        displayName,
        linkedAt: new Date().toISOString()
      };

      await redis.set(`discord-link:${saved.discordId}`, JSON.stringify(record));
      await redis.set(`roblox-link:${robloxId}`, String(saved.discordId));

      res.statusCode = 200;
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.end(`<!doctype html>
<html><head><meta charset="utf-8"><title>Roblox Linked</title>
<style>body{font-family:system-ui;background:#111;color:#fff;display:grid;place-items:center;min-height:100vh;margin:0}main{text-align:center;max-width:560px;padding:30px}p{color:#aaa}</style>
</head><body><main><h1>Roblox account linked</h1><p>You can return to Discord.</p><p><strong>${escapeHtml(displayName)}</strong> (@${escapeHtml(username)})</p></main></body></html>`);
    }

    if (action === "lookup" || action === "unlink") {
      const discordId = url.searchParams.get("discord_user_id");
      const sig = req.headers["x-discord-oauth-signature"];

      if (!discordId || !validSignature(sig, signature(discordId))) {
        return sendJson(res, 401, { error: "Unauthorized." });
      }

      if (action === "lookup") {
        const record = await redis.get(`discord-link:${discordId}`);
        return sendJson(res, 200, {
          linked: Boolean(record),
          account: record || null
        });
      }

      const record = await redis.get(`discord-link:${discordId}`);
      if (record) {
        const data = typeof record === "string" ? JSON.parse(record) : record;
        if (data.robloxId) await redis.del(`roblox-link:${data.robloxId}`);
      }

      await redis.del(`discord-link:${discordId}`);
      return sendJson(res, 200, { success: true });
    }

    return sendJson(res, 404, { error: "Unknown action." });
  } catch (error) {
    console.error(error);
    return sendJson(res, 500, { error: "Internal server error." });
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
