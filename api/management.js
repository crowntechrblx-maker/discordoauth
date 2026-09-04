import { createClient } from "@supabase/supabase-js";
import crypto from "node:crypto";

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

function cookieSecret() {
  return process.env.MANAGEMENT_DASHBOARD_SECRET || required("DISCORD_OAUTH_SECRET");
}

function sign(value) {
  return crypto.createHmac("sha256", cookieSecret()).update(value).digest("base64url");
}

function makeSession() {
  const value = `${Date.now()}.${crypto.randomBytes(24).toString("base64url")}`;
  return `${value}.${sign(value)}`;
}

function validSession(req) {
  const cookie = req.headers.cookie || "";
  const match = cookie.match(/(?:^|;\s*)sis_management=([^;]+)/);
  if (!match) return false;

  const parts = decodeURIComponent(match[1]).split(".");
  if (parts.length !== 3) return false;

  const [timestamp, random, supplied] = parts;
  const value = `${timestamp}.${random}`;
  const expected = sign(value);

  if (supplied.length !== expected.length) return false;

  try {
    if (!crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) return false;
  } catch {
    return false;
  }

  return Number(timestamp) > Date.now() - 8 * 60 * 60 * 1000;
}

function htmlEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function sendHtml(res, status, body, headers = {}) {
  res.statusCode = status;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  for (const [key, value] of Object.entries(headers)) res.setHeader(key, value);
  res.end(body);
}

function loginPage(error = "") {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIS Management</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#0d1110;color:#eef3ef;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:grid;place-items:center;padding:24px}.card{width:min(430px,100%);background:#151b18;border:1px solid #29332e;border-radius:18px;padding:34px;box-shadow:0 24px 70px #0008}.eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:#7f9087;font-weight:700}h1{margin:8px 0 8px;font-size:30px}p{color:#9daaa3;line-height:1.55}label{display:block;margin:22px 0 8px;font-size:13px;font-weight:700;color:#cdd6d1}input{width:100%;padding:13px 14px;background:#0d1210;border:1px solid #344039;border-radius:10px;color:#fff;font-size:15px;outline:none}input:focus{border-color:#6f887a}button{width:100%;margin-top:18px;padding:13px;border:0;border-radius:10px;background:#2f7d68;color:#fff;font-weight:700;font-size:15px;cursor:pointer}.error{margin-top:14px;padding:11px 12px;border-radius:9px;background:#3a211f;color:#f2b8b0;font-size:13px}</style></head>
<body><main class="card"><div class="eyebrow">Secret Intelligence Service</div><h1>Management Portal</h1><p>Restricted access to SIS personnel activity and monthly quota information.</p><form method="post"><label for="password">Management password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button>${error ? `<div class="error">${htmlEscape(error)}</div>` : ""}</form></main></body></html>`;
}

function dashboardPage(data) {
  const rows = data.personnel;
  const counts = data.summary;
  const quota = data.quota.formatted;
  const monthLabel = new Date(`${data.month}-01T00:00:00`).toLocaleDateString("en-GB", { month: "long", year: "numeric" });

  const tableRows = rows.map(person => {
    const statusClass = person.status === "met" ? "met" : person.status === "in_progress" ? "progress" : "none";
    const statusText = person.status === "met" ? "Quota met" : person.status === "in_progress" ? "In progress" : "No activity";
    return `<tr><td><strong>${htmlEscape(person.display_name || person.discord_username || person.roblox_username || "Unknown")}</strong><small>${htmlEscape(person.roblox_username || "No Roblox account linked")}</small></td><td>${htmlEscape(person.activity)}</td><td>${person.shifts}</td><td><div class="bar"><span style="width:${Math.min(100, Number(person.percentage) || 0)}%"></span></div><small>${person.percentage}%</small></td><td><span class="status ${statusClass}">${statusText}</span></td></tr>`;
  }).join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SIS Management — ${htmlEscape(monthLabel)}</title><style>
*{box-sizing:border-box}body{margin:0;background:#0d1110;color:#edf3ef;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{max-width:1200px;margin:auto;padding:34px 22px 60px}.top{display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:28px}.eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:#7f9087;font-weight:800}.top h1{margin:5px 0 4px;font-size:30px}.muted{color:#8f9b95}.logout{border:1px solid #344039;color:#bfcac4;text-decoration:none;padding:9px 13px;border-radius:9px;font-size:13px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}.card{background:#151b18;border:1px solid #29332e;border-radius:15px;padding:19px}.label{color:#8f9b95;font-size:12px;text-transform:uppercase;letter-spacing:.08em;font-weight:700}.number{font-size:28px;font-weight:800;margin-top:7px}.tablebox{background:#151b18;border:1px solid #29332e;border-radius:15px;overflow:hidden}.tablehead{padding:19px 20px;border-bottom:1px solid #29332e;display:flex;justify-content:space-between;align-items:center}.tablehead h2{margin:0;font-size:18px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:15px 18px;border-bottom:1px solid #222b26;font-size:14px}th{color:#84918a;font-size:11px;text-transform:uppercase;letter-spacing:.08em}td small{display:block;color:#75817b;margin-top:4px}.bar{height:7px;background:#252e2a;border-radius:99px;width:130px;overflow:hidden;margin-bottom:5px}.bar span{display:block;height:100%;background:#5f9d89;border-radius:99px}.status{display:inline-block;padding:5px 8px;border-radius:999px;font-size:11px;font-weight:800}.status.met{background:#173c31;color:#7bd2b5}.status.progress{background:#40371c;color:#e2c46b}.status.none{background:#252b28;color:#9ca7a1}.empty{padding:30px;color:#8f9b95;text-align:center}@media(max-width:850px){.cards{grid-template-columns:repeat(2,1fr)}.tablebox{overflow:auto}table{min-width:760px}}@media(max-width:500px){.cards{grid-template-columns:1fr 1fr}.wrap{padding:24px 14px}}
</style></head><body><main class="wrap"><header class="top"><div><div class="eyebrow">Secret Intelligence Service</div><h1>Personnel Activity</h1><div class="muted">${htmlEscape(monthLabel)} · Monthly quota: ${htmlEscape(quota)}</div></div><a class="logout" href="/management?logout=1">Sign out</a></header><section class="cards"><div class="card"><div class="label">Total Personnel</div><div class="number">${counts.total}</div></div><div class="card"><div class="label">Quota Met</div><div class="number">${counts.quota_met}</div></div><div class="card"><div class="label">In Progress</div><div class="number">${counts.in_progress}</div></div><div class="card"><div class="label">No Activity</div><div class="number">${counts.no_activity}</div></div></section><section class="tablebox"><div class="tablehead"><h2>Personnel</h2><div class="muted">${counts.quota_met} of ${counts.total} complete</div></div>${rows.length ? `<table><thead><tr><th>Personnel</th><th>Activity</th><th>Shifts</th><th>Progress</th><th>Status</th></tr></thead><tbody>${tableRows}</tbody></table>` : `<div class="empty">No personnel found.</div>`}</section></main></body></html>`;
}

async function fetchBot(pathname) {
  const base = required("MANAGEMENT_API_URL").replace(/\/$/, "");
  const response = await fetch(`${base}${pathname}`, {
    headers: { Authorization: `Bearer ${required("MANAGEMENT_API_SECRET")}` },
    cache: "no-store"
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Bot API returned ${response.status}`);
  return data;
}

async function buildData(month) {
  const [quotaData, memberData] = await Promise.all([
    fetchBot(`/api/management/quota?month=${encodeURIComponent(month)}`),
    fetchBot("/api/management/members")
  ]);

  const db = supabase();
  const { data: links, error } = await db.from("oauth_links")
    .select("discord_id, roblox_id, roblox_username, display_name, linked_at");
  if (error) throw error;

  const linkByDiscord = new Map((links || []).map(link => [String(link.discord_id), link]));
  const activityByRoblox = new Map((quotaData.personnel || []).map(row => [String(row.roblox_username).toLowerCase(), row]));

  const personnel = (memberData.members || []).map(member => {
    const link = linkByDiscord.get(String(member.discord_id));
    const activity = link ? activityByRoblox.get(String(link.roblox_username || "").toLowerCase()) : null;
    return {
      ...member,
      roblox_id: link?.roblox_id || null,
      roblox_username: link?.roblox_username || null,
      display_name: link?.display_name || member.display_name || member.discord_username,
      shifts: activity?.shifts || 0,
      seconds: activity?.seconds || 0,
      activity: activity?.activity || "0s",
      percentage: activity?.percentage || 0,
      status: activity?.status || "no_activity",
      last_shift: activity?.last_shift || null
    };
  });

  personnel.sort((a, b) => (b.seconds || 0) - (a.seconds || 0) || String(a.display_name).localeCompare(String(b.display_name)));

  const summary = {
    total: personnel.length,
    quota_met: personnel.filter(p => p.status === "met").length,
    in_progress: personnel.filter(p => p.status === "in_progress").length,
    no_activity: personnel.filter(p => p.status === "no_activity").length
  };

  return { ...quotaData, personnel, summary };
}

export default async function handler(req, res) {
  try {
    const url = new URL(req.url, `https://${req.headers.host}`);

    if (req.method === "GET" && url.searchParams.get("logout") === "1") {
      return sendHtml(res, 200, loginPage(), {
        "Set-Cookie": "sis_management=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax"
      });
    }

    if (req.method === "GET" && !validSession(req)) {
      return sendHtml(res, 200, loginPage());
    }

    if (req.method === "POST") {
      let body = "";
      for await (const chunk of req) body += chunk;
      const params = new URLSearchParams(body);
      const password = params.get("password") || "";
      if (!password || password !== required("MANAGEMENT_PASSWORD")) {
        return sendHtml(res, 401, loginPage("Incorrect management password."));
      }
      const session = makeSession();
      return sendHtml(res, 302, "", {
        Location: "/management",
        "Set-Cookie": `sis_management=${encodeURIComponent(session)}; Max-Age=28800; Path=/; HttpOnly; Secure; SameSite=Lax`
      });
    }

    if (req.method !== "GET") {
      return sendHtml(res, 405, "Method not allowed");
    }

    const now = new Date();
    const month = url.searchParams.get("month") || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
    const data = await buildData(month);
    return sendHtml(res, 200, dashboardPage(data), {
      "Cache-Control": "no-store"
    });
  } catch (error) {
    console.error("Management dashboard error:", error);
    return sendHtml(res, 500, `<html><body style="font-family:system-ui;background:#0d1110;color:#fff;padding:40px"><h1>Management dashboard unavailable</h1><p style="color:#aaa">${htmlEscape(error.message)}</p></body></html>`);
  }
}
