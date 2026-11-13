const enc = new TextEncoder();
const dec = new TextDecoder();

const OPERATOR_USERNAME = "hackerx";
const OPERATOR_ACCOUNT = "hackerx@xmail.org";

function response(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function id() {
  return crypto.randomUUID();
}

function now() {
  return new Date().toISOString();
}

function b64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function unb64(s) {
  const binary = atob(s);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function b64url(bytes) {
  return b64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - s.length % 4) % 4);
  return unb64(s);
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return new Uint8Array(
    await crypto.subtle.sign("HMAC", key, enc.encode(value))
  );
}

async function hashIp(ip, env) {
  return b64url(await hmac(ip || "unknown", env.SESSION_SECRET));
}

async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: fromB64url(salt),
    iterations: 310000,
    hash: "SHA-256"
  }, key, 256);

  return b64url(new Uint8Array(bits));
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;

  let diff = a.length ^ b.length;
  const len = Math.max(a.length, b.length);

  for (let i = 0; i < len; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }

  return diff === 0;
}

async function makeSession(payload, env) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const signature = b64url(await hmac(body, env.SESSION_SECRET));
  return body + "." + signature;
}

async function readSession(request, env) {
  const cookies = request.headers.get("Cookie") || "";
  const match = cookies.match(/(?:^|;\s*)xmail_session=([^;]+)/);

  if (!match) return null;

  const parts = match[1].split(".");
  if (parts.length !== 2) return null;

  const expected = b64url(await hmac(parts[0], env.SESSION_SECRET));

  if (!safeEqual(parts[1], expected)) return null;

  try {
    const payload = JSON.parse(dec.decode(fromB64url(parts[0])));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

function setCookie(token) {
  return "xmail_session=" + token +
    "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800";
}

function clearCookie() {
  return "xmail_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0";
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

async function log(env, actor, action, target = "", details = "") {
  await env.DB.prepare(`
    INSERT INTO audit_logs
    (id, actor, action, target, details, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(id(), actor, action, target, details, now()).run();
}

async function setting(env, key) {
  const row = await env.DB.prepare(
    "SELECT value FROM settings WHERE key = ?"
  ).bind(key).first();

  return row ? row.value : null;
}

async function ensureOperator(env) {
  const existing = await env.DB.prepare(
    "SELECT id FROM users WHERE username = ?"
  ).bind(OPERATOR_USERNAME).first();

  if (existing) return;

  if (!env.OPERATOR_INITIAL_PASSWORD) {
    throw new Error("OPERATOR_INITIAL_PASSWORD is missing.");
  }

  const salt = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await passwordHash(env.OPERATOR_INITIAL_PASSWORD, salt);

  await env.DB.prepare(`
    INSERT OR IGNORE INTO users
    (id, username, account_id, password_salt, password_hash,
     password_change_required, role, created_at)
    VALUES (?, ?, ?, ?, ?, 1, 'operator', ?)
  `).bind(
    id(),
    OPERATOR_USERNAME,
    OPERATOR_ACCOUNT,
    salt,
    hash,
    now()
  ).run();
}

async function isBanned(env, userId, ipHash) {
  const time = now();

  const userBan = await env.DB.prepare(`
    SELECT id FROM bans
    WHERE user_id = ?
    AND (expires_at IS NULL OR expires_at > ?)
    LIMIT 1
  `).bind(userId, time).first();

  const ipBan = await env.DB.prepare(`
    SELECT id FROM bans
    WHERE ip_hash = ?
    AND (expires_at IS NULL OR expires_at > ?)
    LIMIT 1
  `).bind(ipHash, time).first();

  return !!(userBan || ipBan);
}

async function getAuth(request, env) {
  const session = await readSession(request, env);
  if (!session) return null;

  const user = await env.DB.prepare(`
    SELECT id, username, account_id, role,
           session_version, password_change_required
    FROM users WHERE id = ?
  `).bind(session.id).first();

  if (!user) return null;

  if (user.session_version !== session.sv) return null;
  if (user.role !== session.role) return null;

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const ipHash = await hashIp(ip, env);

  if (await isBanned(env, user.id, ipHash)) return null;

  return user;
}

async function requireOperator(request, env) {
  const user = await getAuth(request, env);

  if (!user || user.role !== "operator" ||
      user.password_change_required) {
    return null;
  }

  return user;
}

async function issueLogin(user, env) {
  const token = await makeSession({
    id: user.id,
    username: user.username,
    role: user.role,
    sv: user.session_version,
    exp: Date.now() + 604800000
  }, env);

  return {
    token,
    headers: { "Set-Cookie": setCookie(token) }
  };
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method !== "GET") {
    const origin = request.headers.get("Origin");

    if (!origin || origin !== url.origin) {
      return response({ error: "Invalid request origin." }, 403);
    }
  }

  await ensureOperator(env);

  if (path === "/api/config" && method === "GET") {
    return response({
      registrationOpen:
        (await setting(env, "whitelist_mode")) !== "true"
    });
  }

  if (path === "/api/register" && method === "POST") {
    const data = await readBody(request);
    const username = String(data.username || "").trim().toLowerCase();
    const password = String(data.password || "");

    if (!/^[a-z0-9_]{3,20}$/.test(username)) {
      return response({
        error: "Username must be 3–20 letters, numbers or underscores."
      }, 400);
    }

    if (username === OPERATOR_USERNAME) {
      return response({ error: "That username is reserved." }, 400);
    }

    if (password.length < 10 || password.length > 128) {
      return response({
        error: "Password must be 10–128 characters."
      }, 400);
    }

    if ((await setting(env, "whitelist_mode")) === "true") {
      const allowed = await env.DB.prepare(
        "SELECT username FROM whitelist WHERE username = ?"
      ).bind(username).first();

      if (!allowed) {
        return response({ error: "Registration is restricted." }, 403);
      }
    }

    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE username = ?"
    ).bind(username).first();

    if (existing) {
      return response({ error: "Username already exists." }, 409);
    }

    const salt = b64url(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await passwordHash(password, salt);
    const userId = id();
    const accountId = username + "@xmail.org";

    try {
      await env.DB.prepare(`
        INSERT INTO users
        (id, username, account_id, password_salt, password_hash,
         password_change_required, role, created_at)
        VALUES (?, ?, ?, ?, ?, 0, 'user', ?)
      `).bind(
        userId, username, accountId, salt, hash, now()
      ).run();
    } catch {
      return response({ error: "Could not create account." }, 409);
    }

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const ipHash = await hashIp(ip, env.SESSION_SECRET);

    await env.DB.prepare(
      "UPDATE users SET last_ip_hash = ? WHERE id = ?"
    ).bind(ipHash, userId).run();

    const user = {
      id: userId,
      username,
      account_id: accountId,
      role: "user",
      session_version: 1,
      password_change_required: 0
    };

    const login = await issueLogin(user, env);
    await log(env, username, "register", accountId);

    return response({
      success: true,
      username,
      accountId,
      role: "user",
      passwordChangeRequired: false
    }, 200, login.headers);
  }

  if (path === "/api/login" && method === "POST") {
    const data = await readBody(request);
    const username = String(data.username || "").trim().toLowerCase();
    const password = String(data.password || "");

    const user = await env.DB.prepare(`
      SELECT * FROM users
      WHERE username = ? OR account_id = ?
      LIMIT 1
    `).bind(username, username).first();

    if (!user || !safeEqual(
      await passwordHash(password, user.password_salt),
      user.password_hash
    )) {
      return response({ error: "Incorrect username or password." }, 401);
    }

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const ipHash = await hashIp(ip, env);

    if (await isBanned(env, user.id, ipHash)) {
      return response({ error: "This account or network is banned." }, 403);
    }

    if (user.role !== "operator" &&
        (await setting(env, "whitelist_mode")) === "true") {
      const allowed = await env.DB.prepare(
        "SELECT username FROM whitelist WHERE username = ?"
      ).bind(user.username).first();

      if (!allowed) {
        return response({ error: "Access is restricted." }, 403);
      }
    }

    await env.DB.prepare(
      "UPDATE users SET last_ip_hash = ? WHERE id = ?"
    ).bind(ipHash, user.id).run();

    const login = await issueLogin(user, env);
    await log(env, user.username, "login", user.account_id);

    return response({
      success: true,
      username: user.username,
      accountId: user.account_id,
      role: user.role,
      passwordChangeRequired: !!user.password_change_required
    }, 200, login.headers);
  }

  if (path === "/api/logout" && method === "POST") {
    return response({ success: true }, 200, {
      "Set-Cookie": clearCookie()
    });
  }

  if (path === "/api/me" && method === "GET") {
    const user = await getAuth(request, env);

    if (!user) return response({ user: null });

    return response({
      user: {
        username: user.username,
        accountId: user.account_id,
        role: user.role,
        passwordChangeRequired: !!user.password_change_required
      }
    });
  }

  if (path === "/api/change-password" && method === "POST") {
    const user = await getAuth(request, env);

    if (!user) {
      return response({ error: "Please log in again." }, 401);
    }

    const data = await readBody(request);
    const oldPassword = String(data.oldPassword || "");
    const newPassword = String(data.newPassword || "");

    if (newPassword.length < 10 || newPassword.length > 128) {
      return response({
        error: "New password must be 10–128 characters."
      }, 400);
    }

    const record = await env.DB.prepare(
      "SELECT * FROM users WHERE id = ?"
    ).bind(user.id).first();

    if (!safeEqual(
      await passwordHash(oldPassword, record.password_salt),
      record.password_hash
    )) {
      return response({ error: "Current password is incorrect." }, 401);
    }

    const salt = b64url(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await passwordHash(newPassword, salt);
    const newVersion = record.session_version + 1;

    await env.DB.prepare(`
      UPDATE users
      SET password_salt = ?,
          password_hash = ?,
          password_change_required = 0,
          session_version = ?
      WHERE id = ?
    `).bind(salt, hash, newVersion, user.id).run();

    const updated = {
      id: user.id,
      username: user.username,
      role: user.role,
      session_version: newVersion
    };

    const login = await issueLogin(updated, env);
    await log(env, user.username, "password_changed", user.account_id);

    return response({ success: true }, 200, login.headers);
  }

  if (path.startsWith("/api/admin/")) {
    const operator = await requireOperator(request, env);

    if (!operator) {
      return response({
        error: "Operator access required. Change your starter password first."
      }, 403);
    }

    if (path === "/api/admin/users" && method === "GET") {
      const result = await env.DB.prepare(`
        SELECT id, username, account_id, role, created_at
        FROM users ORDER BY created_at DESC LIMIT 500
      `).all();

      return response({ users: result.results || [] });
    }

    if (path === "/api/admin/logs" && method === "GET") {
      const result = await env.DB.prepare(`
        SELECT * FROM audit_logs
        ORDER BY created_at DESC LIMIT 200
      `).all();

      return response({ logs: result.results || [] });
    }

    if (path === "/api/admin/settings" && method === "GET") {
      return response({
        whitelistMode:
          (await setting(env, "whitelist_mode")) === "true"
      });
    }

    if (path === "/api/admin/settings" && method === "POST") {
      const data = await readBody(request);

      await env.DB.prepare(`
        INSERT INTO settings (key, value)
        VALUES ('whitelist_mode', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
      `).bind(data.whitelistMode ? "true" : "false").run();

      await log(env, operator.username, "whitelist_mode", "",
        data.whitelistMode ? "enabled" : "disabled");

      return response({ success: true });
    }

    if (path === "/api/admin/whitelist" && method === "GET") {
      const result = await env.DB.prepare(
        "SELECT * FROM whitelist ORDER BY created_at DESC"
      ).all();

      return response({ entries: result.results || [] });
    }

    if (path === "/api/admin/whitelist" && method === "POST") {
      const data = await readBody(request);
      const username = String(data.username || "").trim().toLowerCase();

      if (!/^[a-z0-9_]{3,20}$/.test(username)) {
        return response({ error: "Invalid username." }, 400);
      }

      if (username === OPERATOR_USERNAME) {
        return response({ error: "Operator cannot be changed here." }, 400);
      }

      if (data.remove) {
        await env.DB.prepare(
          "DELETE FROM whitelist WHERE username = ?"
        ).bind(username).run();
      } else {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO whitelist (username, created_at)
          VALUES (?, ?)
        `).bind(username, now()).run();
      }

      await log(env, operator.username,
        data.remove ? "whitelist_remove" : "whitelist_add",
        username);

      return response({ success: true });
    }

    if (path === "/api/admin/action" && method === "POST") {
      const data = await readBody(request);
      const target = String(data.userId || "");
      const action = String(data.action || "");
      const reason = String(data.reason || "No reason provided").slice(0, 200);

      const user = await env.DB.prepare(
        "SELECT * FROM users WHERE id = ?"
      ).bind(target).first();

      if (!user) return response({ error: "User not found." }, 404);

      if (user.role === "operator") {
        return response({ error: "Cannot moderate the operator account." }, 403);
      }

      const allowed = [
        "kick", "ban", "temp_ban", "unban",
        "ip_ban", "temp_ip_ban", "unban_ip"
      ];

      if (!allowed.includes(action)) {
        return response({ error: "Unknown action." }, 400);
      }

      const minutes = Math.min(
        Math.max(Number(data.minutes) || 60, 1),
        525600
      );

      if (action === "kick") {
        await env.DB.prepare(`
          UPDATE users SET session_version = session_version + 1
          WHERE id = ?
        `).bind(target).run();
      }

      if (action === "ban" || action === "temp_ban") {
        const expiry = action === "temp_ban"
          ? new Date(Date.now() + minutes * 60000).toISOString()
          : null;

        await env.DB.prepare(`
          INSERT INTO bans
          (id, user_id, reason, expires_at, created_at)
          VALUES (?, ?, ?, ?, ?)
        `).bind(id(), target, reason, expiry, now()).run();

        await env.DB.prepare(`
          UPDATE users SET session_version = session_version + 1
          WHERE id = ?
        `).bind(target).run();
      }

      if (action === "unban") {
        await env.DB.prepare(
          "DELETE FROM bans WHERE user_id = ?"
        ).bind(target).run();
      }

      if (action === "ip_ban" || action === "temp_ip_ban") {
        if (!user.last_ip_hash) {
          return response({ error: "No recorded IP for this user." }, 400);
        }

        const expiry = action === "temp_ip_ban"
          ? new Date(Date.now() + minutes * 60000).toISOString()
          : null;

        await env.DB.prepare(`
          INSERT INTO bans
          (id, ip_hash, reason, expires_at, created_at)
          VALUES (?, ?, ?, ?, ?)
        `).bind(id(), user.last_ip_hash, reason, expiry, now()).run();
      }

      if (action === "unban_ip" && user.last_ip_hash) {
        await env.DB.prepare(
          "DELETE FROM bans WHERE ip_hash = ?"
        ).bind(user.last_ip_hash).run();
      }

      await log(env, operator.username, action, user.username, reason);
      return response({ success: true });
    }

    if (path === "/api/admin/backup" && method === "GET") {
      const tables = [
        "users", "bans", "whitelist", "settings", "audit_logs"
      ];

      const backup = {};

      for (const table of tables) {
        const result = await env.DB.prepare(
          "SELECT * FROM " + table
        ).all();

        backup[table] = result.results || [];
      }

      return response({
        format: "XMAIL_BACKUP_V1",
        createdAt: now(),
        data: backup
      });
    }

    if (path === "/api/admin/restore" && method === "POST") {
      const data = await readBody(request);

      if (!data || data.format !== "XMAIL_BACKUP_V1" || !data.data) {
        return response({ error: "Invalid backup file." }, 400);
      }

      const tables = [
        "users", "bans", "whitelist", "settings", "audit_logs"
      ];

      for (const table of tables) {
        if (!Array.isArray(data.data[table])) {
          return response({ error: "Missing backup table: " + table }, 400);
        }
      }

      const total = tables.reduce(
        (sum, table) => sum + data.data[table].length, 0
      );

      if (total > 500) {
        return response({ error: "Backup limit is 500 records." }, 400);
      }

      const statements = [];

      for (const table of tables) {
        statements.push(env.DB.prepare("DELETE FROM " + table));
      }

      for (const u of data.data.users) {
        if (!u.id || !u.username || !u.account_id ||
            !u.password_salt || !u.password_hash || !u.created_at ||
            !["user", "operator"].includes(u.role)) {
          return response({ error: "Invalid user record." }, 400);
        }

        statements.push(env.DB.prepare(`
          INSERT INTO users
          (id, username, account_id, password_salt, password_hash,
           password_change_required, role, created_at, last_ip_hash,
           session_version)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          u.id, u.username, u.account_id, u.password_salt,
          u.password_hash, u.password_change_required || 0,
          u.role, u.created_at, u.last_ip_hash || null,
          u.session_version || 1
        ));
      }

      for (const b of data.data.bans) {
        statements.push(env.DB.prepare(`
          INSERT INTO bans
          (id, user_id, ip_hash, reason, expires_at, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(
          b.id, b.user_id || null, b.ip_hash || null,
          b.reason || "", b.expires_at || null, b.created_at
        ));
      }

      for (const w of data.data.whitelist) {
        statements.push(env.DB.prepare(`
          INSERT INTO whitelist (username, created_at)
          VALUES (?, ?)
        `).bind(w.username, w.created_at));
      }

      for (const s of data.data.settings) {
        statements.push(env.DB.prepare(`
          INSERT INTO settings (key, value) VALUES (?, ?)
        `).bind(s.key, s.value));
      }

      for (const l of data.data.audit_logs) {
        statements.push(env.DB.prepare(`
          INSERT INTO audit_logs
          (id, actor, action, target, details, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(
          l.id, l.actor, l.action, l.target || "",
          l.details || "", l.created_at
        ));
      }

      try {
        await env.DB.batch(statements);
      } catch {
        return response({ error: "Restore failed. Check the backup." }, 400);
      }

      await log(env, operator.username, "restore", "", "Database restored");
      return response({ success: true });
    }
  }

  return response({ error: "API endpoint not found." }, 404);
}

export default {
  async fetch(request, env) {
    try {
      if (!env.DB || !env.SESSION_SECRET ||
          !env.OPERATOR_INITIAL_PASSWORD) {
        return response({
          error: "XMail server configuration is incomplete."
        }, 500);
      }

      if (env.SESSION_SECRET.length < 32) {
        return response({
          error: "SESSION_SECRET must be at least 32 characters."
        }, 500);
      }

      const url = new URL(request.url);

      if (url.pathname.startsWith("/api/")) {
        return await handleApi(request, env);
      }

      return env.ASSETS.fetch(request);
    } catch (error) {
      return response({ error: "Internal server error." }, 500);
    }
  }
};