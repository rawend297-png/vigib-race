// VIGIB RACE — Cloudflare Pages (_worker.js, advanced mode)
// - Halaman statis (index.html, admin.html, data.json, logo) dilayani dari env.ASSETS.
// - data.json ditulis oleh server Roblox ke repo GitHub.
// - Panel admin: perubahan admin (edit / hapus) disimpan sebagai "overlay" di KV
//   lalu diterapkan di atas data.json saat /api/data diminta. Data asli dari game tidak diubah,
//   jadi semua perubahan bisa dipulihkan.
//
// Binding yang dibutuhkan di Cloudflare Pages:
//   KV namespace  : RACE_KV
//
// Akun:
//   super  -> kelola akun admin (buat, hapus, reset password) + semua hak admin
//   admin  -> edit / hapus data sesi & klasemen

const MODES = ["liga", "normal", "team"];
// Akun super admin dibuat SEKALI lewat halaman setup (admin.html) oleh pemiliknya sendiri.
// Tidak ada password atau hash password di kode ini (repo publik).
const SUPER_USERNAME = "Hanrietsuki";
const DUMMY_SALT = "AAAAAAAAAAAAAAAAAAAAAA==";
const PBKDF2_ITER = 10000;
const SESSION_TTL = 60 * 60 * 12; // 12 jam
const LOGIN_MAX_FAIL = 10; // per IP per 15 menit
const COOKIE = "vgadm";
const GATE_COOKIE = "vggate";
const GATE_TTL = 60 * 60 * 24 * 7; // kode akses berlaku 7 hari per perangkat

// ---------- util ----------
const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra },
  });
const err = (msg, status = 400) => json({ ok: false, error: msg }, status);
const str = (v, max = 64) => (v == null ? "" : String(v)).slice(0, max);
const num = (v, d = 0) => (Number.isFinite(Number(v)) ? Number(v) : d);
const int = (v, d = 0) => (Number.isFinite(Number(v)) ? Math.floor(Number(v)) : d);
const hexColor = (v) => {
  const s = str(v, 9).replace(/[^#0-9a-fA-F]/g, "");
  return s ? (s.startsWith("#") ? s : "#" + s) : "";
};
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const randHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
const userKey = (u) => "acct:" + String(u).toLowerCase();
const validUsername = (u) => typeof u === "string" && /^[A-Za-z0-9_]{3,20}$/.test(u);
const validPassword = (p) => typeof p === "string" && p.length >= 8 && p.length <= 128;

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}

async function pbkdf2(password, saltB64, iter) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unb64(saltB64), iterations: iter }, key, 256);
  return b64(bits);
}
async function makeHash(password) {
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  return { salt, hash: await pbkdf2(password, salt, PBKDF2_ITER), iter: PBKDF2_ITER };
}

function getCookie(request, name) {
  const c = request.headers.get("cookie") || "";
  for (const part of c.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}
const sessionCookie = (token, maxAge) =>
  `${COOKIE}=${token}; Path=/api; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

const gateCookie = (token, maxAge) =>
  `${GATE_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

// ---------- KV helpers ----------
async function kvJson(env, key, fallback = null) {
  const v = await env.RACE_KV.get(key);
  if (!v) return fallback;
  try { return JSON.parse(v); } catch { return fallback; }
}
const kvPut = (env, key, val, opt) => env.RACE_KV.put(key, JSON.stringify(val), opt);

async function getAccount(env, username) {
  return kvJson(env, userKey(username));
}
async function setupNeeded(env) {
  if (await env.RACE_KV.get("setup:done")) return false;
  return !(await kvJson(env, userKey(SUPER_USERNAME)));
}
async function handleSetup(request, env) {
  if (!(await setupNeeded(env))) return err("Setup sudah selesai", 409);
  const body = await readJson(request);
  const username = str(body.username, 40).trim();
  if (username.toLowerCase() !== SUPER_USERNAME.toLowerCase()) return err("Username super admin harus " + SUPER_USERNAME, 400);
  if (!validPassword(body.password)) return err("Password minimal 8 karakter", 400);
  const h = await makeHash(body.password);
  const acct = { username: SUPER_USERNAME, role: "super", ...h, ver: 1, createdAt: Date.now(), createdBy: "setup" };
  await kvPut(env, userKey(SUPER_USERNAME), acct);
  await env.RACE_KV.put("setup:done", "1");
  const token = randHex(32);
  await kvPut(env, "sess:" + token, { username: acct.username, ver: acct.ver, at: Date.now() }, { expirationTtl: SESSION_TTL });
  await addLog(env, acct.username, "akun", "setup super admin");
  return json({ ok: true, user: { username: acct.username, role: acct.role } }, 200, { "set-cookie": sessionCookie(token, SESSION_TTL) });
}

async function addLog(env, user, action, detail) {
  const log = (await kvJson(env, "log", [])) || [];
  log.unshift({ t: Date.now(), user, action, detail: str(detail, 200) });
  await kvPut(env, "log", log.slice(0, 300));
}

function emptyOverlay() {
  return { deleted: { liga: [], normal: [], team: [] }, edits: { liga: {}, normal: {}, team: {} }, lbEdits: { liga: {} }, lbDeleted: { liga: [] } };
}
async function getOverlay(env) {
  const ov = (await kvJson(env, "overlay")) || emptyOverlay();
  const base = emptyOverlay();
  for (const k of Object.keys(base)) ov[k] = Object.assign(base[k], ov[k] || {});
  return ov;
}

// ---------- kode akses panel (gerbang sebelum login) ----------
async function getGate(env) {
  return kvJson(env, "gate:config");
}
async function gateOk(request, env) {
  const gate = await getGate(env);
  if (!gate) return true; // belum ada kode akses -> panel terbuka (hanya login)
  const token = getCookie(request, GATE_COOKIE);
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return false;
  const g = await kvJson(env, "gatetok:" + token);
  return !!(g && g.ver === gate.ver);
}
async function handleGate(request, env) {
  const gate = await getGate(env);
  if (!gate) return json({ ok: true, open: true });
  const ip = request.headers.get("cf-connecting-ip") || "0";
  const rlKey = "rlg:" + ip;
  const fails = int(await env.RACE_KV.get(rlKey), 0);
  if (fails >= LOGIN_MAX_FAIL) return err("Terlalu banyak percobaan. Coba lagi 15 menit lagi.", 429);
  const body = await readJson(request);
  const code = typeof body.code === "string" ? body.code : "";
  const ok = safeEqual(await pbkdf2(code, gate.salt, gate.iter || PBKDF2_ITER), gate.hash);
  if (!ok) {
    await env.RACE_KV.put(rlKey, String(fails + 1), { expirationTtl: 900 });
    return err("Kode akses salah", 401);
  }
  const token = randHex(32);
  await kvPut(env, "gatetok:" + token, { ver: gate.ver, at: Date.now() }, { expirationTtl: GATE_TTL });
  return json({ ok: true }, 200, { "set-cookie": gateCookie(token, GATE_TTL) });
}
const validGateCode = (c) => typeof c === "string" && c.length >= 6 && c.length <= 64;

const GATE_PAGE = `<!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow"><title>Kode Akses · VIGIB Race</title><link rel="icon" type="image/png" href="logo-vg.png">
<style>
*{box-sizing:border-box}html,body{margin:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:#100d0a;color:#faf3e4;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
background-image:radial-gradient(circle at 12% 8%,rgba(226,186,112,.10) 0%,transparent 38%),radial-gradient(circle at 88% 92%,rgba(150,108,48,.12) 0%,transparent 42%)}
.c{width:100%;max-width:380px;padding:30px 26px;border-radius:16px;border:1px solid rgba(226,186,112,.18);background:linear-gradient(180deg,rgba(46,39,29,.82),rgba(34,29,23,.86));text-align:center;display:flex;flex-direction:column;gap:14px}
img{width:76px;height:76px;margin:0 auto;filter:drop-shadow(0 0 18px rgba(226,186,112,.35))}
h1{margin:0;font-family:Georgia,serif;letter-spacing:.06em;font-size:22px;background:linear-gradient(180deg,#ffecc4,#e2ba70 55%,#966c30);-webkit-background-clip:text;background-clip:text;color:transparent}
p{margin:0;color:#b0a696;font-size:13px}
input{width:100%;padding:11px 12px;border-radius:9px;border:1px solid rgba(88,72,50,.9);background:rgba(11,9,7,.75);color:#faf3e4;font-size:15px;text-align:center;letter-spacing:.12em;outline:none}
input:focus{border-color:#e2ba70;box-shadow:0 0 0 3px rgba(226,186,112,.15)}
button{padding:11px;border-radius:9px;border:0;background:linear-gradient(180deg,#ffecc4,#e2ba70);color:#1c160e;font-weight:700;font-size:14px;cursor:pointer}
button:disabled{opacity:.6}
.e{padding:9px 12px;border-radius:9px;font-size:13px;background:rgba(229,138,122,.1);border:1px solid rgba(229,138,122,.35);color:#e58a7a;display:none}
a{color:#b0a696;font-size:12px;text-decoration:none}
</style></head><body>
<form class="c" id="f" autocomplete="off">
<img src="logo-vg.png" alt="VG"><h1>PANEL ADMIN</h1><p>Masukkan kode akses khusus untuk membuka panel.</p>
<div class="e" id="e"></div>
<input id="k" type="password" placeholder="Kode akses" maxlength="64" required autofocus>
<button id="b" type="submit">Buka Panel</button>
<a href="./">← Kembali ke website</a>
</form>
<script>
document.getElementById("f").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const b = document.getElementById("b"), e = document.getElementById("e");
  b.disabled = true; e.style.display = "none";
  try {
    const r = await fetch("/api/gate", { method: "POST", headers: { "content-type": "application/json", "x-vigib": "1" }, body: JSON.stringify({ code: document.getElementById("k").value }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok || j.ok === false) throw new Error(j.error || ("HTTP " + r.status));
    location.reload();
  } catch (er) { e.textContent = er.message; e.style.display = "block"; b.disabled = false; }
});
</script></body></html>`;

// ---------- auth ----------
async function currentUser(request, env) {
  const token = getCookie(request, COOKIE);
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;
  const sess = await kvJson(env, "sess:" + token);
  if (!sess) return null;
  const acct = await kvJson(env, userKey(sess.username));
  if (!acct || acct.ver !== sess.ver) return null; // akun dihapus / password direset
  return { token, username: acct.username, role: acct.role, seeded: !!acct.seeded };
}

async function handleLogin(request, env) {
  const ip = request.headers.get("cf-connecting-ip") || "0";
  const rlKey = "rl:" + ip;
  const fails = int(await env.RACE_KV.get(rlKey), 0);
  if (fails >= LOGIN_MAX_FAIL) return err("Terlalu banyak percobaan. Coba lagi 15 menit lagi.", 429);
  const body = await readJson(request);
  const username = str(body.username, 40).trim();
  const password = typeof body.password === "string" ? body.password : "";
  const acct = validUsername(username) ? await getAccount(env, username) : null;
  let ok = false;
  if (acct) ok = safeEqual(await pbkdf2(password, acct.salt, acct.iter || PBKDF2_ITER), acct.hash);
  else await pbkdf2(password || "x", DUMMY_SALT, PBKDF2_ITER); // samakan waktu respon
  if (!ok) {
    await env.RACE_KV.put(rlKey, String(fails + 1), { expirationTtl: 900 });
    return err("Username atau password salah", 401);
  }
  const token = randHex(32);
  await kvPut(env, "sess:" + token, { username: acct.username, ver: acct.ver, at: Date.now() }, { expirationTtl: SESSION_TTL });
  await addLog(env, acct.username, "login", "");
  return json({ ok: true, user: { username: acct.username, role: acct.role, seeded: !!acct.seeded } }, 200, { "set-cookie": sessionCookie(token, SESSION_TTL) });
}

async function readJson(request) {
  const len = Number(request.headers.get("content-length") || 0);
  if (len > 200_000) throw new HttpError("Data terlalu besar", 413);
  try { return (await request.json()) || {}; } catch { throw new HttpError("JSON tidak valid", 400); }
}
class HttpError extends Error { constructor(m, s) { super(m); this.status = s; } }

// ---------- data ----------
async function staticData(request, env) {
  const r = await env.ASSETS.fetch(new Request(new URL("/data.json", request.url)));
  if (!r.ok) return { ok: true, updatedAt: 0, modes: {}, avatars: {} };
  try { return await r.json(); } catch { return { ok: true, updatedAt: 0, modes: {}, avatars: {} }; }
}

function normalizeData(d) {
  d.modes = d.modes && typeof d.modes === "object" && !Array.isArray(d.modes) ? d.modes : {};
  for (const m of MODES) {
    const md = d.modes[m] && typeof d.modes[m] === "object" ? d.modes[m] : (d.modes[m] = {});
    md.sessions = Array.isArray(md.sessions) ? md.sessions : [];
    if (!Array.isArray(md.ligaLeaderboard)) md.ligaLeaderboard = null;
  }
  if (!d.avatars || Array.isArray(d.avatars)) d.avatars = {};
  return d;
}

function applyOverlay(d, ov) {
  for (const m of MODES) {
    const md = d.modes[m];
    const del = new Set((ov.deleted[m] || []).map(Number));
    const ed = ov.edits[m] || {};
    md.sessions = md.sessions
      .filter((s) => !del.has(Number(s.sessionNumber)))
      .map((s) => (ed[s.sessionNumber] ? ed[s.sessionNumber] : s))
      .sort((a, b) => b.sessionNumber - a.sessionNumber);
  }
  const lb = d.modes.liga.ligaLeaderboard;
  if (Array.isArray(lb)) {
    const del = new Set((ov.lbDeleted.liga || []).map(String));
    const ed = ov.lbEdits.liga || {};
    d.modes.liga.ligaLeaderboard = lb
      .filter((e) => !del.has(String(e.userId)))
      .map((e) => (ed[e.userId] ? { ...e, ...ed[e.userId] } : e));
  }
  return d;
}

function cleanSession(s, mode, n) {
  const out = {
    sessionNumber: n,
    timestamp: int(s.timestamp),
    mode,
    champions: (Array.isArray(s.champions) ? s.champions : []).slice(0, 60).map((c) => ({
      userId: int(c.userId), displayName: str(c.displayName), rank: int(c.rank),
      ...(c.points != null && c.points !== "" ? { points: num(c.points) } : {}),
    })),
    participants: (Array.isArray(s.participants) ? s.participants : []).slice(0, 300).map((p) => ({
      userId: int(p.userId), displayName: str(p.displayName),
      ...(p.team ? { team: { name: str(p.team.name, 40), colorHex: hexColor(p.team.colorHex) } } : {}),
    })),
  };
  if (Array.isArray(s.ligaPoints)) {
    out.ligaPoints = s.ligaPoints.slice(0, 300).map((l) => ({ userId: int(l.userId), displayName: str(l.displayName), points: num(l.points) }));
  }
  if (Array.isArray(s.teamData)) {
    out.teamData = s.teamData.slice(0, 30).map((t) => ({
      name: str(t.name, 40), colorHex: hexColor(t.colorHex), points: num(t.points), memberCount: int(t.memberCount),
      members: (Array.isArray(t.members) ? t.members : []).slice(0, 60).map((m) => ({
        userId: int(m.userId), displayName: str(m.displayName), points: num(m.points), position: int(m.position, 999),
      })),
    }));
  }
  return out;
}

// ---------- admin actions ----------
async function adminAction(path, request, env, user) {
  const ov = await getOverlay(env);
  const body = await readJson(request);
  const mode = MODES.includes(body.mode) ? body.mode : null;
  let detail = "";

  switch (path) {
    case "/api/admin/session/save": {
      if (!mode) throw new HttpError("Mode tidak dikenal");
      const n = int(body.session && body.session.sessionNumber);
      if (n <= 0) throw new HttpError("Nomor sesi tidak valid");
      ov.edits[mode][n] = cleanSession(body.session, mode, n);
      detail = `edit sesi ${mode} #${n}`;
      break;
    }
    case "/api/admin/session/revert": {
      if (!mode) throw new HttpError("Mode tidak dikenal");
      const n = int(body.sessionNumber);
      delete ov.edits[mode][n];
      detail = `batalkan edit ${mode} #${n}`;
      break;
    }
    case "/api/admin/session/delete": {
      if (!mode) throw new HttpError("Mode tidak dikenal");
      const n = int(body.sessionNumber);
      if (n <= 0) throw new HttpError("Nomor sesi tidak valid");
      if (!ov.deleted[mode].includes(n)) ov.deleted[mode].push(n);
      detail = `hapus sesi ${mode} #${n}`;
      break;
    }
    case "/api/admin/session/restore": {
      if (!mode) throw new HttpError("Mode tidak dikenal");
      const n = int(body.sessionNumber);
      ov.deleted[mode] = ov.deleted[mode].filter((x) => x !== n);
      detail = `pulihkan sesi ${mode} #${n}`;
      break;
    }
    case "/api/admin/leaderboard/save": {
      const uid = String(int(body.userId));
      if (uid === "0") throw new HttpError("UserId tidak valid");
      ov.lbEdits.liga[uid] = { displayName: str(body.displayName), totalPoints: num(body.totalPoints), ...(body.sessionCount != null ? { sessionCount: int(body.sessionCount) } : {}) };
      detail = `edit klasemen liga ${uid} → ${ov.lbEdits.liga[uid].totalPoints} pts`;
      break;
    }
    case "/api/admin/leaderboard/revert": {
      const uid = String(int(body.userId));
      delete ov.lbEdits.liga[uid];
      detail = `batalkan edit klasemen ${uid}`;
      break;
    }
    case "/api/admin/leaderboard/delete": {
      const uid = String(int(body.userId));
      if (!ov.lbDeleted.liga.includes(uid)) ov.lbDeleted.liga.push(uid);
      detail = `hapus dari klasemen liga ${uid}`;
      break;
    }
    case "/api/admin/leaderboard/restore": {
      const uid = String(int(body.userId));
      ov.lbDeleted.liga = ov.lbDeleted.liga.filter((x) => x !== uid);
      detail = `pulihkan klasemen ${uid}`;
      break;
    }
    default:
      throw new HttpError("Tidak ditemukan", 404);
  }
  await kvPut(env, "overlay", ov);
  await addLog(env, user.username, "data", detail);
  return json({ ok: true, overlay: ov });
}

async function superAction(path, request, env, user) {
  if (path === "/api/super/gate" && request.method === "GET") {
    const g = await getGate(env);
    return json({ ok: true, active: !!g, updatedAt: g ? g.updatedAt : null, updatedBy: g ? g.updatedBy : null });
  }
  if (path === "/api/super/gate") {
    const body = await readJson(request);
    if (!validGateCode(body.code)) throw new HttpError("Kode akses 6-64 karakter");
    const old = await getGate(env);
    const h = await makeHash(body.code);
    await kvPut(env, "gate:config", { ...h, ver: ((old && old.ver) || 0) + 1, updatedAt: Date.now(), updatedBy: user.username });
    await addLog(env, user.username, "akun", old ? "ganti kode akses panel" : "pasang kode akses panel");
    // perangkat super admin ini langsung diberi akses baru supaya tidak terkunci sendiri
    const g = await getGate(env);
    const token = randHex(32);
    await kvPut(env, "gatetok:" + token, { ver: g.ver, at: Date.now() }, { expirationTtl: GATE_TTL });
    return json({ ok: true }, 200, { "set-cookie": gateCookie(token, GATE_TTL) });
  }
  if (path === "/api/super/accounts" && request.method === "GET") {
    const list = [];
    let cursor;
    do {
      const r = await env.RACE_KV.list({ prefix: "acct:", cursor });
      for (const k of r.keys) {
        const a = await kvJson(env, k.name);
        if (a) list.push({ username: a.username, role: a.role, createdAt: a.createdAt, createdBy: a.createdBy, updatedAt: a.updatedAt || null });
      }
      cursor = r.list_complete ? null : r.cursor;
    } while (cursor);
    list.sort((a, b) => (a.role === b.role ? a.username.localeCompare(b.username) : a.role === "super" ? -1 : 1));
    return json({ ok: true, accounts: list });
  }
  const body = await readJson(request);
  const username = str(body.username, 40).trim();
  if (!validUsername(username)) throw new HttpError("Username 3-20 karakter: huruf, angka, garis bawah");

  if (path === "/api/super/accounts/create") {
    if (!validPassword(body.password)) throw new HttpError("Password minimal 8 karakter");
    if (await getAccount(env, username)) throw new HttpError("Username sudah dipakai", 409);
    const h = await makeHash(body.password);
    await kvPut(env, userKey(username), { username, role: "admin", ...h, ver: 1, createdAt: Date.now(), createdBy: user.username });
    await addLog(env, user.username, "akun", `buat admin ${username}`);
    return json({ ok: true });
  }
  const acct = await getAccount(env, username);
  if (!acct) throw new HttpError("Akun tidak ditemukan", 404);

  if (path === "/api/super/accounts/delete") {
    if (acct.role === "super") throw new HttpError("Akun super admin tidak bisa dihapus");
    await env.RACE_KV.delete(userKey(username));
    await addLog(env, user.username, "akun", `hapus admin ${acct.username}`);
    return json({ ok: true });
  }
  if (path === "/api/super/accounts/reset") {
    if (!validPassword(body.password)) throw new HttpError("Password minimal 8 karakter");
    const h = await makeHash(body.password);
    Object.assign(acct, h, { ver: (acct.ver || 1) + 1, updatedAt: Date.now(), seeded: false });
    await kvPut(env, userKey(acct.username), acct);
    await addLog(env, user.username, "akun", `reset password ${acct.username}`);
    return json({ ok: true });
  }
  throw new HttpError("Tidak ditemukan", 404);
}

async function changeOwnPassword(request, env, user) {
  const body = await readJson(request);
  const acct = await kvJson(env, userKey(user.username));
  if (!acct) throw new HttpError("Akun tidak ditemukan", 404);
  const okOld = safeEqual(await pbkdf2(String(body.oldPassword || ""), acct.salt, acct.iter || PBKDF2_ITER), acct.hash);
  if (!okOld) throw new HttpError("Password lama salah", 401);
  if (!validPassword(body.newPassword)) throw new HttpError("Password baru minimal 8 karakter");
  const h = await makeHash(body.newPassword);
  Object.assign(acct, h, { ver: (acct.ver || 1) + 1, updatedAt: Date.now(), seeded: false });
  await kvPut(env, userKey(acct.username), acct);
  // buat sesi baru supaya tetap login
  const token = randHex(32);
  await kvPut(env, "sess:" + token, { username: acct.username, ver: acct.ver, at: Date.now() }, { expirationTtl: SESSION_TTL });
  await env.RACE_KV.delete("sess:" + user.token);
  await addLog(env, acct.username, "akun", "ganti password sendiri");
  return json({ ok: true }, 200, { "set-cookie": sessionCookie(token, SESSION_TTL) });
}

// ---------- router ----------
async function handleApi(request, env, url) {
  const p = url.pathname.replace(/\/+$/, "");
  const m = request.method;

  if (p === "/api/health") return json({ ok: true, kv: !!env.RACE_KV });
  if (p === "/api/data" && m === "GET") {
    const d = normalizeData(await staticData(request, env));
    if (env.RACE_KV) applyOverlay(d, await getOverlay(env));
    return json(d);
  }
  if (!env.RACE_KV) return err("KV RACE_KV belum dipasang di Cloudflare Pages", 503);

  // semua permintaan yang mengubah data wajib JSON + header khusus (perlindungan CSRF)
  if (m !== "GET") {
    if (!(request.headers.get("content-type") || "").includes("application/json") || request.headers.get("x-vigib") !== "1") {
      return err("Permintaan ditolak", 403);
    }
  }

  if (p === "/api/gate" && m === "POST") return handleGate(request, env);
  // semua API panel (setup, login, admin, super) wajib lolos kode akses kalau kode sudah dipasang
  if (!(await gateOk(request, env))) return err("Kode akses panel diperlukan", 403);

  if (p === "/api/setup" && m === "GET") return json({ ok: true, needed: await setupNeeded(env), username: SUPER_USERNAME });
  if (p === "/api/setup" && m === "POST") return handleSetup(request, env);
  if (p === "/api/login" && m === "POST") return handleLogin(request, env);

  const user = await currentUser(request, env);
  if (p === "/api/me") return user ? json({ ok: true, user: { username: user.username, role: user.role, seeded: user.seeded } }) : err("Belum login", 401);
  if (p === "/api/logout" && m === "POST") {
    if (user) await env.RACE_KV.delete("sess:" + user.token);
    return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });
  }
  if (!user) return err("Belum login", 401);

  if (p === "/api/password" && m === "POST") return changeOwnPassword(request, env, user);
  if (p === "/api/admin/state" && m === "GET") {
    const raw = normalizeData(await staticData(request, env));
    return json({ ok: true, raw, overlay: await getOverlay(env) });
  }
  if (p === "/api/admin/log" && m === "GET") return json({ ok: true, log: (await kvJson(env, "log", [])) || [] });
  if (p.startsWith("/api/admin/") && m === "POST") return adminAction(p, request, env, user);

  if (p.startsWith("/api/super/")) {
    if (user.role !== "super") return err("Khusus super admin", 403);
    return superAction(p, request, env, user);
  }
  return err("Tidak ditemukan", 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(request, env, url);
      } catch (e) {
        if (e instanceof HttpError) return err(e.message, e.status || 400);
        return err("Kesalahan server: " + (e && e.message ? e.message : e), 500);
      }
    }
    const isAdmin = url.pathname === "/admin" || url.pathname === "/admin.html";
    if (isAdmin && env.RACE_KV && !(await gateOk(request, env))) {
      return new Response(GATE_PAGE, { status: 200, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY", "referrer-policy": "no-referrer" } });
    }
    const res = await env.ASSETS.fetch(request);
    if (isAdmin) {
      const h = new Headers(res.headers);
      h.set("x-frame-options", "DENY");
      h.set("referrer-policy", "no-referrer");
      h.set("cache-control", "no-store");
      return new Response(res.body, { status: res.status, headers: h });
    }
    return res;
  },
};
