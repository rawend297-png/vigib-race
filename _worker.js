// AEVORA RACE (dulu VIGIB RACE) — Cloudflare Pages (_worker.js, advanced mode)
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
//
// (2026-11-05) Hapus sesi = benar-benar dihapus. Sesi dikenali lewat timestamp (primary key), lalu dicatat di
//   overlay.purged sebagai "tombstone" { k, t = waktu hapus }. Efeknya:
//   - langsung hilang dari website & panel admin;
//   - server Roblox membaca daftar ini (GET /api/reserved) dan membuang sesi itu dari data.json;
//   - kalau secret GITHUB_TOKEN dipasang di Cloudflare Pages, data.json di GitHub langsung ikut dibersihkan;
//   - (17:50) kalau Book DIKIRIM ULANG dari game, sesi itu MUNCUL LAGI: server game memberi tanda
//     syncedAt (waktu kirim) pada setiap sesi kiriman, dan tombstone hanya berlaku untuk sesi yang
//     syncedAt-nya lebih lama dari waktu hapus.
// (17:50) Badge #N = urutan sesi yang tampil per mode (1 = paling lama, N = jumlah sesi), dihitung ulang
//   setiap /api/data. sessionNumber tetap dipakai sebagai id internal panel admin.
//   Variabel opsional: GITHUB_TOKEN (Contents: Read and write), GITHUB_REPO, GITHUB_BRANCH.

const MODES = ["liga", "normal", "team"];
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
  return {
    deleted: { liga: [], normal: [], team: [] },
    edits: { liga: {}, normal: {}, team: {} },
    lbEdits: { liga: {} },
    lbDeleted: { liga: [] },
    added: { liga: [], normal: [], team: [] },
    maxNum: { liga: 0, normal: 0, team: 0 },
    purged: { liga: [], normal: [], team: [] }, // tombstone hapus permanen: [{ k, b, sig, n, t, by }]
    lbClearedAt: 0, // waktu "Hapus Semua" liga: klasemen data.json yang lebih lama dari ini diabaikan
  };
}
async function getOverlay(env) {
  const ov = (await kvJson(env, "overlay")) || emptyOverlay();
  const base = emptyOverlay();
  for (const k of Object.keys(base)) {
    ov[k] = base[k] !== null && typeof base[k] === "object" ? Object.assign(base[k], ov[k] || {}) : (ov[k] ?? base[k]);
  }
  return ov;
}

// ---------- hapus permanen (PRIMARY KEY sesi = timestamp) ----------
// Kunci selalu milidetik: detik Unix dari game dikali 1000, milidetik dipakai apa adanya.
// HARUS sama dengan stampKey() di VigibWebsite (Roblox).
const MAX_PURGED = 3000;
function stampKey(s) {
  const t = Math.floor(Number(s && s.timestamp));
  if (!Number.isFinite(t) || t <= 0) return 0;
  return t < 1e11 ? t * 1000 : t;
}
// sidik jari isi sesi; HARUS sama dengan sigOf() di VigibWebsite (untuk sesi Book lama tanpa timestamp)
const sigOf = (s) =>
  `${(Array.isArray(s.participants) ? s.participants : []).length}|${(Array.isArray(s.champions) ? s.champions : []).map((c) => `${c && c.userId}:${c && c.rank}`).join(",")}`;
function tombstone(s, user) {
  // t selalu lebih baru dari syncedAt sesi itu (jam server game & Cloudflare bisa beda beberapa detik),
  // jadi versi yang sedang tampil pasti tersembunyi; baru muncul lagi kalau game mengirim ulang setelahnya.
  return { k: stampKey(s), b: int(s.bookNumber) || int(s.sessionNumber), sig: sigOf(s), n: int(s.sessionNumber), t: Math.max(Date.now(), int(s.syncedAt) + 1), by: user };
}
function addPurged(ov, mode, list) {
  // timestamp yang pernah dihapus lalu dikirim ulang dan dihapus lagi: waktu hapusnya diperbarui
  const byK = new Map(ov.purged[mode].map((e) => [Number(e.k), e]));
  for (const e of list) if (e.k > 0) { byK.delete(e.k); byK.set(e.k, e); }
  ov.purged[mode] = [...byK.values()].slice(-MAX_PURGED);
}
// tombstone berlaku hanya untuk sesi yang terakhir dikirim game SEBELUM dihapus
function purgeMap(ov, m) {
  const map = new Map();
  for (const e of ov.purged[m] || []) if (Number(e.k) > 0) map.set(Number(e.k), int(e.t));
  return map;
}
const isHidden = (map, s) => { const k = stampKey(s); return k > 0 && map.has(k) && map.get(k) > int(s.syncedAt); };
// Badge #N = urutan sesi per mode: 1 = paling lama, N = jumlah sesi. Daftar diurutkan terbaru dulu.
function assignBadges(sessions) {
  const asc = sessions.slice().sort((a, b) => (stampKey(a) - stampKey(b)) || (int(a.sessionNumber) - int(b.sessionNumber)));
  asc.forEach((s, i) => { s.badge = i + 1; });
  return asc.reverse();
}

// Buang sesi yang sudah dihapus permanen dari data mentah (data.json). Klasemen liga dikurangi poin
// sesi yang dibuang. Mengembalikan daftar mode yang berubah.
function purgeData(d, ov) {
  const changed = [];
  for (const m of MODES) {
    const md = d.modes[m];
    const map = purgeMap(ov, m);
    const keep = [], gone = [];
    for (const s of md.sessions) (isHidden(map, s) ? gone : keep).push(s);
    let ubah = gone.length > 0;
    md.sessions = keep;
    if (m === "liga" && Array.isArray(md.ligaLeaderboard)) {
      if (int(ov.lbClearedAt) > 0 && int(md.updatedAt) < int(ov.lbClearedAt)) {
        if (md.ligaLeaderboard.length) { md.ligaLeaderboard = []; ubah = true; }
      } else if (gone.length) {
        const minus = {};
        for (const s of gone) {
          for (const l of Array.isArray(s.ligaPoints) ? s.ligaPoints : []) {
            const u = String(int(l && l.userId));
            const x = minus[u] || (minus[u] = { p: 0, c: 0 });
            x.p += num(l.points); x.c += 1;
          }
        }
        md.ligaLeaderboard = md.ligaLeaderboard
          .map((e) => {
            const x = minus[String(e.userId)];
            if (!x) return e;
            const r = { ...e, totalPoints: num(e.totalPoints) - x.p };
            if (e.sessionCount != null) r.sessionCount = Math.max(0, int(e.sessionCount) - x.c);
            return r;
          })
          .filter((e) => !(minus[String(e.userId)] && num(e.totalPoints) <= 0 && (e.sessionCount == null || int(e.sessionCount) <= 0)))
          .sort((a, b) => num(b.totalPoints) - num(a.totalPoints));
      }
    }
    if (ubah) changed.push(m);
  }
  return changed;
}

// Opsional: tulis data.json yang sudah dibersihkan langsung ke GitHub (butuh secret GITHUB_TOKEN).
const b64Bytes = (u8) => { let bin = ""; for (let i = 0; i < u8.length; i += 0x8000) bin += String.fromCharCode(...u8.subarray(i, i + 0x8000)); return btoa(bin); };
async function commitPurge(env, ov, user) {
  if (!env.GITHUB_TOKEN) return { ok: true, github: "off" };
  const repo = env.GITHUB_REPO || "rawend297-png/vigib-race";
  const branch = env.GITHUB_BRANCH || "main";
  const url = `https://api.github.com/repos/${repo}/contents/data.json`;
  const headers = {
    authorization: "Bearer " + env.GITHUB_TOKEN, accept: "application/vnd.github+json",
    "x-github-api-version": "2022-11-28", "user-agent": "vigib-race-worker", "content-type": "application/json",
  };
  for (let attempt = 1; attempt <= 3; attempt++) {
    const g = await fetch(url + "?ref=" + encodeURIComponent(branch), { headers });
    if (g.status === 404) return { ok: true, github: "ok" };
    if (!g.ok) return { ok: false, github: "GitHub " + g.status + " saat membaca data.json" };
    const meta = await g.json();
    let d;
    try { d = normalizeData(JSON.parse(new TextDecoder().decode(unb64(String(meta.content || "").replace(/\s/g, ""))))); }
    catch { return { ok: false, github: "data.json di GitHub tidak bisa dibaca" }; }
    const changed = purgeData(d, ov);
    if (!changed.length) return { ok: true, github: "ok" };
    const now = Date.now();
    for (const m of changed) d.modes[m].updatedAt = now;
    d.updatedAt = now;
    const p = await fetch(url, {
      method: "PUT", headers,
      body: JSON.stringify({
        message: `Admin ${user}: hapus permanen sesi (${changed.join(", ")})`,
        content: b64Bytes(new TextEncoder().encode(JSON.stringify(d))), sha: meta.sha, branch,
      }),
    });
    if (p.ok) return { ok: true, github: "ok" };
    if (p.status !== 409 && p.status !== 422) return { ok: false, github: "GitHub " + p.status + " saat menyimpan data.json" };
    await new Promise((r) => setTimeout(r, 800 * attempt));
  }
  return { ok: false, github: "bentrok saat menyimpan data.json, coba lagi" };
}

function findConflicts(raw, ov) {
  const out = [];
  for (const m of MODES) {
    const ada = new Set(raw.modes[m].sessions.map((s) => Number(s.sessionNumber)));
    for (const n of ov.added[m] || []) {
      if (ada.has(Number(n)) && ov.edits[m][n]) out.push({ mode: m, sessionNumber: Number(n) });
    }
  }
  return out;
}

function reservedNumbers(ov) {
  const out = {};
  for (const m of MODES) {
    const set = new Set([
      ...Object.keys(ov.edits[m] || {}).map(Number),
      ...(ov.deleted[m] || []).map(Number),
      ...(ov.added[m] || []).map(Number),
      Number((ov.maxNum && ov.maxNum[m]) || 0),
    ].filter((n) => Number.isFinite(n) && n > 0));
    out[m] = [...set].sort((a, b) => a - b);
  }
  return out;
}
// daftar hapus permanen untuk server Roblox (VigibWebsite.fetchReserved)
function purgedList(ov) {
  const out = {};
  for (const m of MODES) out[m] = (ov.purged[m] || []).map((e) => ({ k: Number(e.k) || 0, t: int(e.t) }));
  return out;
}

// ---------- kode akses panel (gerbang sebelum login) ----------
async function getGate(env) {
  return kvJson(env, "gate:config");
}
async function gateOk(request, env) {
  const gate = await getGate(env);
  if (!gate) return true;
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
<meta name="robots" content="noindex, nofollow"><title>Kode Akses · AEVORA Race</title><link rel="icon" type="image/png" href="favicon-aevora.png">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@500;600;700&family=Cinzel:wght@700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="aevora.css?v=4">
<style>
*{box-sizing:border-box}html,body{margin:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:#070605;color:#f6eedc;font-family:'Montserrat',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}
.c{position:relative;z-index:2;width:100%;max-width:380px;padding:30px 26px;border-radius:16px;border:1px solid rgba(232,190,92,.55);background:linear-gradient(180deg,rgba(16,14,12,.86),rgba(10,9,8,.84));backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);box-shadow:0 24px 70px rgba(0,0,0,.55),0 0 28px rgba(232,190,92,.08);text-align:center;display:flex;flex-direction:column;gap:14px}
img{width:84px;height:84px;margin:0 auto;filter:drop-shadow(0 0 22px rgba(232,190,92,.45))}
h1{margin:0;font-family:'Cinzel',Georgia,serif;letter-spacing:.06em;font-size:24px;background:linear-gradient(180deg,#ffecaa 0%,#ecbe58 45%,#c48c30 55%,#ffdc82 100%);-webkit-background-clip:text;background-clip:text;color:transparent}
p{margin:0;color:#b0a692;font-size:13px}
input{width:100%;padding:11px 12px;border-radius:10px;border:1px solid rgba(232,190,92,.22);background:rgba(5,4,4,.75);color:#f6eedc;font-size:15px;text-align:center;letter-spacing:.12em;outline:none;font-family:inherit}
input:focus{border-color:#e8be5c;box-shadow:0 0 0 3px rgba(232,190,92,.12)}
button{padding:11px;border-radius:10px;border:0;background:linear-gradient(180deg,#ffe8a6 0%,#e8be5c 60%,#c8933c 100%);color:#261a0a;font-weight:700;font-size:14px;cursor:pointer;font-family:inherit;box-shadow:0 4px 16px rgba(232,190,92,.22)}
button:disabled{opacity:.6}
.e{padding:9px 12px;border-radius:9px;font-size:13px;background:rgba(232,138,122,.1);border:1px solid rgba(232,138,122,.35);color:#e88a7a;display:none}
a{color:#b0a692;font-size:12px;text-decoration:none}a:hover{color:#e8be5c}
</style></head><body>
<script src="aevora.js?v=4"></script>
<form class="c" id="f" autocomplete="off">
<img src="logo-aevora.png" alt="AEVORA"><h1>PANEL ADMIN</h1><p>Masukkan kode akses khusus untuk membuka panel.</p>
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
  if (!acct || acct.ver !== sess.ver) return null;
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
  else await pbkdf2(password || "x", DUMMY_SALT, PBKDF2_ITER);
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
  purgeData(d, ov); // sesi yang dihapus permanen tidak pernah tampil lagi
  for (const m of MODES) {
    const md = d.modes[m];
    const del = new Set((ov.deleted[m] || []).map(Number));
    const ed = ov.edits[m] || {};
    const added = new Set((ov.added[m] || []).map(Number));
    const ada = new Set(md.sessions.map((s) => Number(s.sessionNumber)));
    const tambahan = Object.keys(ed).map(Number).filter((n) => !ada.has(n)).map((n) => ({ ...ed[n], addedByAdmin: true }));
    md.sessions = md.sessions
      .map((s) => (ed[s.sessionNumber] && !added.has(Number(s.sessionNumber)) ? ed[s.sessionNumber] : s))
      .concat(tambahan)
      .filter((s) => !del.has(Number(s.sessionNumber)));
    md.sessions = assignBadges(md.sessions);
  }
  const lb = Array.isArray(d.modes.liga.ligaLeaderboard) ? d.modes.liga.ligaLeaderboard : [];
  const lbDel = new Set((ov.lbDeleted.liga || []).map(String));
  const lbEd = ov.lbEdits.liga || {};
  const lbAda = new Set(lb.map((e) => String(e.userId)));
  const lbTambahan = Object.keys(lbEd).filter((uid) => !lbAda.has(uid))
    .map((uid) => ({ userId: Number(uid), displayName: "", totalPoints: 0, ...lbEd[uid], addedByAdmin: true }));
  const lbBaru = lb.map((e) => (lbEd[e.userId] ? { ...e, ...lbEd[e.userId] } : e))
    .concat(lbTambahan)
    .filter((e) => !lbDel.has(String(e.userId)));
  d.modes.liga.ligaLeaderboard = lbBaru.length ? lbBaru : (Array.isArray(d.modes.liga.ligaLeaderboard) ? [] : null);
  return d;
}

function cleanSession(s, mode, n) {
  const out = {
    sessionNumber: n,
    // nomor sesi dari game (Book). Dipakai untuk judul "Sesi N"; badge #N tetap sessionNumber website.
    ...(int(s.bookNumber) > 0 ? { bookNumber: int(s.bookNumber) } : {}),
    timestamp: int(s.timestamp) || Date.now(),
    mode,
    ...(s.name ? { name: str(s.name, 64) } : {}),
    ...(s.title ? { title: str(s.title, 64) } : {}),
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
  let purge = false;

  switch (path) {
    case "/api/admin/session/save": {
      if (!mode) throw new HttpError("Mode tidak dikenal");

      const raw = normalizeData(await staticData(request, env));
      const rawNums = raw.modes[mode].sessions.map((s) => int(s.sessionNumber));
      const sessionToSave = body.session || {};
      let n = int(sessionToSave.sessionNumber);

      if (n <= 0) {
        // Jika nomor sesi TIDAK diisi (<= 0), hitung otomatis (nomor tertinggi + 1)
        const terpakai = [
          ...rawNums,
          ...Object.keys(ov.edits[mode]).map(Number),
          ...ov.deleted[mode].map(Number),
          int(ov.maxNum[mode]),
        ];
        n = Math.max(0, ...terpakai) + 1;
        ov.maxNum[mode] = Math.max(int(ov.maxNum[mode]), n);
        if (!ov.added[mode].includes(n)) ov.added[mode].push(n);
      } else if (body.isNew) {
        // Sesi baru dengan nomor spesifik yang diinput dari form/book (n > 0)
        ov.maxNum[mode] = Math.max(int(ov.maxNum[mode]), n);
        if (!ov.added[mode].includes(n)) ov.added[mode].push(n);
      } else {
        // Edit sesi yang sudah ada
        if (ov.deleted[mode].map(Number).includes(n)) throw new HttpError(`Sesi #${n} sedang dihapus. Pulihkan dulu.`, 409);
      }

      if (!sessionToSave.timestamp) sessionToSave.timestamp = Date.now();

      ov.edits[mode][n] = cleanSession(sessionToSave, mode, n);
      detail = `simpan sesi ${mode} #${n}`;
      break;
    }
    case "/api/admin/session/revert": {
      if (!mode) throw new HttpError("Mode tidak dikenal");
      const n = int(body.sessionNumber);
      delete ov.edits[mode][n];
      ov.added[mode] = ov.added[mode].filter((x) => Number(x) !== n);
      detail = `batalkan edit ${mode} #${n}`;
      break;
    }
    case "/api/admin/session/delete": {
      // HAPUS PERMANEN satu sesi. Sesi dari game dicatat lewat timestamp-nya (tombstone), sesi buatan admin dibuang.
      if (!mode) throw new HttpError("Mode tidak dikenal");
      const n = int(body.sessionNumber);
      if (n <= 0) throw new HttpError("Nomor sesi tidak valid");
      const raw = normalizeData(await staticData(request, env));
      purgeData(raw, ov);
      const s = raw.modes[mode].sessions.find((x) => int(x.sessionNumber) === n);
      if (s && stampKey(s) > 0) {
        addPurged(ov, mode, [tombstone(s, user.username)]);
        ov.deleted[mode] = ov.deleted[mode].filter((x) => Number(x) !== n);
      } else if (s) {
        if (!ov.deleted[mode].includes(n)) ov.deleted[mode].push(n); // sesi lama tanpa timestamp: disembunyikan lewat nomor
      } else if (!ov.edits[mode][n]) {
        throw new HttpError(`Sesi #${n} tidak ditemukan`, 404);
      }
      delete ov.edits[mode][n];
      ov.added[mode] = ov.added[mode].filter((x) => Number(x) !== n);
      purge = true;
      detail = `hapus permanen sesi ${mode} #${n}`;
      break;
    }
    case "/api/admin/session/deleteAll": {
      // HAPUS SEMUA sesi (mode ini, atau semua mode kalau body.all === true). Permanen.
      const targets = body.all === true ? MODES : mode ? [mode] : null;
      if (!targets) throw new HttpError("Mode tidak dikenal");
      const raw = normalizeData(await staticData(request, env));
      purgeData(raw, ov);
      let total = 0;
      for (const m of targets) {
        const list = raw.modes[m].sessions;
        addPurged(ov, m, list.filter((s) => stampKey(s) > 0).map((s) => tombstone(s, user.username)));
        for (const s of list) if (stampKey(s) <= 0 && !ov.deleted[m].includes(int(s.sessionNumber))) ov.deleted[m].push(int(s.sessionNumber));
        total += list.length + Object.keys(ov.edits[m]).filter((x) => !list.some((s) => int(s.sessionNumber) === Number(x))).length;
        ov.edits[m] = {};
        ov.added[m] = [];
        ov.maxNum[m] = 0;
        if (m === "liga") { ov.lbEdits.liga = {}; ov.lbDeleted.liga = []; ov.lbClearedAt = Date.now(); }
      }
      purge = true;
      detail = `hapus semua sesi ${targets.join(", ")} (${total} sesi)`;
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
  if (purge) {
    // data.json ikut dibersihkan (kalau GITHUB_TOKEN ada). Gagal di sini tidak membatalkan hapus:
    // sesi sudah hilang dari website dan akan dibuang dari data.json saat server game mengirim Book berikutnya.
    let gh;
    try { gh = await commitPurge(env, ov, user.username); } catch (e) { gh = { ok: false, github: String(e && e.message || e) }; }
    return json({ ok: true, overlay: ov, github: gh.github, githubOk: gh.ok });
  }
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
  if (p === "/api/reserved" && m === "GET") {
    if (!env.RACE_KV) return json({ ok: true, reserved: { liga: [], normal: [], team: [] }, purged: { liga: [], normal: [], team: [] } });
    const ov = await getOverlay(env);
    return json({ ok: true, reserved: reservedNumbers(ov), purged: purgedList(ov) });
  }
  if (!env.RACE_KV) return err("KV RACE_KV belum dipasang di Cloudflare Pages", 503);

  if (m !== "GET") {
    if (!(request.headers.get("content-type") || "").includes("application/json") || request.headers.get("x-vigib") !== "1") {
      return err("Permintaan ditolak", 403);
    }
  }

  if (p === "/api/gate" && m === "POST") return handleGate(request, env);
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
    const ov = await getOverlay(env);
    purgeData(raw, ov); // sesi yang sudah dihapus permanen tidak ditampilkan lagi di panel
    return json({ ok: true, raw, overlay: ov, conflicts: findConflicts(raw, ov), githubSync: !!env.GITHUB_TOKEN });
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