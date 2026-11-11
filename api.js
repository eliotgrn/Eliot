// Planning Eliot — serveur de synchronisation (Cloudflare Pages Function, route /api)
// Base D1 reliée sous le nom DB. Un seul compte : le premier créé.
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const sha = async s => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
const rnd = n => hex(crypto.getRandomValues(new Uint8Array(n)));
async function pwHash(pw, salt) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new TextEncoder().encode(salt), iterations: 20000 }, k, 256));
}
let ready = false;
async function init(db) {
  if (ready) return;
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY, salt TEXT, hash TEXT, created INTEGER)"),
    db.prepare("CREATE TABLE IF NOT EXISTS sessions(th TEXT PRIMARY KEY, email TEXT, created INTEGER)"),
    db.prepare("CREATE TABLE IF NOT EXISTS counters(email TEXT PRIMARY KEY, rev INTEGER)"),
    db.prepare("CREATE TABLE IF NOT EXISTS records(email TEXT, k TEXT, v TEXT, t INTEGER, rev INTEGER, PRIMARY KEY(email,k))"),
    db.prepare("CREATE INDEX IF NOT EXISTS records_rev ON records(email,rev)"),
    db.prepare("CREATE TABLE IF NOT EXISTS fails(email TEXT, t INTEGER)")
  ]);
  ready = true;
}
async function newSession(db, email) {
  const tok = rnd(32);
  await db.prepare("INSERT INTO sessions(th,email,created) VALUES(?,?,?)").bind(await sha(tok), email, Date.now()).run();
  return tok;
}

export async function onRequest({ request, env }) {
  const db = env.DB;
  if (request.method === "GET") return J({ ok: true, db: !!db });
  if (request.method !== "POST") return J({ error: "Méthode non permise" }, 405);
  if (!db) return J({ error: "Base de données pas encore reliée au serveur." }, 503);
  let body;
  try { body = await request.json(); } catch (e) { return J({ error: "Requête illisible" }, 400); }
  await init(db);
  const a = body.a;

  if (a === "register" || a === "login") {
    const email = String(body.email || "").trim().toLowerCase(), pw = String(body.password || "");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return J({ error: "Adresse e-mail invalide." }, 400);
    if (pw.length < 8) return J({ error: "Mot de passe : 8 caractères minimum." }, 400);
    if (a === "register") {
      const n = await db.prepare("SELECT COUNT(*) AS n FROM users").first("n");
      if (n > 0) return J({ error: "Le compte existe déjà : touche « Se connecter »." }, 409);
      const salt = rnd(16);
      await db.batch([
        db.prepare("INSERT INTO users(email,salt,hash,created) VALUES(?,?,?,?)").bind(email, salt, await pwHash(pw, salt), Date.now()),
        db.prepare("INSERT OR IGNORE INTO counters(email,rev) VALUES(?,0)").bind(email)
      ]);
      return J({ tok: await newSession(db, email), email, created: true });
    }
    const since = Date.now() - 15 * 60 * 1000;
    const f = await db.prepare("SELECT COUNT(*) AS n FROM fails WHERE email=? AND t>?").bind(email, since).first("n");
    if (f >= 8) return J({ error: "Trop d'essais. Réessaie dans 15 minutes." }, 429);
    const u = await db.prepare("SELECT salt,hash FROM users WHERE email=?").bind(email).first();
    if (!u || (await pwHash(pw, u.salt)) !== u.hash) {
      await db.prepare("INSERT INTO fails(email,t) VALUES(?,?)").bind(email, Date.now()).run();
      return J({ error: u ? "Mot de passe incorrect." : "Aucun compte avec cette adresse." }, 401);
    }
    await db.prepare("DELETE FROM fails WHERE email=?").bind(email).run();
    return J({ tok: await newSession(db, email), email });
  }

  // Requêtes authentifiées
  const tok = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const email = tok ? await db.prepare("SELECT email FROM sessions WHERE th=?").bind(await sha(tok)).first("email") : null;
  if (!email) return J({ error: "Session expirée : reconnecte-toi." }, 401);

  if (a === "logout") {
    await db.prepare("DELETE FROM sessions WHERE th=?").bind(await sha(tok)).run();
    return J({ ok: true });
  }

  if (a === "sync") {
    const changes = Array.isArray(body.changes) ? body.changes.filter(c => c && typeof c.k === "string" && Number.isFinite(c.t) && (c.v === null || typeof c.v === "string")) : [];
    let rev = await db.prepare("SELECT rev FROM counters WHERE email=?").bind(email).first("rev") || 0;
    let since = Number(body.since) || 0;
    if (since > rev) since = 0; // base remise à zéro : on renvoie tout
    if (changes.length) {
      rev = await db.prepare("UPDATE counters SET rev=rev+1 WHERE email=? RETURNING rev").bind(email).first("rev");
      // dernière modification gagnante, élément par élément
      await db.prepare(`INSERT INTO records(email,k,v,t,rev)
        SELECT ?1, json_extract(value,'$.k'), json_extract(value,'$.v'), json_extract(value,'$.t'), ?2 FROM json_each(?3) WHERE 1
        ON CONFLICT(email,k) DO UPDATE SET v=excluded.v, t=excluded.t, rev=excluded.rev WHERE excluded.t>=records.t`)
        .bind(email, rev, JSON.stringify(changes)).run();
    }
    // tout ce qui a changé depuis le dernier passage + l'état réel des éléments envoyés (si une version plus récente existait déjà)
    const rows = (await db.prepare(`SELECT k,v,t FROM records WHERE email=?1 AND (rev>?2 OR k IN (SELECT json_extract(value,'$.k') FROM json_each(?3)))`)
      .bind(email, since, JSON.stringify(changes)).all()).results || [];
    return J({ cursor: rev, changes: rows });
  }
  return J({ error: "Action inconnue" }, 400);
}
