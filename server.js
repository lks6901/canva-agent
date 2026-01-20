import express from "express";
import multer from "multer";
import crypto from "crypto";
import "dotenv/config";
import { PDFDocument } from "pdf-lib";


const app = express();
const upload = multer({ storage: multer.memoryStorage() });

const { CANVA_CLIENT_ID, CANVA_CLIENT_SECRET, APP_BASE_URL } = process.env;

if (!CANVA_CLIENT_ID || !CANVA_CLIENT_SECRET || !APP_BASE_URL) {
  console.error("❌ Missing env vars: CANVA_CLIENT_ID, CANVA_CLIENT_SECRET, APP_BASE_URL");
  process.exit(1);
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- sessions en mémoire (MVP)
const sessions = new Map(); // sid -> { codeVerifier, accessToken, refreshToken, expiresAt }

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function sha256ToB64url(str) {
  return b64url(crypto.createHash("sha256").update(str).digest());
}
function newSid() {
  return crypto.randomBytes(16).toString("hex");
}
function getSid(req) {
  const m = (req.headers.cookie || "").match(/sid=([a-f0-9]+)/);
  return m?.[1] || null;
}
function setSid(res, sid) {
  res.setHeader("Set-Cookie", `sid=${sid}; Path=/; SameSite=Lax`);
}

// Canva endpoints
const CANVA_AUTHORIZE_URL = "https://www.canva.com/api/oauth/authorize";
const CANVA_TOKEN_URL = "https://api.canva.com/rest/v1/oauth/token";

function basicAuthHeader() {
  return "Basic " + Buffer.from(`${CANVA_CLIENT_ID}:${CANVA_CLIENT_SECRET}`).toString("base64");
}

async function canvaFetch(url, { method = "GET", headers = {}, body } = {}) {
  const resp = await fetch(url, { method, headers, body });
  const text = await resp.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch {}
  if (!resp.ok) throw new Error(json?.message || json?.error_description || text || `HTTP ${resp.status}`);
  return json;
}

// UI
app.get("/", (req, res) => {
  const sid = getSid(req);
  const sess = sid ? sessions.get(sid) : null;
  const loggedIn = !!sess?.accessToken;

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.end(`
    <h1>Canva Agent</h1>
    <p>Status: ${loggedIn ? "✅ connecté à Canva" : "❌ pas connecté"}</p>
    <p><a href="/auth/canva">Se connecter à Canva</a></p>
  `);
});

// OAuth start (PKCE)
app.get("/auth/canva", (req, res) => {
  const sid = newSid();
  setSid(res, sid);

  const codeVerifier = b64url(crypto.randomBytes(32));
  const codeChallenge = sha256ToB64url(codeVerifier);
  sessions.set(sid, { codeVerifier });

  const redirectUri = `${APP_BASE_URL}/oauth/callback`;
  const state = crypto.randomBytes(16).toString("hex");
  const scope = encodeURIComponent("design:content:write design:content:read");

  const url =
    `${CANVA_AUTHORIZE_URL}` +
    `?code_challenge=${encodeURIComponent(codeChallenge)}` +
    `&code_challenge_method=s256` +
    `&scope=${scope}` +
    `&response_type=code` +
    `&client_id=${encodeURIComponent(CANVA_CLIENT_ID)}` +
    `&state=${encodeURIComponent(state)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}`;

  res.redirect(url);
});

// OAuth callback
app.get("/oauth/callback", async (req, res) => {
  try {
    const sid = getSid(req);
    if (!sid || !sessions.get(sid)) throw new Error("Session introuvable. Recommence /auth/canva.");

    const sess = sessions.get(sid);
    const { code } = req.query;
    if (!code) throw new Error("Code manquant.");

    const redirectUri = `${APP_BASE_URL}/oauth/callback`;
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: String(code),
      code_verifier: sess.codeVerifier,
      redirect_uri: redirectUri
    });

    const token = await canvaFetch(CANVA_TOKEN_URL, {
      method: "POST",
      headers: {
        "Authorization": basicAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    });

    sess.accessToken = token.access_token;
    sess.refreshToken = token.refresh_token;
    sess.expiresAt = Date.now() + (token.expires_in * 1000);
    sessions.set(sid, sess);

    res.redirect("/");
  } catch (e) {
    res.status(500).send("Erreur OAuth: " + String(e.message || e));
  }
});

const PORT = process.env.PORT || 10000;
// --- helper : récupérer access token depuis TA session en mémoire
function getAccessToken(req) {
  const sid = getSid(req);
  const sess = sid ? sessions.get(sid) : null;
  return sess?.accessToken || null;
}

function titleBase64(title) {
  return Buffer.from(title, "utf8").toString("base64");
}

// 1) IMPORT PPTX -> Canva (job)
app.post("/api/import", upload.single("file"), async (req, res) => {
  try {
    const token = getAccessToken(req);
    if (!token) return res.status(401).json({ error: "Pas connecté à Canva" });
    if (!req.file) return res.status(400).json({ error: "Fichier manquant" });

    const title = req.body?.title || "DISCIPLINE - Lukas GUILLAUD";
    const mimeType =
      req.file.mimetype ||
      "application/vnd.openxmlformats-officedocument.presentationml.presentation";

    const r = await fetch("https://api.canva.com/rest/v1/imports", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/octet-stream",
        "Import-Metadata": JSON.stringify({
          title_base64: titleBase64(title),
          mime_type: mimeType,
        }),
      },
      body: req.file.buffer,
    });

    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);

    return res.json({ jobId: data?.job?.id, status: data?.job?.status });
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

// 2) STATUS IMPORT (job -> designId + edit_url)
app.get("/api/import/:jobId", async (req, res) => {
  try {
    const token = getAccessToken(req);
    if (!token) return res.status(401).json({ error: "Pas connecté à Canva" });

    const { jobId } = req.params;
    const r = await fetch(`https://api.canva.com/rest/v1/imports/${jobId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);

    return res.json(data);
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

// 3) EXPORT PDF (designId -> export job)
app.post("/api/export/pdf", async (req, res) => {
  try {
    const token = getAccessToken(req);
    if (!token) return res.status(401).json({ error: "Pas connecté à Canva" });

    const { designId, quality = "regular" } = req.body || {};
    if (!designId) return res.status(400).json({ error: "designId manquant" });

    const r = await fetch("https://api.canva.com/rest/v1/exports", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        design_id: designId,
        format: { type: "pdf", export_quality: quality },
      }),
    });

    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);

    return res.json({ exportId: data?.job?.id, status: data?.job?.status });
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

// 4) STATUS EXPORT (export job -> urls)
app.get("/api/export/:exportId", async (req, res) => {
  try {
    const token = getAccessToken(req);
    if (!token) return res.status(401).json({ error: "Pas connecté à Canva" });

    const { exportId } = req.params;
    const r = await fetch(`https://api.canva.com/rest/v1/exports/${exportId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);

    return res.json(data);
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});

// 5) FUSIONNER plusieurs PDFs (urls Canva) en 1 PDF
app.post("/api/merge-pdf", async (req, res) => {
  try {
    const { urls, filename = "DISCIPLINE.pdf" } = req.body || {};
    if (!Array.isArray(urls) || urls.length < 2) {
      return res.status(400).json({ error: "Il faut au moins 2 urls PDF" });
    }

    const merged = await PDFDocument.create();

    for (const u of urls) {
      const bytes = await fetch(u).then(r => r.arrayBuffer());
      const doc = await PDFDocument.load(bytes);
      const pages = await merged.copyPages(doc, doc.getPageIndices());
      pages.forEach(p => merged.addPage(p));
    }

    const out = await merged.save();

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    return res.send(Buffer.from(out));
  } catch (e) {
    return res.status(500).json({ error: String(e?.message || e) });
  }
});
app.listen(PORT, () => console.log("Serveur lancé sur le port", PORT));
