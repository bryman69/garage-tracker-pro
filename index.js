const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Simple cookie parser
app.use((req, res, next) => {
  req.cookies = {};
  const header = req.headers.cookie;
  if (header) {
    header.split(";").forEach(c => {
      const [k, ...v] = c.trim().split("=");
      req.cookies[k.trim()] = v.join("=");
    });
  }
  next();
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── Database init ─────────────────────────────────────────────────────────────
async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    notify_email TEXT,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await pool.query(`CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  await pool.query(`CREATE TABLE IF NOT EXISTS vehicles (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    vrm TEXT NOT NULL,
    name TEXT, insurer TEXT, insurance_expiry TEXT,
    make TEXT, colour TEXT, mot_expiry TEXT, tax_expiry TEXT,
    dvla_fetched TEXT, dvla_error TEXT, mot_history JSONB,
    mot_history_fetched TEXT, mot_history_error TEXT,
    model TEXT, last_serviced TEXT, v5c_date TEXT, mot_status TEXT,
    added_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, vrm)
  )`);

  await pool.query(`CREATE TABLE IF NOT EXISTS notification_log (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    vrm TEXT, check_type TEXT, days_before INT,
    sent_at TIMESTAMPTZ DEFAULT NOW()
  )`);

  // Create default admin account if none exists
  const existing = await pool.query("SELECT id FROM users WHERE is_admin = TRUE LIMIT 1");
  if (existing.rows.length === 0 && process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await pool.query(
      "INSERT INTO users (email, password_hash, name, notify_email, is_admin) VALUES ($1,$2,$3,$4,TRUE) ON CONFLICT DO NOTHING",
      [process.env.ADMIN_EMAIL, hash, "Admin", process.env.ADMIN_EMAIL]
    );
    console.log("Admin account created:", process.env.ADMIN_EMAIL);
  }

  console.log("Database ready");
}

// ── Auth middleware ───────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: "Not logged in" });
  const result = await pool.query(
    "SELECT s.user_id, u.email, u.name, u.notify_email, u.is_admin FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=$1 AND s.expires_at > NOW()",
    [token]
  );
  if (!result.rows.length) return res.status(401).json({ error: "Session expired" });
  req.user = result.rows[0];
  next();
}

async function requireAdmin(req, res, next) {
  await requireAuth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: "Admin only" });
    next();
  });
}

// ── Static files ──────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

// SPA fallback for auth pages
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

// ── Auth endpoints ────────────────────────────────────────────────────────────
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase().trim()]);
    if (!result.rows.length) return res.status(401).json({ error: "Invalid email or password" });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid email or password" });
    // Create session
    const token = crypto.randomBytes(32).toString("hex");
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
    await pool.query("INSERT INTO sessions (user_id, token, expires_at) VALUES ($1,$2,$3)", [user.id, token, expires]);
    res.setHeader("Set-Cookie", `session=${token}; HttpOnly; Path=/; SameSite=Strict; Expires=${expires.toUTCString()}`);
    res.json({ ok: true, user: { email: user.email, name: user.name, is_admin: user.is_admin } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/logout", async (req, res) => {
  const token = req.cookies.session;
  if (token) await pool.query("DELETE FROM sessions WHERE token=$1", [token]);
  res.setHeader("Set-Cookie", "session=; HttpOnly; Path=/; Max-Age=0");
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ email: req.user.email, name: req.user.name, notify_email: req.user.notify_email, is_admin: req.user.is_admin });
});

app.put("/api/me", requireAuth, async (req, res) => {
  const { name, notify_email, current_password, new_password } = req.body;
  try {
    const updates = [], values = []; let i = 1;
    if (name !== undefined) { updates.push(`name=$${i++}`); values.push(name); }
    if (notify_email !== undefined) { updates.push(`notify_email=$${i++}`); values.push(notify_email); }
    if (new_password && current_password) {
      const userRes = await pool.query("SELECT password_hash FROM users WHERE id=$1", [req.user.user_id]);
      const valid = await bcrypt.compare(current_password, userRes.rows[0].password_hash);
      if (!valid) return res.status(401).json({ error: "Current password incorrect" });
      const hash = await bcrypt.hash(new_password, 12);
      updates.push(`password_hash=$${i++}`); values.push(hash);
    }
    if (!updates.length) return res.status(400).json({ error: "Nothing to update" });
    values.push(req.user.user_id);
    await pool.query(`UPDATE users SET ${updates.join(",")} WHERE id=$${i}`, values);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: manage users ───────────────────────────────────────────────────────
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  const result = await pool.query("SELECT id, email, name, notify_email, is_admin, created_at FROM users ORDER BY created_at ASC");
  res.json(result.rows);
});

app.post("/api/admin/users", requireAdmin, async (req, res) => {
  const { email, password, name, notify_email } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users (email, password_hash, name, notify_email) VALUES ($1,$2,$3,$4) RETURNING id, email, name, notify_email, created_at",
      [email.toLowerCase().trim(), hash, name || null, notify_email || email.toLowerCase().trim()]
    );
    res.json(result.rows[0]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Email already exists" });
    res.status(500).json({ error: e.message });
  }
});

app.delete("/api/admin/users/:id", requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (id === req.user.user_id) return res.status(400).json({ error: "Cannot delete yourself" });
  await pool.query("DELETE FROM users WHERE id=$1", [id]);
  res.json({ ok: true });
});

app.put("/api/admin/users/:id/reset-password", requireAdmin, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: "Password required" });
  const hash = await bcrypt.hash(password, 12);
  await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [hash, req.params.id]);
  res.json({ ok: true });
});

// ── Vehicles (per user) ───────────────────────────────────────────────────────
app.get("/api/vehicles", requireAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM vehicles WHERE user_id=$1 ORDER BY added_at ASC", [req.user.user_id]);
    res.json(result.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/vehicles", requireAuth, async (req, res) => {
  const { vrm, name, insurer, insurance_expiry, last_serviced } = req.body;
  if (!vrm) return res.status(400).json({ error: "VRM required" });
  const cleanVrm = vrm.toUpperCase().replace(/\s/g, "");
  try {
    await pool.query(
      "INSERT INTO vehicles (user_id, vrm, name, insurer, insurance_expiry, last_serviced) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (user_id, vrm) DO NOTHING",
      [req.user.user_id, cleanVrm, name || null, insurer || null, insurance_expiry || null, last_serviced || null]
    );
    const result = await pool.query("SELECT * FROM vehicles WHERE user_id=$1 AND vrm=$2", [req.user.user_id, cleanVrm]);
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put("/api/vehicles/:vrm", requireAuth, async (req, res) => {
  const vrm = req.params.vrm.toUpperCase().replace(/\s/g, "");
  const allowed = ["name","insurer","insurance_expiry","make","colour","model","last_serviced","v5c_date","mot_status","mot_expiry","tax_expiry","dvla_fetched","dvla_error","mot_history","mot_history_fetched","mot_history_error"];
  const updates = [], values = []; let i = 1;
  for (const key of allowed) {
    if (key in req.body) { updates.push(`${key}=$${i++}`); values.push(req.body[key]); }
  }
  if (!updates.length) return res.status(400).json({ error: "Nothing to update" });
  values.push(req.user.user_id, vrm);
  try {
    await pool.query(`UPDATE vehicles SET ${updates.join(",")} WHERE user_id=$${i} AND vrm=$${i+1}`, values);
    const result = await pool.query("SELECT * FROM vehicles WHERE user_id=$1 AND vrm=$2", [req.user.user_id, vrm]);
    res.json(result.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete("/api/vehicles/:vrm", requireAuth, async (req, res) => {
  const vrm = req.params.vrm.toUpperCase().replace(/\s/g, "");
  await pool.query("DELETE FROM vehicles WHERE user_id=$1 AND vrm=$2", [req.user.user_id, vrm]);
  res.json({ ok: true });
});

// ── DVLA lookup ───────────────────────────────────────────────────────────────
app.post("/lookup", requireAuth, async (req, res) => {
  const vrm = (req.body.registrationNumber || "").replace(/\s/g, "").toUpperCase();
  if (!vrm) return res.status(400).json({ error: "Missing VRM" });
  try {
    const dvlaRes = await fetch("https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": process.env.DVLA_API_KEY },
      body: JSON.stringify({ registrationNumber: vrm })
    });
    const data = await dvlaRes.json();
    // Store V5C date + check MOT status change (per user)
    if (data.dateOfLastV5CIssued || data.motStatus) {
      try {
        const existing = await pool.query("SELECT v5c_date, mot_status, name, make FROM vehicles WHERE user_id=$1 AND vrm=$2", [req.user.user_id, vrm]);
        if (existing.rows.length > 0) {
          const prev = existing.rows[0];
          const vName = prev.name || prev.make || vrm;
          const updates = {};
          if (data.dateOfLastV5CIssued && data.dateOfLastV5CIssued !== prev.v5c_date) {
            if (prev.v5c_date) {
              const fmt = new Date(data.dateOfLastV5CIssued).toLocaleDateString("en-GB", { day:"numeric", month:"short", year:"numeric" });
              await sendEmailToUser(req.user.user_id, { vrm, vehicle: vName, type: "V5C Log Book", days: "N/A", expiry: fmt, message: `${vName} (${vrm}) — V5C log book date changed to ${fmt}. Please verify.` });
            }
            updates.v5c_date = data.dateOfLastV5CIssued;
          }
          if (data.motStatus && data.motStatus !== prev.mot_status && prev.mot_status !== null) {
            const isPassed = data.motStatus === "Valid";
            const emoji = isPassed ? "✅" : "❌";
            const expiry = data.motExpiryDate ? new Date(data.motExpiryDate).toLocaleDateString("en-GB", { day:"numeric", month:"short", year:"numeric" }) : "unknown";
            await sendEmailToUser(req.user.user_id, { vrm, vehicle: vName, type: "MOT Status", days: "Now", expiry, message: `${emoji} ${vName} (${vrm}) — MOT ${isPassed ? "PASSED" : "FAILED"}. Expiry: ${expiry}` });
          }
          if (data.motStatus) updates.mot_status = data.motStatus;
          if (Object.keys(updates).length) {
            const sets = Object.keys(updates).map((k,i) => `${k}=$${i+1}`).join(",");
            await pool.query(`UPDATE vehicles SET ${sets} WHERE user_id=$${Object.keys(updates).length+1} AND vrm=$${Object.keys(updates).length+2}`, [...Object.values(updates), req.user.user_id, vrm]);
          }
        }
      } catch(e) { console.log("V5C/MOT update error:", e.message); }
    }
    res.status(dvlaRes.status).json(data);
  } catch (e) { res.status(502).json({ error: "DVLA error: " + e.message }); }
});

// ── MOT history ───────────────────────────────────────────────────────────────
app.get("/mot-history/:vrm", requireAuth, async (req, res) => {
  const vrm = (req.params.vrm || "").replace(/\s/g, "").toUpperCase();
  try {
    const tokenRes = await fetch(
      "https://login.microsoftonline.com/a455b827-244f-4c97-b5b4-ce5d13b4d00c/oauth2/v2.0/token",
      { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "client_credentials", client_id: process.env.MOT_CLIENT_ID, client_secret: process.env.MOT_CLIENT_SECRET, scope: "https://tapi.dvsa.gov.uk/.default" }) }
    );
    if (!tokenRes.ok) return res.status(502).json({ error: "Token error" });
    const { access_token } = await tokenRes.json();
    const motRes = await fetch(`https://history.mot.api.gov.uk/v1/trade/vehicles/registration/${vrm}`,
      { headers: { Authorization: `Bearer ${access_token}`, "X-API-Key": process.env.MOT_API_KEY, Accept: "application/json" } });
    const data = await motRes.json();
    res.status(motRes.status).json(data);
  } catch (e) { res.status(502).json({ error: e.message }); }
});

// ── Email notifications ───────────────────────────────────────────────────────
async function sendEmailToUser(userId, templateParams) {
  const userRes = await pool.query("SELECT notify_email FROM users WHERE id=$1", [userId]);
  if (!userRes.rows.length) return false;
  const email = userRes.rows[0].notify_email;
  if (!email) return false;
  return sendEmailJS({ ...templateParams, to_email: email });
}

async function sendEmailJS(templateParams) {
  const { EMAILJS_PUBLIC_KEY, EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, EMAILJS_PRIVATE_KEY } = process.env;
  if (!EMAILJS_PUBLIC_KEY || !EMAILJS_SERVICE_ID || !EMAILJS_TEMPLATE_ID) return false;
  try {
    const res = await fetch("https://api.emailjs.com/api/v1.0/email/send", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ service_id: EMAILJS_SERVICE_ID, template_id: EMAILJS_TEMPLATE_ID,
        user_id: EMAILJS_PUBLIC_KEY, accessToken: EMAILJS_PRIVATE_KEY || undefined,
        template_params: templateParams })
    });
    const text = await res.text();
    console.log("EmailJS ->", templateParams.to_email, ":", res.status, text);
    return res.status === 200;
  } catch(e) { console.log("EmailJS error:", e.message); return false; }
}

function daysUntil(dateStr) {
  if (!dateStr) return null;
  const now = new Date(); now.setHours(0,0,0,0);
  return Math.ceil((new Date(dateStr) - now) / 86400000);
}

function serviceNextDue(lastServiced) {
  if (!lastServiced) return null;
  const d = new Date(lastServiced);
  d.setFullYear(d.getFullYear() + 1);
  return d.toISOString().split("T")[0];
}

function formatDate(d) {
  if (!d) return "unknown";
  return new Date(d).toLocaleDateString("en-GB", { day:"numeric", month:"short", year:"numeric" });
}

async function alreadyNotified(userId, vrm, checkType, daysBefore) {
  const r = await pool.query(
    "SELECT id FROM notification_log WHERE user_id=$1 AND vrm=$2 AND check_type=$3 AND days_before=$4 AND sent_at > NOW() - INTERVAL '23 hours'",
    [userId, vrm, checkType, daysBefore]);
  return r.rows.length > 0;
}

async function runNotificationCheck() {
  console.log("Running notification check...");
  const { rows: users } = await pool.query("SELECT id, notify_email FROM users WHERE notify_email IS NOT NULL AND notify_email != ''");
  const THRESHOLDS = [30, 7, 1];
  let sent = 0;
  for (const user of users) {
    const { rows: vehicles } = await pool.query("SELECT * FROM vehicles WHERE user_id=$1", [user.id]);
    for (const v of vehicles) {
      const vName = v.name || v.make || v.vrm;
      const checks = [
        { type: "MOT", expiry: v.mot_expiry },
        { type: "Road tax", expiry: v.tax_expiry },
        { type: "Insurance", expiry: v.insurance_expiry },
        { type: "Service", expiry: serviceNextDue(v.last_serviced) },
      ];
      for (const { type, expiry } of checks) {
        if (!expiry) continue;
        const days = daysUntil(expiry);
        if (days === null) continue;
        for (const threshold of THRESHOLDS) {
          if (days <= threshold && days >= threshold - 1) {
            const alreadySent = await alreadyNotified(user.id, v.vrm, type, threshold);
            if (!alreadySent) {
              const label = days <= 0 ? "has expired" : days === 1 ? "is due tomorrow" : `is due in ${days} days`;
              const ok = await sendEmailJS({
                vrm: v.vrm, vehicle: vName, type,
                days: days <= 0 ? "EXPIRED" : `${days} day${days!==1?"s":""}`,
                expiry: formatDate(expiry),
                message: `${vName} (${v.vrm}) — ${type} ${label} on ${formatDate(expiry)}`,
                to_email: user.notify_email
              });
              if (ok) {
                await pool.query("INSERT INTO notification_log (user_id, vrm, check_type, days_before) VALUES ($1,$2,$3,$4)", [user.id, v.vrm, type, threshold]);
                console.log(`Notified user ${user.id}: ${v.vrm} ${type} (${threshold}-day)`);
                sent++;
              }
            }
          }
        }
      }
    }
  }
  console.log(`Notification check done. Sent: ${sent}`);
}

// Schedule at 9am UK time
function scheduleAt9amUK() {
  const now = new Date();
  const london = new Date(now.toLocaleString("en-GB", { timeZone: "Europe/London" }));
  const h = london.getHours(), m = london.getMinutes(), s = london.getSeconds();
  const secsUntil9 = ((9 - h - 1) * 3600 + (60 - m - 1) * 60 + (60 - s)) % 86400;
  const msUntil9 = secsUntil9 <= 0 ? (86400 + secsUntil9) * 1000 : secsUntil9 * 1000;
  console.log("Next check in", Math.round(msUntil9 / 60000), "mins (9am UK)");
  setTimeout(() => {
    runNotificationCheck();
    setInterval(runNotificationCheck, 24 * 60 * 60 * 1000);
  }, msUntil9);
}

// Test email endpoint
app.get("/test-email", requireAuth, async (req, res) => {
  const vrm = req.query.vrm || "TEST01";
  const vehicle = req.query.vehicle || "Test Vehicle";
  const type = req.query.type || "MOT";
  const days = req.query.days || "7 days";
  const expiry = req.query.expiry || "1 May 2027";
  const userRes = await pool.query("SELECT notify_email FROM users WHERE id=$1", [req.user.user_id]);
  const email = userRes.rows[0]?.notify_email;
  if (!email) return res.send("No notification email set in your account settings");
  const ok = await sendEmailJS({ vrm, vehicle, type, days, expiry, message: `${vehicle} (${vrm}) — ${type} is due in ${days} on ${expiry}`, to_email: email });
  res.send(ok ? `✅ Test email sent to ${email}` : "❌ Failed — check logs");
});

const PORT = process.env.PORT || 3000;
initDb().then(() => {
  app.listen(PORT, () => console.log(`Garage Tracker Pro running on port ${PORT}`));
  scheduleAt9amUK();
});
