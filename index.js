/**
 * Kushtia Smart Tutor — Auth + Ad-Request (Tutor Advertisement) Worker
 *
 * Handles: OTP send/verify (email works today, mobile is a TODO stub, same
 * as before), password-based register + login backed by D1 (both "user" and
 * "tutor" roles are active the moment they register — there is no approval
 * gate on signup or login anymore), and a separate, optional "ad request"
 * workflow: a logged-in tutor fills one combined form (profile info + photo
 * URL from client-side Cloudinary upload + payment proof) to ask for a public
 * listing; an admin reviews and approves/rejects it. Being rejected or having
 * no ad request at all does NOT stop a tutor from logging in or using their
 * account — it only controls whether they show up on GET /api/tutors.
 *
 * Bindings needed (set in wrangler.toml / Cloudflare dashboard):
 *   - KV Namespace: OTP_KV          (OTP codes + "verified:<contact>" flags — unchanged)
 *   - D1 Database:  DB              (users / ad_requests / admins — see schema.sql)
 *   - Secret:       RESEND_API_KEY  (from resend.com, free plan)
 *   - Secret:       ADMIN_SECRET    (random long string — signs admin session tokens)
 *   - Secret:       ADMIN_SETUP_KEY (random string — protects the one-time admin bootstrap route)
 *   - Var:          ALLOWED_ORIGIN  (e.g. "https://your-site.com" — for CORS)
 *   - Var:          RESEND_FROM     (verified sender, e.g. "Kushtia Smart Tutor <noreply@yourdomain.com>")
 *
 * Endpoints:
 *   POST /api/send-otp           { contact, method, fallbackEmail? }   method: "mobile" | "email"
 *   POST /api/verify-otp         { contact, otp }
 *   POST /api/register           { identifier, email, phone, name, role, password, agreedTerms }
 *                                 -- both roles are active immediately, no pending state, no ad-request fields here anymore.
 *   POST /api/login               { identifier, password }
 *                                 -- for role="tutor", the response includes `adRequest` (latest ad_requests row, or null)
 *                                    so the frontend can prefill / show current advertisement status.
 *   POST /api/ad-request-submit  { userId, name, phone, subject, qualification, area, photoUrl, paySender, payTrx, payAmount, ...profile fields }
 *                                 -- ONE ad per account: first submission INSERTs, every later submission
 *                                    UPDATEs that same row and resets status to 'pending'. Errors if already pending.
 *   POST /api/admin-login        { email, password }
 *   POST /api/admin/bootstrap    { email, password, setupKey }   -- one-time, creates the first admin
 *   GET  /api/admin/ad-requests  (Authorization: Bearer <admin token>)   -- LEGACY, still works: pending ad_requests, with photo + payment info
 *   POST /api/admin/approve-ad-request { requestId }             (Authorization: Bearer <admin token>)  -- LEGACY, sets status='running'
 *   POST /api/admin/reject-ad-request  { requestId, note }        (Authorization: Bearer <admin token>)  -- LEGACY
 *   GET  /api/tutors             (public — LEGACY, status='running' ad_requests, includes photo_url)
 *
 *   -- Admin dashboard (admin-panel.html) --
 *   GET  /api/admin/dashboard-stats                    (Authorization: Bearer <admin token>)
 *   GET  /api/admin/ads?status=pending|running|paused|rejected|cancelled   (comma-separated statuses allowed)
 *   POST /api/admin/ads/:id/approve   -- status -> running
 *   POST /api/admin/ads/:id/reject    { note }   -- status -> rejected
 *   POST /api/admin/ads/:id/pause     -- status -> paused
 *   POST /api/admin/ads/:id/resume    -- status -> running
 *   POST /api/admin/ads/:id/delete    -- permanently deletes the row
 *   POST /api/admin/ads/:id/update    { name, phone, subject, qualification, area,
 *                                        gender, university, department, session, currentLocation,
 *                                        expectedSalary, experienceYears, subjects,
 *                                        eduBachelorDept, eduBachelorSession, eduBachelorCurrent,
 *                                        sscYear, sscSchool, sscGroup, sscResult,
 *                                        hscYear, hscCollege, hscGroup, hscResult, extraInfo }
 *   POST /api/admin/ads/:id/availability  { availability: "available" | "busy" }
 *
 *   NOTE — POST /api/admin/ads/:id/approve now also auto-generates tutor_id
 *   the first time an ad is approved (prefix derived from `university`, e.g.
 *   "Rajshahi University" -> RU_1240; serial tracked per-prefix in the
 *   tutor_id_counters table). Re-approving an already-approved ad does not
 *   overwrite its existing tutor_id. REQUIRES body { validityDays } (a
 *   positive integer, days) — sets expires_at = now + validityDays. Response
 *   includes { ok, tutorId, expiresAt }.
 *
 *   NOTE — POST /api/admin/ads/:id/resume accepts an optional body
 *   { validityDays } to restart the expiry clock; omitted, it just resumes
 *   with the existing expires_at as-is and clears auto_expired.
 *
 *   NOTE — a scheduled() Cron Trigger handler (see bottom of file) auto-
 *   pauses any 'running' ad whose expires_at has passed, setting
 *   auto_expired = 1 so the admin panel can flag it for deletion.
 *
 *   -- Public tutor listing (hire-tutor.html) --
 *   GET  /api/public/tutors      (public — status='running' ad_requests, card fields:
 *                                  avatarUrl, name, university, department, session, gender,
 *                                  tutorId, currentLocation, availability, subjects)
 *   GET  /api/public/tutors/:id  (public — status='running' only, full profile fields for
 *                                  tutor-profile.html: education, subjects, experience, extra info.
 *                                  Excludes phone/email/payment info.)
 *
 * NOTE — SMS OTP: there is no SMS gateway wired up yet. When method is
 * "mobile", sendOtp() falls back to emailing the code to `fallbackEmail` if
 * the user supplied one during signup. Swap in a real SMS provider inside
 * sendOtpSms() below once you pick one.
 */

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function json(data, status, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(env) },
  });
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000)); // 6 digits
}

function isEmail(str) {
  return /^\S+@\S+\.\S+$/.test(str);
}
function isPhone(str) {
  return /^01[0-9]{9}$/.test(str);
}

async function sendOtpEmail(env, email, otp) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: env.RESEND_FROM,
      to: [email],
      subject: "আপনার Kushtia Smart Tutor OTP কোড",
      html: `
        <div style="font-family:sans-serif;padding:24px;">
          <h2 style="color:#1B7A3D;">Kushtia Smart Tutor</h2>
          <p>আপনার ভেরিফিকেশন কোড:</p>
          <p style="font-size:28px;font-weight:700;letter-spacing:6px;color:#0E3B22;">${otp}</p>
          <p style="color:#666;font-size:13px;">এই কোডটি ৫ মিনিটের জন্য কার্যকর থাকবে। আপনি যদি এই রিকুয়েস্ট না করে থাকেন, এই ইমেইলটি উপেক্ষা করুন।</p>
        </div>
      `,
    }),
  });
  if (!res.ok) {
    const errText = await res.text();
    throw new Error("Resend send failed: " + errText);
  }
}

// TODO: wire up a real SMS gateway (SSL Wireless / BulkSMSBD / Twilio / etc.)
// and replace this stub. Until then, mobile-method OTPs fall back to email
// (see the /api/send-otp handler below).
async function sendOtpSms(env, phone, otp) {
  throw new Error("SMS gateway এখনো সেটআপ হয়নি");
}

// ---------- password hashing (PBKDF2 via Web Crypto, no external deps) ----------
function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuf(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
}

async function hashPassword(password, saltB64) {
  const salt = saltB64 ? base64ToBuf(saltB64) : crypto.getRandomValues(new Uint8Array(16)).buffer;
  const keyMaterial = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, 256
  );
  return { hash: bufToBase64(bits), salt: bufToBase64(salt) };
}

async function verifyPassword(password, storedHash, storedSalt) {
  const { hash } = await hashPassword(password, storedSalt);
  return hash === storedHash;
}

// ---------- admin session tokens (HMAC-signed, no extra storage needed) ----------
async function hmacKey(env) {
  return crypto.subtle.importKey(
    "raw", new TextEncoder().encode(env.ADMIN_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
}

async function signAdminToken(env, admin) {
  const payload = JSON.stringify({ id: admin.id, email: admin.email, exp: Date.now() + 1000 * 60 * 60 * 12 }); // 12h
  const payloadB64 = btoa(payload);
  const key = await hmacKey(env);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64));
  return `${payloadB64}.${bufToBase64(sig)}`;
}

async function verifyAdminToken(env, token) {
  if (!token) return null;
  const [payloadB64, sigB64] = token.split(".");
  if (!payloadB64 || !sigB64) return null;
  const key = await hmacKey(env);
  const expectedSig = bufToBase64(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payloadB64)));
  if (expectedSig !== sigB64) return null;
  try {
    const payload = JSON.parse(atob(payloadB64));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function getBearerToken(request) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}

// ---------- tutor_id auto-generation (e.g. "Rajshahi University" -> RU_1240) ----------
const TUTOR_ID_PREFIX_STOPWORDS = new Set(["of", "the", "and", "a", "an", "for"]);

function universityToPrefix(university) {
  const words = (university || "")
    .trim()
    .split(/\s+/)
    .filter((w) => w && !TUTOR_ID_PREFIX_STOPWORDS.has(w.toLowerCase()));
  const prefix = words.map((w) => w[0].toUpperCase()).join("");
  return prefix || "TU"; // fallback if university is blank/unparseable
}

// Generates the next tutor_id for a given university, e.g. RU_1240, RU_1241, ...
// Uses a small per-prefix counter table so IDs are unique and sequential even
// across many universities. Not perfectly race-proof under heavy concurrent
// approvals, but fine for this scale (D1 has no easy row-level locking).
async function generateTutorId(env, university) {
  const prefix = universityToPrefix(university);

  let counter = await env.DB.prepare(
    `SELECT last_serial FROM tutor_id_counters WHERE prefix = ?`
  ).bind(prefix).first();

  if (!counter) {
    await env.DB.prepare(
      `INSERT INTO tutor_id_counters (prefix, last_serial) VALUES (?, 1239)`
    ).bind(prefix).run();
    counter = { last_serial: 1239 };
  }

  const nextSerial = counter.last_serial + 1;
  await env.DB.prepare(
    `UPDATE tutor_id_counters SET last_serial = ? WHERE prefix = ?`
  ).bind(nextSerial, prefix).run();

  return `${prefix}_${nextSerial}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(env) });
    }

    try {
      // ---------- POST /api/send-otp ----------
      // body: { contact, method: "mobile" | "email", fallbackEmail? }
      if (pathname === "/api/send-otp" && request.method === "POST") {
        const { contact, method, fallbackEmail } = await request.json();

        if (!contact) return json({ error: "তথ্য অসম্পূর্ণ" }, 400, env);
        if (method === "email" && !isEmail(contact)) {
          return json({ error: "সঠিক ইমেইল দিন" }, 400, env);
        }
        if (method === "mobile" && !isPhone(contact)) {
          return json({ error: "সঠিক মোবাইল নম্বর দিন" }, 400, env);
        }

        // Simple rate-limit: 1 OTP per 45s per contact
        const lastSent = await env.OTP_KV.get(`cooldown:${contact}`);
        if (lastSent) {
          return json({ error: "একটু পরে আবার চেষ্টা করুন" }, 429, env);
        }

        const otp = generateOtp();
        let sentTo = contact;

        try {
          if (method === "email") {
            await sendOtpEmail(env, contact, otp);
          } else {
            // mobile: no SMS gateway yet — fall back to fallbackEmail if given
            if (fallbackEmail && isEmail(fallbackEmail)) {
              await sendOtpEmail(env, fallbackEmail, otp);
              sentTo = fallbackEmail;
            } else {
              await sendOtpSms(env, contact, otp); // always throws for now (see TODO)
            }
          }
        } catch (err) {
          return json({
            error: method === "mobile"
              ? "SMS OTP এখনো চালু হয়নি — সাইনআপ ফর্মে একটা ইমেইল যোগ করুন অথবা Email ট্যাব দিয়ে সাইনআপ করুন"
              : "ইমেইল পাঠাতে সমস্যা হয়েছে",
          }, 500, env);
        }

        await env.OTP_KV.put(`otp:${contact}`, otp, { expirationTtl: 300 }); // 5 min
        await env.OTP_KV.put(`cooldown:${contact}`, "1", { expirationTtl: 60 });

        return json({ ok: true, sentTo }, 200, env);
      }

      // ---------- POST /api/verify-otp ----------
      if (pathname === "/api/verify-otp" && request.method === "POST") {
        const { contact, otp } = await request.json();
        if (!contact || !otp) return json({ error: "তথ্য অসম্পূর্ণ" }, 400, env);

        const stored = await env.OTP_KV.get(`otp:${contact}`);
        if (!stored || stored !== otp) {
          return json({ error: "OTP সঠিক নয় বা মেয়াদ শেষ" }, 400, env);
        }

        await env.OTP_KV.delete(`otp:${contact}`);
        await env.OTP_KV.put(`verified:${contact}`, "1", { expirationTtl: 900 }); // 15 min

        return json({ ok: true }, 200, env);
      }

      // ---------- POST /api/register ----------
      // body: { identifier, email, phone, name, role, password, agreedTerms }
      // `identifier` is the contact (email or phone) that just went through OTP verification.
      // Both role="user" and role="tutor" are inserted into users and are active
      // immediately — there is no approval gate on registration anymore, and no
      // ad-request fields are collected here. A tutor fills out the full ad
      // request (profile info + photo + payment proof) later from profile.html
      // via POST /api/ad-request-submit — fully decoupled from signing up.
      if (pathname === "/api/register" && request.method === "POST") {
        const { identifier, email, phone, name, role, password, agreedTerms } = await request.json();

        if (!identifier || !name || !role || !password || !agreedTerms) {
          return json({ error: "সব তথ্য পূরণ করুন এবং শর্তে সম্মত হন" }, 400, env);
        }
        if (role !== "tutor" && role !== "user") {
          return json({ error: "সঠিক role দিন" }, 400, env);
        }
        if (password.length < 6) {
          return json({ error: "পাসওয়ার্ড কমপক্ষে ৬ ক্যারেক্টার হতে হবে" }, 400, env);
        }

        const isVerified = await env.OTP_KV.get(`verified:${identifier}`);
        if (!isVerified) {
          return json({ error: "আগে ভেরিফাই করুন" }, 401, env);
        }

        const dup = await env.DB.prepare(
          `SELECT id FROM users WHERE (email = ? AND email != '') OR (phone = ? AND phone != '')`
        ).bind(email || "", phone || "").first();
        if (dup) {
          return json({ error: "এই অ্যাকাউন্ট আগে থেকেই আছে, লগইন করুন" }, 409, env);
        }

        const { hash, salt } = await hashPassword(password);
        const userId = crypto.randomUUID();
        const now = Date.now();

        await env.DB.prepare(
          `INSERT INTO users (id, name, phone, email, password_hash, password_salt, role, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(userId, name, phone || "", email || "", hash, salt, role, now).run();

        await env.OTP_KV.delete(`verified:${identifier}`);

        return json({
          ok: true,
          user: { id: userId, name, role, email: email || "", phone: phone || "" },
        }, 200, env);
      }

      // ---------- POST /api/login ----------
      // body: { identifier, password } — identifier can be an email or an 01XXXXXXXXX phone number
      if (pathname === "/api/login" && request.method === "POST") {
        const { identifier, password } = await request.json();
        if (!identifier || !password) {
          return json({ error: "সব তথ্য পূরণ করুন" }, 400, env);
        }
        if (!isEmail(identifier) && !isPhone(identifier)) {
          return json({ error: "সঠিক মোবাইল নম্বর অথবা ইমেইল দিন" }, 400, env);
        }

        const column = isPhone(identifier) ? "phone" : "email";
        const user = await env.DB.prepare(`SELECT * FROM users WHERE ${column} = ?`).bind(identifier).first();
        if (!user) {
          return json({ error: "এই তথ্যে কোনো অ্যাকাউন্ট পাওয়া যায়নি" }, 404, env);
        }

        const ok = await verifyPassword(password, user.password_hash, user.password_salt);
        if (!ok) {
          return json({ error: "পাসওয়ার্ড সঠিক নয়" }, 401, env);
        }

        // Tutor login is never blocked by ad-request status. We just attach the
        // latest ad_requests row (if any) so the frontend can show/prefill it
        // ("pending review", "approved — you're listed", "rejected: <note>", ...).
        let adRequest = null;
        if (user.role === "tutor") {
          const reqRow = await env.DB.prepare(
            `SELECT id, status, name, phone, subject, qualification, area, photo_url,
                    pay_sender, pay_trx, pay_amount, note, tutor_id, validity_days, expires_at,
                    created_at
             FROM ad_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`
          ).bind(user.id).first();
          adRequest = reqRow || null;
        }

        return json({
          ok: true,
          user: { id: user.id, name: user.name, role: user.role, email: user.email, phone: user.phone },
          adRequest,
        }, 200, env);
      }

      // ---------- POST /api/ad-request-submit ----------
      // body: { userId, name, phone, subject, qualification, area, photoUrl,
      //         paySender, payTrx, payAmount,
      //         gender, university, department, session, currentLocation,
      //         expectedSalary, experienceYears, subjects,
      //         eduBachelorDept, eduBachelorSession, eduBachelorCurrent,
      //         sscYear, sscSchool, sscGroup, sscResult,
      //         hscYear, hscCollege, hscGroup, hscResult, extraInfo }
      //
      // ONE ad per account, always. A logged-in tutor can (re-)apply any
      // time — even while already 'running' — to correct/update their
      // profile; doing so always sends the ad back to 'pending' for a fresh
      // admin review. There is never more than one ad_requests row per
      // user_id: the first submission INSERTs it, every submission after
      // that UPDATEs the same row in place (tutor_id, once assigned by an
      // approval, is preserved across re-submissions). Blocked only if a
      // submission is already sitting in 'pending' review.
      //
      // photoUrl is a Cloudinary URL the browser already uploaded to
      // directly — the Worker never touches image bytes, just stores the link.
      if (pathname === "/api/ad-request-submit" && request.method === "POST") {
        const body = await request.json();
        const {
          userId, name, phone, subject, qualification, area, photoUrl, paySender, payTrx, payAmount,
          gender, university, department, session, currentLocation,
          expectedSalary, experienceYears, subjects,
          eduBachelorDept, eduBachelorSession, eduBachelorCurrent,
          sscYear, sscSchool, sscGroup, sscResult,
          hscYear, hscCollege, hscGroup, hscResult,
          extraInfo,
        } = body;

        if (!userId || !name || !phone || !subject || !area || !paySender || !payTrx || !payAmount) {
          return json({ error: "সব তথ্য পূরণ করুন" }, 400, env);
        }

        const user = await env.DB.prepare(`SELECT * FROM users WHERE id = ?`).bind(userId).first();
        if (!user) {
          return json({ error: "ইউজার পাওয়া যায়নি" }, 404, env);
        }
        if (user.role !== "tutor") {
          return json({ error: "শুধুমাত্র টিউটর অ্যাকাউন্ট থেকে আবেদন করা যাবে" }, 403, env);
        }

        const existing = await env.DB.prepare(
          `SELECT id, status FROM ad_requests WHERE user_id = ? LIMIT 1`
        ).bind(userId).first();
        if (existing && existing.status === "pending") {
          return json({ error: "আপনার একটি আবেদন ইতিমধ্যে পর্যালোচনাধীন আছে" }, 409, env);
        }

        const now = Date.now();
        const reqId = existing ? existing.id : crypto.randomUUID();

        const fieldValues = [
          name, phone, subject, qualification || "", area, photoUrl || "",
          paySender, payTrx, payAmount,
          gender || "", university || "", department || "", session || "", currentLocation || "",
          expectedSalary || "", experienceYears || "", subjects || "",
          eduBachelorDept || "", eduBachelorSession || "", eduBachelorCurrent ? 1 : 0,
          sscYear || "", sscSchool || "", sscGroup || "", sscResult || "",
          hscYear || "", hscCollege || "", hscGroup || "", hscResult || "",
          extraInfo || "",
        ];

        if (existing) {
          // Re-submission: update the one row this account owns, send it
          // back to 'pending' for review. tutor_id / validity / expiry are
          // deliberately left untouched here — approve() re-sets validity
          // fresh, and tutor_id is never reassigned once given.
          await env.DB.prepare(
            `UPDATE ad_requests SET
               status = 'pending', name = ?, phone = ?, subject = ?, qualification = ?, area = ?, photo_url = ?,
               pay_sender = ?, pay_trx = ?, pay_amount = ?, note = NULL,
               gender = ?, university = ?, department = ?, session = ?, current_location = ?,
               expected_salary = ?, experience_years = ?, subjects = ?,
               edu_bachelor_dept = ?, edu_bachelor_session = ?, edu_bachelor_current = ?,
               ssc_year = ?, ssc_school = ?, ssc_group = ?, ssc_result = ?,
               hsc_year = ?, hsc_college = ?, hsc_group = ?, hsc_result = ?,
               extra_info = ?, updated_at = ?
             WHERE id = ?`
          ).bind(...fieldValues, now, reqId).run();
        } else {
          await env.DB.prepare(
            `INSERT INTO ad_requests
               (id, user_id, status, name, phone, subject, qualification, area, photo_url,
                pay_sender, pay_trx, pay_amount, note,
                gender, university, department, session, current_location,
                expected_salary, experience_years, subjects,
                edu_bachelor_dept, edu_bachelor_session, edu_bachelor_current,
                ssc_year, ssc_school, ssc_group, ssc_result,
                hsc_year, hsc_college, hsc_group, hsc_result,
                extra_info, created_at, updated_at)
             VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(reqId, userId, ...fieldValues, now, now).run();
        }

        return json({
          ok: true,
          adRequest: { id: reqId, status: "pending" },
        }, 200, env);
      }

      // ---------- POST /api/admin-login ----------
      if (pathname === "/api/admin-login" && request.method === "POST") {
        const { email, password } = await request.json();
        if (!email || !password) {
          return json({ error: "সব তথ্য পূরণ করুন" }, 400, env);
        }

        const admin = await env.DB.prepare(`SELECT * FROM admins WHERE email = ?`).bind(email).first();
        if (!admin) {
          return json({ error: "ভুল ইমেইল বা পাসওয়ার্ড" }, 401, env);
        }
        const ok = await verifyPassword(password, admin.password_hash, admin.password_salt);
        if (!ok) {
          return json({ error: "ভুল ইমেইল বা পাসওয়ার্ড" }, 401, env);
        }

        const token = await signAdminToken(env, admin);
        return json({ ok: true, token, admin: { id: admin.id, email: admin.email } }, 200, env);
      }

      // ---------- POST /api/admin/bootstrap ----------
      // One-time setup route to create the FIRST admin account (only works
      // while the admins table is empty). Call it once, e.g.:
      //
      //   curl -X POST https://your-worker.workers.dev/api/admin/bootstrap \
      //     -H "Content-Type: application/json" \
      //     -d '{"email":"admin@example.com","password":"a-strong-password","setupKey":"<value of ADMIN_SETUP_KEY secret>"}'
      //
      // After the first admin exists, this route always returns 409.
      if (pathname === "/api/admin/bootstrap" && request.method === "POST") {
        const { email, password, setupKey } = await request.json();
        if (!env.ADMIN_SETUP_KEY || setupKey !== env.ADMIN_SETUP_KEY) {
          return json({ error: "অনুমতি নেই" }, 403, env);
        }
        const countRow = await env.DB.prepare(`SELECT COUNT(*) as c FROM admins`).first();
        if (countRow && countRow.c > 0) {
          return json({ error: "Admin আগে থেকেই তৈরি করা আছে" }, 409, env);
        }
        if (!email || !isEmail(email) || !password || password.length < 6) {
          return json({ error: "সঠিক ইমেইল ও পাসওয়ার্ড (কমপক্ষে ৬ ক্যারেক্টার) দিন" }, 400, env);
        }

        const { hash, salt } = await hashPassword(password);
        await env.DB.prepare(
          `INSERT INTO admins (id, email, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?)`
        ).bind(crypto.randomUUID(), email, hash, salt, Date.now()).run();

        return json({ ok: true }, 200, env);
      }

      // ---------- GET /api/admin/ad-requests ----------
      if (pathname === "/api/admin/ad-requests" && request.method === "GET") {
        const payload = await verifyAdminToken(env, getBearerToken(request));
        if (!payload) return json({ error: "Admin session মেয়াদোত্তীর্ণ, আবার লগইন করুন" }, 401, env);

        const { results } = await env.DB.prepare(`
          SELECT ar.id AS request_id, ar.status, ar.name, ar.phone, ar.subject, ar.qualification,
                 ar.area, ar.photo_url, ar.pay_sender, ar.pay_trx, ar.pay_amount,
                 ar.note, ar.created_at, ar.updated_at,
                 u.id AS user_id, u.email
          FROM ad_requests ar
          JOIN users u ON u.id = ar.user_id
          WHERE ar.status = 'pending'
          ORDER BY ar.created_at DESC
        `).all();

        return json({ ok: true, requests: results }, 200, env);
      }

      // ---------- POST /api/admin/approve-ad-request ----------
      if (pathname === "/api/admin/approve-ad-request" && request.method === "POST") {
        const payload = await verifyAdminToken(env, getBearerToken(request));
        if (!payload) return json({ error: "Admin session মেয়াদোত্তীর্ণ, আবার লগইন করুন" }, 401, env);

        const { requestId } = await request.json();
        if (!requestId) return json({ error: "requestId প্রয়োজন" }, 400, env);

        await env.DB.prepare(
          `UPDATE ad_requests SET status = 'running', updated_at = ? WHERE id = ?`
        ).bind(Date.now(), requestId).run();

        return json({ ok: true }, 200, env);
      }

      // ---------- POST /api/admin/reject-ad-request ----------
      if (pathname === "/api/admin/reject-ad-request" && request.method === "POST") {
        const payload = await verifyAdminToken(env, getBearerToken(request));
        if (!payload) return json({ error: "Admin session মেয়াদোত্তীর্ণ, আবার লগইন করুন" }, 401, env);

        const { requestId, note } = await request.json();
        if (!requestId) return json({ error: "requestId প্রয়োজন" }, 400, env);

        await env.DB.prepare(
          `UPDATE ad_requests SET status = 'rejected', note = ?, updated_at = ? WHERE id = ?`
        ).bind(note || "", Date.now(), requestId).run();

        return json({ ok: true }, 200, env);
      }

      // ---------- GET /api/tutors (public) ----------
      if (pathname === "/api/tutors" && request.method === "GET") {
        const { results } = await env.DB.prepare(`
          SELECT ar.name, ar.phone, ar.subject, ar.qualification, ar.area, ar.photo_url,
                 u.id, u.email
          FROM ad_requests ar
          JOIN users u ON u.id = ar.user_id
          WHERE ar.status = 'running'
          ORDER BY ar.updated_at DESC
        `).all();

        return json({ ok: true, tutors: results }, 200, env);
      }

      // ================= Admin dashboard (admin-panel.html) =================

      // ---------- GET /api/admin/dashboard-stats ----------
      if (pathname === "/api/admin/dashboard-stats" && request.method === "GET") {
        const payload = await verifyAdminToken(env, getBearerToken(request));
        if (!payload) return json({ error: "Admin session মেয়াদোত্তীর্ণ, আবার লগইন করুন" }, 401, env);

        const { results } = await env.DB.prepare(
          `SELECT status, COUNT(*) as c FROM ad_requests GROUP BY status`
        ).all();

        const stats = { total: 0, pending: 0, running: 0, paused: 0, cancelled: 0, rejected: 0 };
        for (const row of results) {
          if (row.status in stats) stats[row.status] = row.c;
          stats.total += row.c;
        }

        return json({ ok: true, stats }, 200, env);
      }

      // ---------- GET /api/admin/ads?status=pending|running|paused|rejected|cancelled ----------
      // status can be a comma-separated list, e.g. status=rejected,cancelled
      if (pathname === "/api/admin/ads" && request.method === "GET") {
        const payload = await verifyAdminToken(env, getBearerToken(request));
        if (!payload) return json({ error: "Admin session মেয়াদোত্তীর্ণ, আবার লগইন করুন" }, 401, env);

        const statusParam = url.searchParams.get("status") || "";
        const statuses = statusParam.split(",").map((s) => s.trim()).filter(Boolean);
        const validStatuses = ["pending", "running", "paused", "rejected", "cancelled"];
        const filtered = statuses.filter((s) => validStatuses.includes(s));
        if (filtered.length === 0) {
          return json({ error: "সঠিক status দিন" }, 400, env);
        }

        const placeholders = filtered.map(() => "?").join(",");
        const { results } = await env.DB.prepare(`
          SELECT ar.id, ar.name, ar.phone, u.email AS email, ar.subject, ar.qualification,
                 ar.area, ar.status, ar.created_at,
                 ar.tutor_id AS tutorId, ar.validity_days AS validityDays,
                 ar.expires_at AS expiresAt, ar.auto_expired AS autoExpired
          FROM ad_requests ar
          JOIN users u ON u.id = ar.user_id
          WHERE ar.status IN (${placeholders})
          ORDER BY ar.created_at DESC
        `).bind(...filtered).all();

        return json({ ok: true, ads: results }, 200, env);
      }

      // ---------- POST /api/admin/ads/:id/<action> ----------
      // action: approve | reject | pause | resume | delete | update
      const adsActionMatch = pathname.match(/^\/api\/admin\/ads\/([^/]+)\/(approve|reject|pause|resume|delete|update|availability)$/);
      if (adsActionMatch && request.method === "POST") {
        const payload = await verifyAdminToken(env, getBearerToken(request));
        if (!payload) return json({ error: "Admin session মেয়াদোত্তীর্ণ, আবার লগইন করুন" }, 401, env);

        const [, adId, action] = adsActionMatch;

        const existing = await env.DB.prepare(`SELECT id, university, tutor_id FROM ad_requests WHERE id = ?`).bind(adId).first();
        if (!existing) return json({ error: "এই বিজ্ঞাপন পাওয়া যায়নি" }, 404, env);

        const now = Date.now();

        if (action === "approve") {
          // Admin sets the validity period (in days) at approval time — this
          // is required every time an ad is approved (fresh approval or
          // re-approval after edits), since it decides when the scheduled
          // worker will auto-pause it.
          const body = await request.json().catch(() => ({}));
          const validityDays = parseInt(body.validityDays, 10);
          if (!validityDays || validityDays <= 0) {
            return json({ error: "মেয়াদ (validityDays) একটা পজিটিভ সংখ্যা হিসেবে দিতে হবে" }, 400, env);
          }

          // Auto-generate tutor_id the first time this ad is approved (never
          // overwrites an existing tutor_id on re-approval).
          let tutorId = existing.tutor_id;
          if (!tutorId) {
            tutorId = await generateTutorId(env, existing.university);
          }

          const expiresAt = now + validityDays * 24 * 60 * 60 * 1000;
          await env.DB.prepare(
            `UPDATE ad_requests
             SET status = 'running', tutor_id = ?, validity_days = ?, expires_at = ?, auto_expired = 0, updated_at = ?
             WHERE id = ?`
          ).bind(tutorId, validityDays, expiresAt, now, adId).run();
          return json({ ok: true, tutorId, expiresAt }, 200, env);
        }

        if (action === "reject") {
          const body = await request.json().catch(() => ({}));
          await env.DB.prepare(
            `UPDATE ad_requests SET status = 'rejected', note = ?, updated_at = ? WHERE id = ?`
          ).bind(body.note || "", now, adId).run();
          return json({ ok: true }, 200, env);
        }

        if (action === "pause") {
          await env.DB.prepare(`UPDATE ad_requests SET status = 'paused', updated_at = ? WHERE id = ?`).bind(now, adId).run();
          return json({ ok: true }, 200, env);
        }

        if (action === "resume") {
          // Manually resuming a paused ad (whether the admin paused it, or
          // the scheduled worker auto-paused it for being expired) clears
          // the auto_expired flag. If the admin includes a fresh
          // validityDays, the expiry clock restarts from now; otherwise the
          // existing expires_at is left as-is (admin's call — e.g. resuming
          // briefly without extending).
          const body = await request.json().catch(() => ({}));
          const validityDays = parseInt(body.validityDays, 10);

          if (validityDays && validityDays > 0) {
            const expiresAt = now + validityDays * 24 * 60 * 60 * 1000;
            await env.DB.prepare(
              `UPDATE ad_requests SET status = 'running', validity_days = ?, expires_at = ?, auto_expired = 0, updated_at = ? WHERE id = ?`
            ).bind(validityDays, expiresAt, now, adId).run();
            return json({ ok: true, expiresAt }, 200, env);
          }

          await env.DB.prepare(
            `UPDATE ad_requests SET status = 'running', auto_expired = 0, updated_at = ? WHERE id = ?`
          ).bind(now, adId).run();
          return json({ ok: true }, 200, env);
        }

        if (action === "delete") {
          await env.DB.prepare(`DELETE FROM ad_requests WHERE id = ?`).bind(adId).run();
          return json({ ok: true }, 200, env);
        }

        if (action === "update") {
          const body = await request.json().catch(() => ({}));
          const {
            name, phone, subject, qualification, area,
            gender, university, department, session, currentLocation,
            expectedSalary, experienceYears, subjects,
            eduBachelorDept, eduBachelorSession, eduBachelorCurrent,
            sscYear, sscSchool, sscGroup, sscResult,
            hscYear, hscCollege, hscGroup, hscResult,
            extraInfo,
          } = body;
          if (!name || !phone) {
            return json({ error: "নাম ও ফোন নম্বর আবশ্যক" }, 400, env);
          }
          await env.DB.prepare(
            `UPDATE ad_requests SET
               name = ?, phone = ?, subject = ?, qualification = ?, area = ?,
               gender = ?, university = ?, department = ?, session = ?, current_location = ?,
               expected_salary = ?, experience_years = ?, subjects = ?,
               edu_bachelor_dept = ?, edu_bachelor_session = ?, edu_bachelor_current = ?,
               ssc_year = ?, ssc_school = ?, ssc_group = ?, ssc_result = ?,
               hsc_year = ?, hsc_college = ?, hsc_group = ?, hsc_result = ?,
               extra_info = ?, updated_at = ?
             WHERE id = ?`
          ).bind(
            name, phone, subject || "", qualification || "", area || "",
            gender || "", university || "", department || "", session || "", currentLocation || "",
            expectedSalary || "", experienceYears || "", subjects || "",
            eduBachelorDept || "", eduBachelorSession || "", eduBachelorCurrent ? 1 : 0,
            sscYear || "", sscSchool || "", sscGroup || "", sscResult || "",
            hscYear || "", hscCollege || "", hscGroup || "", hscResult || "",
            extraInfo || "", now,
            adId
          ).run();
          return json({ ok: true }, 200, env);
        }

        if (action === "availability") {
          const body = await request.json().catch(() => ({}));
          const { availability } = body;
          if (availability !== "available" && availability !== "busy") {
            return json({ error: "availability এর মান 'available' অথবা 'busy' হতে হবে" }, 400, env);
          }
          await env.DB.prepare(
            `UPDATE ad_requests SET availability = ?, updated_at = ? WHERE id = ?`
          ).bind(availability, now, adId).run();
          return json({ ok: true }, 200, env);
        }
      }

      // ================= Public tutor listing (hire-tutor.html) =================

      // ---------- GET /api/public/tutors ----------
      // No auth. Only 'running' ads. Excludes phone/email for privacy.
      // Returns just enough for the hire-tutor.html cards; full detail lives
      // behind GET /api/public/tutors/:id.
      if (pathname === "/api/public/tutors" && request.method === "GET") {
        const { results } = await env.DB.prepare(`
          SELECT id, name, photo_url AS avatarUrl, subject, qualification, area,
                 university, department, session, gender, tutor_id AS tutorId,
                 current_location AS currentLocation, availability, subjects
          FROM ad_requests
          WHERE status = 'running'
          ORDER BY updated_at DESC
        `).all();

        return json({ ok: true, tutors: results }, 200, env);
      }

      // ---------- GET /api/public/tutors/:id ----------
      // No auth. Only 'running' ads. Excludes phone/email/payment info — full
      // profile fields for tutor-profile.html's detail page + tabs.
      const publicTutorDetailMatch = pathname.match(/^\/api\/public\/tutors\/([^/]+)$/);
      if (publicTutorDetailMatch && request.method === "GET") {
        const [, tId] = publicTutorDetailMatch;

        const tutor = await env.DB.prepare(`
          SELECT id, name, photo_url AS avatarUrl, subject, qualification, area,
                 gender, university, department, session, tutor_id AS tutorId,
                 current_location AS currentLocation, expected_salary AS expectedSalary,
                 experience_years AS experienceYears, availability, subjects,
                 edu_bachelor_dept AS eduBachelorDept, edu_bachelor_session AS eduBachelorSession,
                 edu_bachelor_current AS eduBachelorCurrent,
                 ssc_year AS sscYear, ssc_school AS sscSchool, ssc_group AS sscGroup, ssc_result AS sscResult,
                 hsc_year AS hscYear, hsc_college AS hscCollege, hsc_group AS hscGroup, hsc_result AS hscResult,
                 extra_info AS extraInfo
          FROM ad_requests
          WHERE id = ? AND status = 'running'
        `).bind(tId).first();

        if (!tutor) {
          return json({ error: "টিউটর প্রোফাইল পাওয়া যায়নি" }, 404, env);
        }

        return json({ ok: true, tutor }, 200, env);
      }

      return json({ error: "Not found" }, 404, env);
    } catch (err) {
      return json({ error: "সার্ভারে সমস্যা হয়েছে: " + err.message }, 500, env);
    }
  },

  // ---------- Scheduled: auto-pause ads past their validity (expires_at) ----------
  // Wire this up with a Cron Trigger in wrangler.toml, e.g. run hourly:
  //   [triggers]
  //   crons = ["0 * * * *"]
  //
  // We deliberately PAUSE (not delete) expired ads and set auto_expired = 1,
  // so the admin panel can show a clear "মেয়াদ শেষ — ডিলিট প্রয়োজন" flag and
  // the admin makes the final call on deleting it (via the existing
  // POST /api/admin/ads/:id/delete route) or extending it (via /resume with
  // a fresh validityDays).
  async scheduled(event, env, ctx) {
    const now = Date.now();
    await env.DB.prepare(
      `UPDATE ad_requests
       SET status = 'paused', auto_expired = 1, updated_at = ?
       WHERE status = 'running' AND expires_at IS NOT NULL AND expires_at < ?`
    ).bind(now, now).run();
  },
};
