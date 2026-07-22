/**
 * Kushtia Smart Tutor — Auth + Tutor-Approval Worker
 *
 * Handles: OTP send/verify (email works today, mobile is a TODO stub, same
 * as before), password-based register + login backed by D1, and the tutor
 * approval workflow (admin login, list/approve/reject tutor requests,
 * public approved-tutors listing).
 *
 * Bindings needed (set in wrangler.toml / Cloudflare dashboard):
 *   - KV Namespace: OTP_KV          (OTP codes + "verified:<contact>" flags — unchanged)
 *   - D1 Database:  DB              (users / tutor_requests / admins — see schema.sql)
 *   - Secret:       RESEND_API_KEY  (from resend.com, free plan)
 *   - Secret:       ADMIN_SECRET    (random long string — signs admin session tokens)
 *   - Secret:       ADMIN_SETUP_KEY (random string — protects the one-time admin bootstrap route)
 *   - Var:          ALLOWED_ORIGIN  (e.g. "https://your-site.com" — for CORS)
 *   - Var:          RESEND_FROM     (verified sender, e.g. "Kushtia Smart Tutor <noreply@yourdomain.com>")
 *
 * Endpoints:
 *   POST /api/send-otp          { contact, method, fallbackEmail? }   method: "mobile" | "email"
 *   POST /api/verify-otp        { contact, otp }
 *   POST /api/register          { identifier, email, phone, name, role, password, agreedTerms, subject?, qualification?, area? }
 *   POST /api/login             { identifier, password }
 *   POST /api/admin-login       { email, password }
 *   POST /api/admin/bootstrap   { email, password, setupKey }   -- one-time, creates the first admin
 *   GET  /api/admin/requests    (Authorization: Bearer <admin token>)
 *   POST /api/admin/approve     { requestId }                  (Authorization: Bearer <admin token>)
 *   POST /api/admin/reject      { requestId, note }             (Authorization: Bearer <admin token>)
 *   GET  /api/tutors            (public — approved tutors only)
 *
 * NOTE — SMS OTP: there is no SMS gateway wired up yet. When method is
 * "mobile", sendOtp() falls back to emailing the code to `fallbackEmail` if
 * the user supplied one during signup. Swap in a real SMS provider inside
 * sendOtpSms() below once you pick one.
 */

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
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
        await env.OTP_KV.put(`cooldown:${contact}`, "1", { expirationTtl: 45 });

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
      // body: { identifier, email, phone, name, role, password, agreedTerms, subject?, qualification?, area? }
      // `identifier` is the contact (email or phone) that just went through OTP verification.
      // role="user"  -> inserted into users and considered active immediately.
      // role="tutor" -> inserted into users + a pending row in tutor_requests; not
      //                 allowed to log in until an admin approves the request.
      if (pathname === "/api/register" && request.method === "POST") {
        const { identifier, email, phone, name, role, password, agreedTerms, subject, qualification, area } = await request.json();

        if (!identifier || !name || !role || !password || !agreedTerms) {
          return json({ error: "সব তথ্য পূরণ করুন এবং শর্তে সম্মত হন" }, 400, env);
        }
        if (role !== "tutor" && role !== "user") {
          return json({ error: "সঠিক role দিন" }, 400, env);
        }
        if (password.length < 6) {
          return json({ error: "পাসওয়ার্ড কমপক্ষে ৬ ক্যারেক্টার হতে হবে" }, 400, env);
        }
        if (role === "tutor" && (!subject || !area)) {
          return json({ error: "সাবজেক্ট এবং এলাকা দিন" }, 400, env);
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

        if (role === "tutor") {
          await env.DB.prepare(
            `INSERT INTO tutor_requests (id, user_id, status, subject, qualification, area, admin_note, created_at, updated_at)
             VALUES (?, ?, 'pending', ?, ?, ?, NULL, ?, ?)`
          ).bind(crypto.randomUUID(), userId, subject || "", qualification || "", area || "", now, now).run();

          await env.OTP_KV.delete(`verified:${identifier}`);

          return json({
            ok: true,
            pending: true,
            message: "আপনার আবেদন Admin রিভিউ করছেন, অনুমোদন হলে জানানো হবে",
          }, 200, env);
        }

        await env.OTP_KV.delete(`verified:${identifier}`);

        return json({
          ok: true,
          pending: false,
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

        if (user.role === "tutor") {
          const reqRow = await env.DB.prepare(
            `SELECT * FROM tutor_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`
          ).bind(user.id).first();

          if (reqRow && reqRow.status === "pending") {
            return json({ error: "আপনার আবেদনটি এখনো রিভিউ হয়নি, অনুমোদনের অপেক্ষায় আছে" }, 403, env);
          }
          if (reqRow && reqRow.status === "rejected") {
            return json({
              error: reqRow.admin_note
                ? `আপনার আবেদনটি গ্রহণ করা হয়নি: ${reqRow.admin_note}`
                : "আপনার আবেদনটি গ্রহণ করা হয়নি",
            }, 403, env);
          }
        }

        return json({
          ok: true,
          user: { id: user.id, name: user.name, role: user.role, email: user.email, phone: user.phone },
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

      // ---------- GET /api/admin/requests ----------
      if (pathname === "/api/admin/requests" && request.method === "GET") {
        const payload = await verifyAdminToken(env, getBearerToken(request));
        if (!payload) return json({ error: "Admin session মেয়াদোত্তীর্ণ, আবার লগইন করুন" }, 401, env);

        const { results } = await env.DB.prepare(`
          SELECT tr.id AS request_id, tr.status, tr.subject, tr.qualification, tr.area,
                 tr.admin_note, tr.created_at, tr.updated_at,
                 u.id AS user_id, u.name, u.phone, u.email
          FROM tutor_requests tr
          JOIN users u ON u.id = tr.user_id
          WHERE tr.status = 'pending'
          ORDER BY tr.created_at DESC
        `).all();

        return json({ ok: true, requests: results }, 200, env);
      }

      // ---------- POST /api/admin/approve ----------
      if (pathname === "/api/admin/approve" && request.method === "POST") {
        const payload = await verifyAdminToken(env, getBearerToken(request));
        if (!payload) return json({ error: "Admin session মেয়াদোত্তীর্ণ, আবার লগইন করুন" }, 401, env);

        const { requestId } = await request.json();
        if (!requestId) return json({ error: "requestId প্রয়োজন" }, 400, env);

        await env.DB.prepare(
          `UPDATE tutor_requests SET status = 'approved', updated_at = ? WHERE id = ?`
        ).bind(Date.now(), requestId).run();

        return json({ ok: true }, 200, env);
      }

      // ---------- POST /api/admin/reject ----------
      if (pathname === "/api/admin/reject" && request.method === "POST") {
        const payload = await verifyAdminToken(env, getBearerToken(request));
        if (!payload) return json({ error: "Admin session মেয়াদোত্তীর্ণ, আবার লগইন করুন" }, 401, env);

        const { requestId, note } = await request.json();
        if (!requestId) return json({ error: "requestId প্রয়োজন" }, 400, env);

        await env.DB.prepare(
          `UPDATE tutor_requests SET status = 'rejected', admin_note = ?, updated_at = ? WHERE id = ?`
        ).bind(note || "", Date.now(), requestId).run();

        return json({ ok: true }, 200, env);
      }

      // ---------- GET /api/tutors (public) ----------
      if (pathname === "/api/tutors" && request.method === "GET") {
        const { results } = await env.DB.prepare(`
          SELECT u.id, u.name, u.phone, u.email,
                 tr.subject, tr.qualification, tr.area
          FROM tutor_requests tr
          JOIN users u ON u.id = tr.user_id
          WHERE tr.status = 'approved'
          ORDER BY tr.updated_at DESC
        `).all();

        return json({ ok: true, tutors: results }, 200, env);
      }

      return json({ error: "Not found" }, 404, env);
    } catch (err) {
      return json({ error: "সার্ভারে সমস্যা হয়েছে: " + err.message }, 500, env);
    }
  },
};
