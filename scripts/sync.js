/**
 * Sports events sync — Priofy API → events.json
 *
 * API তে ঢুকতে অ্যাপের মতোই সাইন করা হেডার লাগে:
 *   x-timestamp : বর্তমান সময় (milliseconds)
 *   x-signature : Base64( HMAC-SHA256(timestamp, SECRET) )
 *
 * রেসপন্সের ফিল্ডগুলো AES-128-CBC দিয়ে এনক্রিপ্টেড থাকে (enc: true),
 * সেগুলো ডিক্রিপ্ট করে আগের events.json এর হুবহু একই ফরম্যাটে সেভ হয়।
 */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ── Config (GitHub Secrets / env দিয়ে বদলানো যায়, না দিলে ডিফল্ট) ──────────────
const API_URL = process.env.API_URL || "https://priofyapi.shopnilofficial47.workers.dev/";
const HMAC_SECRET = process.env.HMAC_SECRET || "PriofySecure2026_LiveApp";
const AES_KEY = process.env.AES_KEY || "PriofySecure2026"; // 16 bytes
const AES_IV = process.env.AES_IV || "PriofyAppIV_2026"; // 16 bytes

const USER_AGENT =
  "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36";

const OUTPUT_FILE = path.join(__dirname, "..", "events.json");
const MAX_RETRIES = 3;

// ── Crypto helpers ────────────────────────────────────────────────────────────
function sign(timestamp) {
  return crypto.createHmac("sha256", HMAC_SECRET).update(timestamp).digest("base64");
}

/** AES-128-CBC ডিক্রিপ্ট; ব্যর্থ হলে null */
function aesDecrypt(str) {
  try {
    const decipher = crypto.createDecipheriv(
      "aes-128-cbc",
      Buffer.from(AES_KEY, "utf8"),
      Buffer.from(AES_IV, "utf8")
    );
    return Buffer.concat([
      decipher.update(Buffer.from(str, "base64")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return null;
  }
}

/** AES → না হলে সাধারণ Base64 (valid হলে) → না হলে যেমন আছে তেমনই */
function dec(str) {
  if (!str || typeof str !== "string") return "";
  const viaAes = aesDecrypt(str);
  if (viaAes !== null) return viaAes;
  // Base64 কিনা যাচাই করে তবেই decode, নাহলে plain text হিসেবে ফেরত দাও
  const looksBase64 = /^[A-Za-z0-9+/]+=*$/.test(str.trim()) && str.length % 4 === 0;
  if (looksBase64) {
    try {
      return Buffer.from(str, "base64").toString("utf8");
    } catch {
      return str;
    }
  }
  return str;
}

/**
 * DRM: events.json এ আগে drm ছিল Base64 ফরম্যাটে ("kid:key" এর Base64)।
 * ডিক্রিপ্ট করার পর যদি plain "kid:key" বা লাইসেন্স URL আসে, তাহলে আবার
 * Base64 করে দেই যাতে ফরম্যাট আগের মতোই থাকে।
 */
function normalizeDrm(value) {
  if (!value) return "";
  const plain = dec(value);
  if (!plain) return "";
  const looksBase64 = /^[A-Za-z0-9+/]+={0,2}$/.test(plain) && plain.length % 4 === 0;
  if (looksBase64 && !plain.includes(":")) return plain; // ইতিমধ্যে Base64
  return Buffer.from(plain, "utf8").toString("base64");
}

/**
 * URL থেকে DRM অংশ কেটে বের করে আনা (নতুন যোগ করা হয়েছে)
 */
function extractDrm(streamUrl) {
  if (!streamUrl) return { cleanUrl: "", drmKey: "" };
  if (streamUrl.includes("drmLicense=")) {
    let parts = streamUrl.split("drmLicense=");
    let cleanUrl = parts[0].split("?")[0]; 
    let drmKey = parts[1].split("&")[0].trim(); 
    return { cleanUrl, drmKey };
  }
  return { cleanUrl: streamUrl, drmKey: "" };
}

// ── Event decoding ────────────────────────────────────────────────────────────
function decodeEncrypted(id, raw) {
  const streams = Array.isArray(raw.s)
    ? raw.s
        .filter((s) => s && typeof s === "object")
        .map((s) => {
          const rawUrl = dec(s.u);
          const { cleanUrl, drmKey } = extractDrm(rawUrl); // 💡 DRM আলাদা করা
          return {
            name: dec(s.n),
            url: cleanUrl,
            referer: dec(s.ref),
            userAgent: dec(s.ua),
            drm: drmKey || normalizeDrm(s.drm),
          };
        })
    : [];

  return {
    id,
    date: raw.d || "",
    time: raw.t || "",
    league: dec(raw.l),
    team1: dec(raw.t1),
    team2: dec(raw.t2),
    logo1: dec(raw.lg1),
    logo2: dec(raw.lg2),
    leagueLogo: dec(raw.llg),
    isHot: raw.is_hot || false,
    visibility: raw.visibility || "",
    streams,
  };
}

/** enc নেই এমন প্লেইন ফরম্যাট (অ্যাপও এটা সাপোর্ট করে) */
function decodePlain(id, raw) {
  const list = Array.isArray(raw.link_live)
    ? raw.link_live
    : Array.isArray(raw.buttons)
    ? raw.buttons
    : [];
  const streams = list
    .filter((s) => s && typeof s === "object")
    .map((s, i) => {
      const rawUrl = s.stream_link || s.videoURL || s.url || "";
      const { cleanUrl, drmKey } = extractDrm(rawUrl); // 💡 DRM আলাদা করা
      return {
        name: s.display_name || s.name || `Server ${i + 1}`,
        url: cleanUrl,
        referer: s.referer || raw.referer || s.headers?.Referer || "",
        userAgent: s.userAgent || s.user_agent || s.headers?.["User-Agent"] || "",
        drm: drmKey || (s.drmLicenseUrl ? Buffer.from(s.drmLicenseUrl, "utf8").toString("base64") : ""),
      };
    });

  return {
    id,
    date: raw.d || raw.matchDate || "",
    time: raw.t || raw.matchTime || "",
    league: raw.league_name || raw.league || "",
    team1: raw.localteam_name || raw.team1 || "",
    team2: raw.visitorteam_name || raw.team2 || "",
    logo1: raw.localteam_logo || raw.logo1 || "",
    logo2: raw.visitorteam_logo || raw.logo2 || "",
    leagueLogo: raw.league_logo || raw.leagueLogo || "",
    isHot: raw.is_hot || false,
    visibility: raw.visibility || "",
    streams,
  };
}

function decodeEvent(id, raw) {
  return raw.enc === true ? decodeEncrypted(id, raw) : decodePlain(id, raw);
}

// ── Fetch ─────────────────────────────────────────────────────────────────────
async function fetchOnce() {
  const timestamp = String(Date.now());
  const res = await fetch(API_URL, {
    method: "GET",
    headers: {
      "x-timestamp": timestamp,
      "x-signature": sign(timestamp),
      "User-Agent": USER_AGENT,
      Accept: "application/json",
    },
    signal: AbortSignal.timeout(20000),
  });

  const text = await res.text();
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
  if (text.includes("Access Denied")) throw new Error(`API: ${text.slice(0, 200)}`);

  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error("JSON parse failed: " + e.message);
  }
}

async function fetchData() {
  let lastErr;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await fetchOnce();
    } catch (err) {
      lastErr = err;
      console.warn(`⚠️  Attempt ${attempt}/${MAX_RETRIES} failed: ${err.message}`);
      if (attempt < MAX_RETRIES) await new Promise((r) => setTimeout(r, 2000 * attempt));
    }
  }
  throw lastErr;
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  console.log(`[${new Date().toISOString()}] Fetching from API...`);

  const raw = await fetchData();
  if (!raw || typeof raw !== "object") throw new Error("Invalid response from API");

  const entries = Array.isArray(raw)
    ? raw.map((e, i) => [String(e?.id ?? i), e])
    : Object.entries(raw);

  const events = entries
    .filter(([, e]) => e && typeof e === "object")
    .map(([id, e]) => decodeEvent(id, e));

  if (events.length === 0) {
    throw new Error("API returned 0 events — পুরনো events.json অক্ষত রাখা হলো");
  }

  const now = new Date();

  // 💡 স্ট্রিম থাকলে status 'LIVE' হবে
  events.forEach((ev) => {
    if (ev.streams && ev.streams.length > 0) {
      ev.status = "LIVE";
    } else {
      const evDate = new Date(`${ev.date} ${ev.time}`);
      ev.status = evDate > now ? "UPCOMING" : "ENDED";
    }
  });

  // 💡 নতুন সর্টিং লজিক: LIVE ম্যাচ আগে, তারপর টাইম অনুযায়ী
  events.sort((a, b) => {
    const aLive = a.streams && a.streams.length > 0 ? 1 : 0;
    const bLive = b.streams && b.streams.length > 0 ? 1 : 0;
    
    if (aLive !== bLive) {
      return bLive - aLive; // যার স্ট্রিম আছে (1) সে আগে যাবে
    }
    return new Date(`${a.date} ${a.time}`) - new Date(`${b.date} ${b.time}`);
  });

  // Bangladesh Standard Time = UTC+6
  const bst = new Date(now.getTime() + 6 * 60 * 60 * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  const months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  const h24 = bst.getUTCHours();
  const h12 = h24 % 12 === 0 ? 12 : h24 % 12;
  const readable =
    `${pad(bst.getUTCDate())} ${months[bst.getUTCMonth()]} ${bst.getUTCFullYear()}, ` +
    `${pad(h12)}:${pad(bst.getUTCMinutes())}:${pad(bst.getUTCSeconds())} ${h24 < 12 ? "AM" : "PM"} BST`;

  // 💡 মোট ম্যাচ এবং লাইভ ম্যাচের কাউন্ট
  const totalCount = events.length;
  const liveCount = events.filter((ev) => ev.streams && ev.streams.length > 0).length;

  const output = {
    last_updated: readable,
    last_updated_iso: now.toISOString(),
    total_events: totalCount,
    live_match: liveCount,
    events,
  };

  fs.writeFileSync(OUTPUT_FILE, JSON.stringify(output, null, 2), "utf8");
  console.log(`[${now.toISOString()}] ✅ Saved ${totalCount} events (${liveCount} LIVE) → last_updated: ${readable}`);
}

main().catch((err) => {
  console.error("❌ Error:", err.message);
  process.exit(1);
});
