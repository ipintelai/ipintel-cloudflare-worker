// =====================
// CONFIG
// =====================
const CHALLENGE_THRESHOLD = 20;
const BLOCK_THRESHOLD     = 80;
const VERIFY_TTL          = 300;   // seconds
const CACHE_TTL           = 7200;  // seconds
const DEFAULT_THEME       = "light";   //theme dark or light

// =====================
// FETCH WITH TIMEOUT
// =====================
async function fetchWithTimeout(url, options = {}, timeoutMs = 1500) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } finally {
    clearTimeout(id);
  }
}




export default {
  async fetch(request, env, ctx) {

    const url = new URL(request.url);
// =====================
// REAL USER PAGE NAVIGATION ONLY
// =====================
if (request.method !== "GET") {
  return fetch(request);
}

const accept = request.headers.get("Accept") || "";
const secMode = request.headers.get("Sec-Fetch-Mode") || "";
const secDest = request.headers.get("Sec-Fetch-Dest") || "";

if (
  !accept.includes("text/html") ||
  secMode !== "navigate" ||
  secDest !== "document"
) {
  return fetch(request);
}

    // =====================
    // GET CLIENT IP (EARLY)
    // =====================
    const ip = request.headers.get("CF-Connecting-IP");
    if (!ip) return fetch(request);

    // =====================
    // HANDLE VERIFY RETURN (SIGNED PROOF)
    // =====================
    if (url.searchParams.has("ipintel_verified")) {
      const proof = url.searchParams.get("ipintel_verified");
    
          // STRICT FORMAT GUARD
          if (!proof.includes(".")) {
          const clean = new URL(url.href);
          clean.searchParams.delete("ipintel_verified");
          return Response.redirect(clean.toString(), 302);
          }
      try {
        const [payloadB64, sigB64] = proof.split(".");
        if (!payloadB64 || !sigB64) throw new Error("bad_format");
    
        const payload = atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"));
        const [ipFromProof, expStr] = payload.split("|");
    
        const exp = Number(expStr);
        const now = Math.floor(Date.now() / 1000);
    
        if (ipFromProof !== ip) throw new Error("ip_mismatch");
        if (!exp || now > exp) throw new Error("expired");
    
        const enc = new TextEncoder();
        const key = await crypto.subtle.importKey(
          "raw",
          enc.encode(env.IPINTEL_API_KEY),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["verify"]
        );
    
        const expectedSig = Uint8Array.from(
          atob(sigB64.replace(/-/g, "+").replace(/_/g, "/")),
          c => c.charCodeAt(0)
        );
    
        const ok = await crypto.subtle.verify(
          "HMAC",
          key,
          expectedSig,
          enc.encode(payload)
        );
    
        if (!ok) throw new Error("bad_signature");
    
        // SUCCESS
        const clean = new URL(url.href);
        clean.searchParams.delete("ipintel_verified");
    
        return new Response(null, {
          status: 302,
          headers: {
            "Set-Cookie": `ipintel_verified=1; Max-Age=${VERIFY_TTL}; Path=/; SameSite=Lax`,
            "Location": clean.toString(),
            "X-IPIntel-Action": "verify",
            "X-IPIntel-Risk": "0"
          }
        });
    
      } catch {
        const clean = new URL(url.href);
        clean.searchParams.delete("ipintel_verified");
      
        request = new Request(clean.toString(), request);
        url = clean;  
      }
      
    }
    
    // =====================
    // HARD EXCLUSIONS
    // =====================
    if (
      url.pathname.endsWith(".css") ||
      url.pathname.endsWith(".js") ||
      url.pathname.endsWith(".png") ||
      url.pathname.endsWith(".jpg") ||
      url.pathname.endsWith(".jpeg") ||
      url.pathname.endsWith(".gif") ||
      url.pathname.endsWith(".svg") ||
      url.pathname.endsWith(".woff") ||
      url.pathname.endsWith(".woff2") ||
      url.pathname.endsWith(".ttf") ||
      url.pathname === "/robots.txt" ||
      url.pathname === "/sitemap.xml"
    ) {
      return fetch(request);
    }

    // =====================
    // CHECK COOKIE
    // =====================
    const cookieHeader = request.headers.get("Cookie") || "";
    const isVerified = cookieHeader.includes("ipintel_verified=1");

    // =====================
    // RISK CACHE
    // =====================
    const cache = caches.default;
    const cacheKey = new Request(`https://cache.ipintel.ai/risk/${ip}`);
    let riskScore = null;

    const cached = await cache.match(cacheKey);
    if (cached) {
      const data = await cached.json();
      riskScore = Number(data.risk);
    }

    // =====================
    // API LOOKUP
    // =====================
    if (riskScore === null) {
      let r;
      try {
        r = await fetchWithTimeout(
          `https://api.ipintel.ai/ip/${ip}?api_key=${env.IPINTEL_API_KEY}`,
          { cf: { cacheTtl: 0 } },
          1200
        );
      } catch {
        return fetch(request); // FAIL OPEN
      }

      if (!r || !r.ok) return fetch(request);

      const data = await r.json();
      riskScore = Number(data.risk_score) || 0;

      ctx.waitUntil(
        cache.put(
          cacheKey,
          new Response(JSON.stringify({ risk: riskScore }), {
            headers: { "Cache-Control": `public, max-age=${CACHE_TTL}` }
          })
        )
      );
    }

    if (riskScore === null) return fetch(request);

    // =====================
    // HARD BLOCK
    // =====================
    if (riskScore >= BLOCK_THRESHOLD) {
      return new Response("Blocked by IPIntel", {
        status: 403,
        headers: {
          "X-IPIntel-Action": "block",
          "X-IPIntel-Risk": String(riskScore)
        }
      });
    }

// =====================
// STRICT CHALLENGE
// =====================
if (riskScore >= CHALLENGE_THRESHOLD && !isVerified) {

  const theme = env.IPINTEL_THEME || DEFAULT_THEME;

  const suppressKey = new Request(
    `https://cache.ipintel.ai/challenge-token/${ip}`
  );

  let token = null;

  // --------------------------
  // TRY LOAD EXISTING TOKEN
  // -------------------------
  const cachedToken = await caches.default.match(suppressKey);
  if (cachedToken) {
    token = await cachedToken.text();
  }

  // ---------------------------
  // CREATE NEW TOKEN IF NEEDED
  // ---------------------------
  if (!token) {
    let initResp;

    try {
      initResp = await fetchWithTimeout(
        `https://api.ipintel.ai/verify/init.php?api_key=${env.IPINTEL_API_KEY}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "User-Agent": "IPIntel-Worker/1.0"
          },
          body: JSON.stringify({
            ip: ip,
            return: url.href,
            theme: theme,
            risk: riskScore,
            source: "cloudflare_worker"
          })
        },
        1200
      );
    } catch {
      return fetch(request); // FAIL OPEN
    }

    if (!initResp || !initResp.ok) {
      return fetch(request);
    }

    const initData = await initResp.json();
    if (!initData.token) {
      return fetch(request);
    }

    token = initData.token;

    // cache token (short-lived)
    ctx.waitUntil(
      caches.default.put(
        suppressKey,
        new Response(token, {
          headers: { "Cache-Control": "max-age=120" }
        })
      )
    );
  }

  // ----------------------------
  // REDIRECT (ALWAYS WITH TOKEN)
  // ----------------------------
  return new Response(null, {
    status: 302,
    headers: {
      "Location": `https://ipintel.ai/verify/?token=${encodeURIComponent(token)}`,
      "X-IPIntel-Action": "challenge",
      "X-IPIntel-Risk": String(riskScore)
    }
  });
}


    // =====================
    // ALLOW
    // =====================
    const originResponse = await fetch(request);

    const headers = new Headers(originResponse.headers);
    headers.set("X-IPIntel-Action", "allow");
    headers.set("X-IPIntel-Risk", String(riskScore));

    return new Response(originResponse.body, {
      status: originResponse.status,
      headers
    });
  }
};
