// api/ai-explain.js — shared AI narrator for the free tools (URL Sentinel, Email, Password).
// The AI ONLY explains already-computed facts. It never computes, scans, or sees secrets.
// Env: NVIDIA_API_KEY (required), NVIDIA_MODEL (optional)
export const config = { runtime: "edge" };
const NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions";
const DEFAULT_MODEL = "meta/llama-3.2-11b-vision-instruct";
const cors = () => ({ "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" });
const json = (o, s) => new Response(JSON.stringify(o), { status: s, headers: { ...cors(), "Content-Type": "application/json" } });

const INTRO = {
  url: "You are a cybersecurity analyst explaining the result of an automated URL safety check to a non-expert. You did not browse the link. Explain what the signals mean and what the person should do.",
  email: "You are a cybersecurity analyst explaining the result of an automated email-domain security check (SPF, DMARC, DKIM, MX) to a non-expert. Explain the gaps and the concrete DNS records they should add.",
  password: "You are a cybersecurity analyst explaining the result of an automated password-exposure check. You are given ONLY aggregate facts; you never see the password itself. Explain the risk and give practical password guidance.",
  recon: "You are a cybersecurity analyst. You are given aggregated OSINT and reputation data about a single indicator (a domain, IP, URL, file hash or CVE) collected from public sources. Write a clear executive analysis: what the indicator is, the most notable findings across the modules, an overall risk read, and what the reader should do. Reference only what the data shows.",
};

export default async function handler(req) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const apiKey = process.env.NVIDIA_API_KEY;
  if (!apiKey) return json({ error: "Server not configured" }, 500);

  let b; try { b = await req.json(); } catch { return json({ error: "bad json" }, 400); }
  const kind = String(b.kind || "").toLowerCase();
  const lang = String(b.lang || "English").slice(0, 20);
  const intro = INTRO[kind];
  if (!intro) return json({ error: "unknown kind" }, 400);
  const data = JSON.stringify(b.data || {}).slice(0, 3500);

  const prompt = `${intro}

FACTS (JSON, already computed by a deterministic check): ${data}

Use ONLY these facts. Do not invent data, scores, vendors or CVEs. Keep it neutral and professional, no hype.
Write in ${lang}. Return ONLY a valid JSON object (no markdown):
{
  "headline": "one-sentence bottom line",
  "summary": "2 to 4 sentence plain-language explanation of what the result means",
  "points": ["2 to 5 short key findings in plain language"],
  "recommendation": "clear, specific next steps the person should take",
  "caveats": ["1 to 2 short caveats, e.g. this is an automated check, not a guarantee"]
}`;

  try {
    const up = await fetch(NVIDIA_URL, {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: process.env.NVIDIA_MODEL || DEFAULT_MODEL,
        messages: [
          { role: "system", content: "You return only valid JSON. You never reveal or ask for secrets or passwords. You never alter the facts you are given." },
          { role: "user", content: prompt },
        ],
        temperature: 0.3, top_p: 0.9, max_tokens: 800, stream: true,
      }),
    });
    if (!up.ok || !up.body) return json({ error: "AI provider error" }, 502);
    const rd = up.body.getReader(), dec = new TextDecoder(); let buf = "", out = "";
    while (true) { const { done, value } = await rd.read(); if (done) break; buf += dec.decode(value, { stream: true }); let i;
      while ((i = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        if (!line.startsWith("data:")) continue; const d = line.slice(5).trim(); if (d === "[DONE]") continue;
        try { const j = JSON.parse(d); const c = j.choices?.[0]?.delta?.content; if (c) out += c; } catch {} } }
    let narr = null;
    try { narr = JSON.parse(out.trim()); } catch { const m = out.match(/\{[\s\S]*\}/); if (m) { try { narr = JSON.parse(m[0]); } catch {} } }
    if (!narr) return json({ error: "Could not parse" }, 502);
    return json({ narrative: narr }, 200);
  } catch (e) { return json({ error: "Server error" }, 500); }
}
