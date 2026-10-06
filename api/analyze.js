// api/analyze.js — reads a news/article URL, extracts a structured security briefing via NVIDIA.
// Env: NVIDIA_API_KEY (required), NVIDIA_MODEL (optional)
export const config = { runtime: "edge" };

const NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions";
const DEFAULT_MODEL = "meta/llama-3.2-11b-vision-instruct";
const cors = () => ({ "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" });
const json = (o, s) => new Response(JSON.stringify(o), { status: s, headers: { ...cors(), "Content-Type": "application/json" } });

function stripHtml(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&#0?39;|&apos;/g, "'").replace(/&quot;/g, '"')
    .replace(/\s+/g, " ").trim();
}

export default async function handler(req) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const apiKey = process.env.NVIDIA_API_KEY;
  if (!apiKey) return json({ error: "Server not configured" }, 500);

  let b; try { b = await req.json(); } catch { return json({ error: "bad json" }, 400); }
  const url = String(b.url || "").trim();
  const language = String(b.lang || "English").slice(0, 20);
  if (!/^https?:\/\//i.test(url)) return json({ error: "Please provide a valid URL (http/https)." }, 400);

  // fetch the article text server-side
  let text = "";
  try {
    const r = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 (compatible; CyberPulse/1.0)" } });
    if (r.ok) text = stripHtml(await r.text()).slice(0, 4500);
  } catch {}
  const basis = text && text.length > 120 ? `Article text:\n"""${text}"""` : `The article text could not be fetched. Analyse based on the URL and your knowledge: ${url}`;

  const prompt = `You are a cybersecurity analyst. Produce a concise structured briefing of this news item.
${basis}

Return ONLY a valid JSON object (no markdown, no commentary), all text written in ${language}:
{
  "title": "the headline",
  "summary": "2-3 sentence plain-language summary",
  "affected": "affected products, vendors or systems, or 'Not specified'",
  "date": "publication date if known, else 'Unknown'",
  "cve": "comma-separated CVE IDs mentioned, or 'None'",
  "impact": "1-2 sentences on the real-world impact / risk",
  "remediation": "1-2 sentences on how to mitigate or what to do, or 'Not specified'"
}`;

  try {
    const up = await fetch(NVIDIA_URL, {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: process.env.NVIDIA_MODEL || DEFAULT_MODEL,
        messages: [
          { role: "system", content: "You are a precise assistant that returns only valid JSON matching the requested schema." },
          { role: "user", content: prompt },
        ],
        temperature: 0.3, top_p: 0.9, max_tokens: 700, stream: true,
      }),
    });
    if (!up.ok || !up.body) return json({ error: "AI provider error", detail: (await up.text().catch(() => "")).slice(0, 200) }, 502);
    const reader = up.body.getReader(), dec = new TextDecoder(); let buf = "", out = "";
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true }); let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        if (!line.startsWith("data:")) continue;
        const d = line.slice(5).trim(); if (d === "[DONE]") continue;
        try { const j = JSON.parse(d); const c = j.choices?.[0]?.delta?.content; if (c) out += c; } catch {}
      }
    }
    let analysis = null;
    try { analysis = JSON.parse(out.trim()); }
    catch { const m = out.match(/\{[\s\S]*\}/); if (m) { try { analysis = JSON.parse(m[0]); } catch {} } }
    if (!analysis) return json({ error: "Could not parse the analysis. Try again." }, 502);
    analysis.url = url;
    return json({ analysis }, 200);
  } catch (e) {
    return json({ error: "Server error" }, 500);
  }
}
