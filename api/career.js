// api/career.js — Career Compass: turns questionnaire answers into a structured plan via NVIDIA.
// Env: NVIDIA_API_KEY (required), NVIDIA_MODEL (optional)
export const config = { runtime: "edge" };
// (Edge runtime streams within ~25s; fine for this call)

const NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions";
const DEFAULT_MODEL = "meta/llama-3.2-11b-vision-instruct"; // lighter & faster than mistral-nemotron

const cors = () => ({ "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" });
const json = (o, s) => new Response(JSON.stringify(o), { status: s, headers: { ...cors(), "Content-Type": "application/json" } });

export default async function handler(req) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const apiKey = process.env.NVIDIA_API_KEY;
  if (!apiKey) return json({ error: "Server not configured" }, 500);

  let a; try { a = await req.json(); } catch { return json({ error: "bad json" }, 400); }
  const clean = (v) => String(v ?? "").slice(0, 300);
  const arr = (v) => Array.isArray(v) ? v.map(clean).join(", ") : clean(v);
  const lang = clean(a.language || "English");

  const profile = `
- Name: ${clean(a.name) || "the person"}
- Current situation: ${clean(a.situation)}
- Experience level: ${clean(a.level)}
- Background: ${arr(a.background)}
- What excites them: ${arr(a.interests)}
- Preferred work style: ${clean(a.style)}
- Weekly time available: ${clean(a.time)}
- Main goal: ${clean(a.goal)}
`.trim();

  const prompt = `You are an experienced tech-careers advisor. The person may be a complete beginner who knows nothing about technology yet. Based on this questionnaire, recommend the IT/technology career areas that best match their personality and interests, and a concrete beginner-friendly action plan.

Questionnaire:
${profile}

Consider the full range of tech areas, for example: Software Development (web, mobile, backend), Data & Analytics, Data Science / AI, Cloud & DevOps, IT Infrastructure & Networking, Cybersecurity, IT Support / Helpdesk, QA / Testing, UX/UI Design, Product Management, Databases, Game Development. Choose whichever fit the person best — do not force cybersecurity.

Return ONLY a valid JSON object (no markdown, no commentary), in this exact schema, with ALL text written in ${lang}:
{
  "profile": "2-3 sentence summary of who they are, their strengths and personality, in plain language",
  "summary": "1-2 sentence headline recommendation",
  "areas": [
    { "name": "tech career area", "match": 0-100 integer,
      "why": "1-2 sentences why it fits their personality and interests",
      "steps": ["ordered, concrete beginner steps: what to learn first, what to practice, how to build a portfolio, how to get the first job"],
      "certifications": ["entry-level certifications or well-known courses, in a sensible order — omit if not typical for the area"],
      "skills": ["key skills and tools to learn, starting from zero"],
      "resources": ["specific beginner resource types or platforms (free where possible)"] }
  ],
  "next90days": ["3-6 concrete, doable actions for the first 90 days"]
}
Rules: recommend the 3 areas that best match, ranked by match (highest first). Assume the person may be starting from ZERO — no prior tech knowledge. Steps must start at the absolute beginning and be practical and ordered. Keep certifications/courses entry-level and realistic. Be specific, motivating and jargon-light.`;

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
        temperature: 0.4, top_p: 0.9, max_tokens: 1200, stream: true,
      }),
    });
    if (!up.ok || !up.body) return json({ error: "AI provider error", detail: (await up.text().catch(()=>"" )).slice(0, 200) }, 502);
    // read the streamed SSE and accumulate the full text (streaming keeps us under the 25s limit)
    const reader = up.body.getReader(); const dec = new TextDecoder(); let buf = "", text = "";
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
        if (!line.startsWith("data:")) continue;
        const data = line.slice(5).trim(); if (data === "[DONE]") continue;
        try { const j = JSON.parse(data); const c = j.choices?.[0]?.delta?.content; if (c) text += c; } catch {}
      }
    }
    text = text.trim();
    // extract JSON object even if the model wraps it
    let plan = null;
    try { plan = JSON.parse(text); }
    catch {
      const m = text.match(/\{[\s\S]*\}/);
      if (m) { try { plan = JSON.parse(m[0]); } catch {} }
    }
    if (!plan || !Array.isArray(plan.areas)) return json({ error: "Could not parse plan", raw: text.slice(0, 400) }, 502);
    return json({ plan }, 200);
  } catch (e) {
    return json({ error: "Server error" }, 500);
  }
}
