// api/career.js — Career Compass: turns questionnaire answers into a structured plan via NVIDIA.
// Env: NVIDIA_API_KEY (required), NVIDIA_MODEL (optional)
export const config = { runtime: "edge" };

const NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions";
const DEFAULT_MODEL = "meta/llama-3.2-11b-vision-instruct";

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

  const prompt = `You are an experienced cybersecurity career advisor. Based on this questionnaire, recommend the best IT/security career paths and a concrete action plan.

Questionnaire:
${profile}

Return ONLY a valid JSON object (no markdown, no commentary), in this exact schema, with ALL text written in ${lang}:
{
  "profile": "2-3 sentence summary of who they are and their strengths",
  "summary": "1-2 sentence headline recommendation",
  "areas": [
    { "name": "area name", "match": 0-100 integer,
      "why": "1-2 sentences why it fits them",
      "steps": ["ordered, concrete steps to get started and progress"],
      "certifications": ["realistic certs for their level, in a sensible order"],
      "skills": ["key skills and tools to learn"],
      "resources": ["specific resource types or platforms to use"] }
  ],
  "next90days": ["3-6 concrete actions for the first 90 days"]
}
Rules: recommend the 3 areas that best match, ranked by match (highest first). Keep certifications realistic for their experience level (don't suggest OSCP to a total beginner). Steps must be practical and ordered. Be specific and encouraging.`;

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
        temperature: 0.5, top_p: 0.9, max_tokens: 1800, stream: false,
      }),
    });
    if (!up.ok) return json({ error: "AI provider error", detail: (await up.text()).slice(0, 200) }, 502);
    const d = await up.json();
    let text = d?.choices?.[0]?.message?.content?.trim() || "";
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
