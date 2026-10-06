// api/news.js — live feed: RSS + NVD CVEs + CISA KEV, with a short in-memory cache (no external DB).
export const config = { runtime: "edge" };

let CACHE = { at: 0, data: null };
const TTL = 10 * 60 * 1000;

const FEEDS = [
  ["The Hacker News", "https://feeds.feedburner.com/TheHackersNews"],
  ["BleepingComputer", "https://www.bleepingcomputer.com/feed/"],
  ["Krebs on Security", "https://krebsonsecurity.com/feed/"],
  ["Dark Reading", "https://www.darkreading.com/rss.xml"],
  ["SecurityWeek", "https://www.securityweek.com/feed/"],
  ["The Record", "https://therecord.media/feed/"],
];
const MAX_PER = 12, MAX_NEWS = 70, MAX_CVE = 15, MAX_KEV = 12;
const clean = (s = "") => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#0?39;|&apos;/g, "'").replace(/&quot;/g, '"').trim();
const pick = (b, t) => { for (const x of t) { const m = b.match(new RegExp(`<${x}[^>]*>([\\s\\S]*?)</${x}>`, "i")); if (m) return m[1]; } return ""; };
const linkOf = (b) => { const h = b.match(/<link[^>]*href=["']([^"']+)["']/i); return h ? h[1] : clean(pick(b, ["link"])); };
const iso = (s) => { const d = new Date(clean(s)); return isNaN(d) ? null : d.toISOString(); };

function parseFeed(xml, source) {
  const out = [];
  const blocks = xml.split(/<item[\s>]/i).slice(1).concat(xml.split(/<entry[\s>]/i).slice(1));
  for (const b of blocks.slice(0, MAX_PER)) {
    const title = clean(pick(b, ["title"])), url = linkOf(b);
    if (title && url) out.push({ title, url, source, category: "news", date: iso(pick(b, ["pubDate", "published", "updated", "dc:date"])) });
  }
  return out;
}
async function getRSS() {
  const res = await Promise.allSettled(FEEDS.map(async ([n, u]) => { const r = await fetch(u, { headers: { "User-Agent": "CyberPulse/2.0" } }); return r.ok ? parseFeed(await r.text(), n) : []; }));
  let items = []; res.forEach(r => r.status === "fulfilled" && (items = items.concat(r.value)));
  items.sort((a, b) => (b.date || "").localeCompare(a.date || "")); return items.slice(0, MAX_NEWS);
}
async function getCVEs() {
  try {
    const f = d => d.toISOString().slice(0, 23);
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=${f(new Date(Date.now() - 2 * 864e5))}&lastModEndDate=${f(new Date())}&resultsPerPage=${MAX_CVE}`;
    const r = await fetch(url, { headers: { "User-Agent": "CyberPulse/2.0" } }); if (!r.ok) return [];
    const d = await r.json();
    return (d.vulnerabilities || []).slice(0, MAX_CVE).map(v => {
      const c = v.cve, id = c.id, desc = (c.descriptions || []).find(x => x.lang === "en")?.value || "";
      const sev = c.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || "";
      return { title: `${id}${sev ? " [" + sev + "]" : ""} — ${desc.slice(0, 110)}`, url: `https://nvd.nist.gov/vuln/detail/${id}`, source: "NVD", category: "cve", date: c.published || null };
    });
  } catch { return []; }
}
async function getKEV() {
  try {
    const r = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", { headers: { "User-Agent": "CyberPulse/2.0" } }); if (!r.ok) return [];
    const d = await r.json();
    return (d.vulnerabilities || []).sort((a, b) => (b.dateAdded || "").localeCompare(a.dateAdded || "")).slice(0, MAX_KEV).map(v => ({ title: `${v.cveID} — ${v.vulnerabilityName}`, url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`, source: "CISA KEV", category: "kev", date: v.dateAdded ? new Date(v.dateAdded).toISOString() : null }));
  } catch { return []; }
}
async function aggregate() {
  const [news, cve, kev] = await Promise.all([getRSS(), getCVEs(), getKEV()]);
  const items = [...news, ...cve, ...kev];
  return { updated: new Date().toISOString(), count: items.length, sources: [...FEEDS.map(f => f[0]), "NVD", "CISA KEV"], items };
}
export default async function handler(req) {
  const cors = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json", "Cache-Control": "no-store" };
  try {
    const force = new URL(req.url).searchParams.get("force");
    if (!force && CACHE.data && (Date.now() - CACHE.at) < TTL) return new Response(JSON.stringify(CACHE.data), { headers: cors });
    const data = await aggregate(); CACHE = { at: Date.now(), data };
    return new Response(JSON.stringify(data), { headers: cors });
  } catch (e) {
    return new Response(JSON.stringify({ updated: new Date().toISOString(), items: [], sources: [], error: "aggregation failed" }), { headers: cors });
  }
}
