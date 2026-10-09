// api/recon.js — single-input intelligence aggregator.
// Detects the indicator type (domain, ip, url, hash, cve, email) and fans out to free public APIs,
// returning normalised "modules" the frontend renders as a dashboard. The AI analysis is a separate step.
// No keys required for the default sources. Optional keys enrich: SAFE_BROWSING_KEY, ABUSEIPDB_KEY, GREYNOISE_KEY.
export const config = { runtime: "edge" };
const cors = () => ({ "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" });
const json = (o, s) => new Response(JSON.stringify(o), { status: s, headers: { ...cors(), "Content-Type": "application/json" } });
const TIMEOUT = 7000;

async function jget(url, opts = {}, ms = TIMEOUT) {
  const c = new AbortController(); const t = setTimeout(() => c.abort(), ms);
  try { const r = await fetch(url, { ...opts, signal: c.signal }); if (!r.ok) return null; return await r.json(); }
  catch { return null; } finally { clearTimeout(t); }
}
async function doh(name, type) {
  const d = await jget(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: "application/dns-json" } });
  return (d?.Answer || []).map(a => String(a.data || "").replace(/^"|"$/g, "").replace(/"\s+"/g, ""));
}

/* ---------- type detection ---------- */
function detect(input) {
  const s = input.trim();
  if (/^CVE-\d{4}-\d{4,}$/i.test(s)) return { type: "cve", value: s.toUpperCase() };
  if (/^[a-f0-9]{64}$/i.test(s)) return { type: "hash", value: s.toLowerCase(), algo: "sha256" };
  if (/^[a-f0-9]{40}$/i.test(s)) return { type: "hash", value: s.toLowerCase(), algo: "sha1" };
  if (/^[a-f0-9]{32}$/i.test(s)) return { type: "hash", value: s.toLowerCase(), algo: "md5" };
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return { type: "ip", value: s };
  if (/^[0-9a-f:]+:[0-9a-f:]+$/i.test(s) && s.includes("::")) return { type: "ip", value: s };
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s)) return { type: "email", value: s.toLowerCase() };
  if (/^[a-z]+:\/\//i.test(s) || /\/\S/.test(s)) { try { const u = new URL(/^[a-z]+:\/\//i.test(s) ? s : "http://" + s); return { type: "url", value: u.href, host: u.hostname }; } catch {} }
  if (/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(s)) return { type: "domain", value: s.toLowerCase() };
  return { type: "unknown", value: s };
}

/* ---------- enrichment helpers ---------- */
async function dnsModule(domain) {
  const [A, AAAA, MX, NS, TXT] = await Promise.all([doh(domain, "A"), doh(domain, "AAAA"), doh(domain, "MX"), doh(domain, "NS"), doh(domain, "TXT")]);
  const spf = TXT.find(r => /v=spf1/i.test(r)) || "";
  return { module: { id: "dns", title: "DNS records",
    rows: [["A", A.join(", ") || "none"], ["AAAA", AAAA.join(", ") || "none"], ["MX", MX.map(m => m.replace(/^\d+\s+/, "")).join(", ") || "none"], ["NS", NS.join(", ") || "none"], ["TXT records", String(TXT.length)]],
    items: TXT.slice(0, 6) }, ip: (A[0] || "").trim(), spf };
}
async function rdapDomain(domain) {
  const d = await jget(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
  if (!d) return null;
  const ev = Object.fromEntries((d.events || []).map(e => [e.eventAction, e.eventDate]));
  const registrar = (d.entities || []).find(e => (e.roles || []).includes("registrar"));
  const rName = registrar?.vcardArray?.[1]?.find(x => x[0] === "fn")?.[3] || registrar?.handle || "Unknown";
  return { id: "rdap", title: "Registration (WHOIS)", rows: [
    ["Registrar", rName], ["Created", (ev.registration || "").slice(0, 10) || "Unknown"],
    ["Updated", (ev["last changed"] || ev.lastChanged || "").slice(0, 10) || "Unknown"],
    ["Expires", (ev.expiration || "").slice(0, 10) || "Unknown"], ["Status", (d.status || []).join(", ") || "Unknown"]] };
}
async function rdapIp(ip) {
  const d = await jget(`https://rdap.org/ip/${encodeURIComponent(ip)}`);
  if (!d) return null;
  const org = (d.entities || []).map(e => e.vcardArray?.[1]?.find(x => x[0] === "fn")?.[3]).find(Boolean) || d.name || "Unknown";
  return { id: "rdap", title: "IP registration", rows: [
    ["Network", d.name || "Unknown"], ["Organisation", org], ["Country", d.country || "Unknown"],
    ["Range", (d.startAddress && d.endAddress) ? `${d.startAddress} - ${d.endAddress}` : (d.handle || "Unknown")]] };
}
async function geoModule(ip) {
  const d = await jget(`https://ipwho.is/${encodeURIComponent(ip)}`);
  if (!d || d.success === false) return null;
  const asn = d.connection?.asn ? "AS" + d.connection.asn : "";
  return { id: "geo", title: "Network / Geo", rows: [
    ["IP", ip], ["Country", [d.city, d.country].filter(Boolean).join(", ") || "Unknown"],
    ["ASN", [asn, d.connection?.org].filter(Boolean).join(" ") || "Unknown"], ["ISP", d.connection?.isp || "Unknown"]] };
}
async function exposureModule(ip) {
  const d = await jget(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`);
  if (!d || (!d.ports?.length && !d.vulns?.length && !d.hostnames?.length)) return { module: null, vulns: [] };
  return { module: { id: "exposure", title: "Exposure (Shodan InternetDB)", rows: [
    ["Open ports", (d.ports || []).join(", ") || "none"], ["Hostnames", (d.hostnames || []).slice(0, 5).join(", ") || "none"],
    ["Known CVEs", String((d.vulns || []).length)]], tags: (d.tags || []), items: (d.vulns || []).slice(0, 12) }, vulns: d.vulns || [] };
}
async function certsModule(domain) {
  const d = await jget(`https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json`, {}, 9000);
  if (!Array.isArray(d) || !d.length) return null;
  const subs = new Set();
  d.forEach(c => String(c.name_value || "").split(/\n/).forEach(n => { n = n.trim().toLowerCase(); if (n && !n.startsWith("*") && n.endsWith(domain)) subs.add(n); }));
  const list = [...subs].sort().slice(0, 30);
  return { id: "certs", title: "Certificates / subdomains", rows: [["Certificates seen", String(d.length)], ["Unique subdomains", String(subs.size)]], items: list };
}
async function emailModule(domain) {
  const [txt, dmarcTxt, mx] = await Promise.all([doh(domain, "TXT"), doh(`_dmarc.${domain}`, "TXT"), doh(domain, "MX")]);
  const spf = txt.find(r => /v=spf1/i.test(r)) || ""; const spfAll = (spf.match(/([~\-+?])all\b/i) || [])[1] || "";
  const dmarc = dmarcTxt.find(r => /v=DMARC1/i.test(r)) || ""; const pol = (dmarc.match(/[;\s]p=([a-z]+)/i) || [])[1] || "";
  let score = 0; if (spf && (spfAll === "-" || spfAll === "~")) score += 40; else if (spf) score += 15;
  if (pol === "reject" || pol === "quarantine") score += 45; else if (dmarc) score += 15; if (mx.length) score += 15;
  const grade = score >= 85 ? "A" : score >= 65 ? "B" : score >= 45 ? "C" : score >= 25 ? "D" : "F";
  return { id: "email", title: "Email security", rows: [
    ["SPF", spf ? (spfAll + "all") : "missing"], ["DMARC", dmarc ? ("p=" + (pol || "none")) : "missing"],
    ["MX", mx.length ? (mx.length + " host(s)") : "missing"], ["Grade", grade]] };
}

let KEV = { at: 0, set: null };
async function kevSet() {
  if (KEV.set && Date.now() - KEV.at < 600000) return KEV.set;
  const d = await jget("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {}, 9000);
  const set = new Set((d?.vulnerabilities || []).map(v => v.cveID)); if (d) KEV = { at: Date.now(), set }; return set;
}
async function cveModule(id) {
  const [nvd, epssD, kev] = await Promise.all([
    jget(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`, { headers: { "User-Agent": "RochaCryptRecon/1.0" } }, 9000),
    jget(`https://api.first.org/data/v1/epss?cve=${id}`), kevSet()]);
  const c = nvd?.vulnerabilities?.[0]?.cve;
  if (!c) return null;
  const desc = (c.descriptions || []).find(x => x.lang === "en")?.value || "";
  const m = c.metrics?.cvssMetricV31?.[0]?.cvssData || c.metrics?.cvssMetricV30?.[0]?.cvssData || {};
  const epss = epssD?.data?.[0]?.epss ? (parseFloat(epssD.data[0].epss) * 100).toFixed(1) + "%" : "Unknown";
  const inKev = kev.has(id);
  const refs = (c.references || []).slice(0, 6).map(r => r.url);
  return { module: { id: "cve", title: "Vulnerability", rows: [
    ["CVE", id], ["Severity", m.baseSeverity || "Unknown"], ["CVSS", m.baseScore != null ? String(m.baseScore) : "Unknown"],
    ["EPSS (exploit prob.)", epss], ["In CISA KEV", inKev ? "Yes, actively exploited" : "No"], ["Published", (c.published || "").slice(0, 10)]],
    items: [desc, ...refs] }, severity: m.baseSeverity || "", epss, kev: inKev };
}
async function hashModule(hash, algo) {
  const d = await jget(`https://hashlookup.circl.lu/lookup/${algo}/${hash}`, { headers: { accept: "application/json" } });
  if (!d || d.message) return { id: "hash", title: "File reputation", rows: [["Hash", hash], ["Algorithm", algo.toUpperCase()], ["Known file", "Not found in CIRCL hashlookup"]] };
  return { id: "hash", title: "File reputation", rows: [["Hash", hash], ["Algorithm", algo.toUpperCase()],
    ["Known file", "Yes (in public dataset)"], ["File name", d.FileName || d["FileName"] || "Unknown"], ["Source", d.source || "Unknown"], ["Size", d.FileSize || "Unknown"]] };
}

/* optional keyed reputation */
async function reputation(target, kind) {
  const rows = []; let flagged = false;
  if (kind === "ip" && process.env.ABUSEIPDB_KEY) {
    const d = await jget(`https://api.abuseipdb.com/api/v2/check?ipAddress=${target}&maxAgeInDays=90`, { headers: { Key: process.env.ABUSEIPDB_KEY, Accept: "application/json" } });
    const s = d?.data?.abuseConfidenceScore; if (s != null) { rows.push(["AbuseIPDB score", s + "%"]); if (s >= 25) flagged = true; }
  }
  if (kind === "ip" && process.env.GREYNOISE_KEY) {
    const d = await jget(`https://api.greynoise.io/v3/community/${target}`, { headers: { key: process.env.GREYNOISE_KEY } });
    if (d?.classification) { rows.push(["GreyNoise", `${d.classification}${d.name ? " (" + d.name + ")" : ""}`]); if (d.classification === "malicious") flagged = true; }
  }
  if ((kind === "url" || kind === "domain") && process.env.SAFE_BROWSING_KEY) {
    const u = kind === "url" ? target : "http://" + target;
    const d = await jget(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.SAFE_BROWSING_KEY}`, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client: { clientId: "rochacrypt", clientVersion: "1.0" }, threatInfo: { threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], platformTypes: ["ANY_PLATFORM"], threatEntryTypes: ["URL"], threatEntries: [{ url: u }] } }) });
    const t = d?.matches?.[0]?.threatType; rows.push(["Google Safe Browsing", t ? t.replace(/_/g, " ").toLowerCase() : "no threats found"]); if (t) flagged = true;
  }
  return rows.length ? { module: { id: "reputation", title: "Reputation", rows }, flagged } : { module: null, flagged: false };
}

/* ---------- url heuristics (same signals as url-scan) ---------- */
function urlHeuristics(href) {
  const u = new URL(href); const host = u.hostname.toLowerCase(); const labels = host.split(".");
  const signals = []; let score = 0; const add = (p, t) => { score += p; signals.push(t); };
  if (u.protocol === "http:") add(15, "No HTTPS.");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(25, "Raw IP address as host.");
  if (/xn--/.test(host)) add(20, "Punycode domain (possible lookalike).");
  if (href.includes("@")) add(25, "Contains '@' which can hide the destination.");
  if (labels.length - 2 > 3) add(10, "Deep subdomain chain.");
  if ((host.match(/-/g) || []).length >= 3) add(8, "Many hyphens in host.");
  if (href.length > 100) add(6, "Very long URL.");
  return { score: Math.min(100, score), signals, host };
}

/* ---------- assemble by type ---------- */
async function build(det) {
  const modules = []; const signals = []; let riskScore = 0;
  const push = m => { if (m) modules.push(m); };

  if (det.type === "domain") {
    const dns = await dnsModule(det.value); push(dns.module);
    const [rdap, certs, email] = await Promise.all([rdapDomain(det.value), certsModule(det.value), emailModule(det.value)]);
    push(rdap);
    if (dns.ip) { const [geo, exp, rep] = await Promise.all([geoModule(dns.ip), exposureModule(dns.ip), reputation(det.value, "domain")]);
      push(geo); push(exp.module); push(rep.module); if (exp.vulns.length) { riskScore += 30; signals.push(`${exp.vulns.length} known CVE(s) on the host.`); } if (rep.flagged) { riskScore += 40; signals.push("Flagged by a reputation source."); } }
    push(certs); push(email);
  } else if (det.type === "ip") {
    const [rdap, geo, exp, rep] = await Promise.all([rdapIp(det.value), geoModule(det.value), exposureModule(det.value), reputation(det.value, "ip")]);
    push(rdap); push(geo); push(exp.module); push(rep.module);
    if (exp.vulns.length) { riskScore += 30; signals.push(`${exp.vulns.length} known CVE(s) exposed.`); }
    if (rep.flagged) { riskScore += 45; signals.push("Flagged by a reputation source."); }
  } else if (det.type === "url") {
    const h = urlHeuristics(det.value); riskScore += h.score; signals.push(...h.signals);
    modules.push({ id: "url", title: "Link analysis", rows: [["URL", det.value], ["Host", h.host], ["Risk signals", String(h.signals.length)]], items: h.signals });
    const dns = await dnsModule(h.host); push(dns.module);
    const rep = await reputation(det.value, "url"); push(rep.module); if (rep.flagged) { riskScore += 45; signals.push("Flagged by Safe Browsing."); }
    if (dns.ip) { const [geo, exp] = await Promise.all([geoModule(dns.ip), exposureModule(dns.ip)]); push(geo); push(exp.module); }
  } else if (det.type === "email") {
    const domain = det.value.split("@")[1];
    modules.push({ id: "identity", title: "Email", rows: [["Address", det.value], ["Domain", domain]] });
    push(await emailModule(domain));
  } else if (det.type === "hash") {
    push(await hashModule(det.value, det.algo));
  } else if (det.type === "cve") {
    const c = await cveModule(det.value); push(c?.module);
    if (c) { const sev = (c.severity || "").toUpperCase(); if (sev === "CRITICAL") riskScore += 40; else if (sev === "HIGH") riskScore += 30; else if (sev) riskScore += 15; if (c.kev) { riskScore += 40; signals.push("Listed in CISA KEV (actively exploited)."); } signals.push(`Severity ${c.severity || "unknown"}, EPSS ${c.epss}.`); }
  }

  riskScore = Math.min(100, riskScore);
  const level = riskScore >= 60 ? "High" : riskScore >= 30 ? "Elevated" : "Low";
  return { modules, risk: { level, score: riskScore, signals } };
}

export default async function handler(req) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  let b; try { b = await req.json(); } catch { return json({ error: "bad json" }, 400); }
  const input = String(b.input || "").trim().slice(0, 300);
  if (!input) return json({ error: "Enter a domain, IP, URL, file hash or CVE." }, 400);
  const det = detect(input);
  if (det.type === "unknown") return json({ error: "Could not recognise that. Try a domain, IP, URL, file hash (md5/sha1/sha256) or a CVE id." }, 400);
  try {
    const { modules, risk } = await build(det);
    return json({ result: { input: det.value, type: det.type, risk, modules } }, 200);
  } catch (e) { return json({ error: "Aggregation failed." }, 500); }
}
