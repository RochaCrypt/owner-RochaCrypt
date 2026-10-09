// api/recon.js — single-input intelligence aggregator (with per-source diagnostics).
// Keys (Vercel env): SHODAN_API_KEY, VIRUSTOTAL_API_KEY, DNSDUMPSTER_API_KEY, NETLAS_API_KEY,
//                    SAFE_BROWSING_KEY, ABUSEIPDB_KEY, GREYNOISE_KEY
export const config = { runtime: "edge" };
const cors = () => ({ "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" });
const json = (o, s) => new Response(JSON.stringify(o), { status: s, headers: { ...cors(), "Content-Type": "application/json" } });
const TIMEOUT = 9000;
const uniq = a => [...new Set(a.filter(Boolean))];
const env = k => process.env[k];

async function raw(url, opts = {}, ms = TIMEOUT) {
  const c = new AbortController(); const t = setTimeout(() => c.abort(), ms);
  try { const r = await fetch(url, { ...opts, signal: c.signal }); const text = await r.text(); return { ok: r.ok, status: r.status, text }; }
  catch (e) { return { ok: false, status: 0, text: "", err: String(e && e.name || e) }; } finally { clearTimeout(t); }
}
const parse = t => { try { return JSON.parse(t); } catch { return null; } };
async function jget(url, opts, ms) { const r = await raw(url, opts, ms); return r.ok ? parse(r.text) : null; }
async function doh(name, type) {
  const d = await jget(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: "application/dns-json" } });
  return (d?.Answer || []).map(a => String(a.data || "").replace(/^"|"$/g, "").replace(/"\s+"/g, ""));
}
function subsFrom(text, domain) {
  const re = new RegExp("([a-z0-9_-]+\\.)+" + domain.replace(/[.]/g, "\\."), "gi");
  return uniq((text.match(re) || []).map(s => s.toLowerCase().replace(/^\*\./, ""))).filter(s => s.endsWith(domain) && s !== domain);
}
const ipsFrom = text => uniq((text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) || []).filter(ip => ip.split(".").every(o => +o <= 255)));

function detect(input) {
  const s = input.trim();
  if (/^CVE-\d{4}-\d{4,}$/i.test(s)) return { type: "cve", value: s.toUpperCase() };
  if (/^[a-f0-9]{64}$/i.test(s)) return { type: "hash", value: s.toLowerCase(), algo: "sha256" };
  if (/^[a-f0-9]{40}$/i.test(s)) return { type: "hash", value: s.toLowerCase(), algo: "sha1" };
  if (/^[a-f0-9]{32}$/i.test(s)) return { type: "hash", value: s.toLowerCase(), algo: "md5" };
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return { type: "ip", value: s };
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s)) return { type: "email", value: s.toLowerCase() };
  if (/^[a-z]+:\/\//i.test(s) || /\/\S/.test(s)) { try { const u = new URL(/^[a-z]+:\/\//i.test(s) ? s : "http://" + s); return { type: "url", value: u.href, host: u.hostname }; } catch {} }
  if (/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(s)) return { type: "domain", value: s.toLowerCase() };
  return { type: "unknown", value: s };
}

/* diagnostics */
function mkDiag() { const d = []; return { list: d, add: (s, r, n) => d.push({ source: s, ok: !!(r && r.ok), code: r ? r.status : 0, n: n || 0, err: r && r.err }) }; }
function diagModule(diag) {
  if (!diag.list.length) return null;
  const items = diag.list.map(e => `${e.source}: ${e.ok ? "ok" : "failed"}${e.code ? " [HTTP " + e.code + "]" : e.err ? " [" + e.err + "]" : ""}${e.ok ? " — " + e.n + " result(s)" : ""}`);
  return { id: "diag", title: "Data sources", note: "Which providers responded. Configure the matching API key if one shows 401/403.", rows: [["Providers queried", String(diag.list.length)]], items };
}

/* base modules */
async function dnsModule(domain) {
  const [A, AAAA, MX, NS, TXT] = await Promise.all([doh(domain, "A"), doh(domain, "AAAA"), doh(domain, "MX"), doh(domain, "NS"), doh(domain, "TXT")]);
  return { module: { id: "dns", title: "DNS records", rows: [
    ["A", A.join(", ") || "none"], ["AAAA", AAAA.join(", ") || "none"],
    ["MX", MX.map(m => m.replace(/^\d+\s+/, "")).join(", ") || "none"], ["NS", NS.join(", ") || "none"], ["TXT", String(TXT.length)]],
    items: TXT.slice(0, 6) }, A, MX, NS };
}
async function rdapDomain(domain) {
  const d = await jget(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
  if (!d) return null;
  const ev = Object.fromEntries((d.events || []).map(e => [e.eventAction, e.eventDate]));
  const reg = (d.entities || []).find(e => (e.roles || []).includes("registrar"));
  const rName = reg?.vcardArray?.[1]?.find(x => x[0] === "fn")?.[3] || reg?.handle || "Unknown";
  return { id: "rdap", title: "Registration (WHOIS)", rows: [
    ["Registrar", rName], ["Created", (ev.registration || "").slice(0, 10) || "Unknown"],
    ["Updated", (ev["last changed"] || "").slice(0, 10) || "Unknown"], ["Expires", (ev.expiration || "").slice(0, 10) || "Unknown"],
    ["Status", (d.status || []).join(", ") || "Unknown"]] };
}
async function rdapIp(ip) {
  const d = await jget(`https://rdap.org/ip/${encodeURIComponent(ip)}`); if (!d) return null;
  const org = (d.entities || []).map(e => e.vcardArray?.[1]?.find(x => x[0] === "fn")?.[3]).find(Boolean) || d.name || "Unknown";
  return { id: "rdap", title: "IP registration", rows: [["Network", d.name || "Unknown"], ["Organisation", org], ["Country", d.country || "Unknown"], ["Range", (d.startAddress && d.endAddress) ? `${d.startAddress} - ${d.endAddress}` : (d.handle || "Unknown")]] };
}
async function geoModule(ip) {
  const d = await jget(`https://ipwho.is/${encodeURIComponent(ip)}`); if (!d || d.success === false) return null;
  const asn = d.connection?.asn ? "AS" + d.connection.asn : "";
  return { id: "geo", title: "Network / Geo", rows: [["IP", ip], ["Location", [d.city, d.country].filter(Boolean).join(", ") || "Unknown"], ["ASN", [asn, d.connection?.org].filter(Boolean).join(" ") || "Unknown"], ["ISP", d.connection?.isp || "Unknown"]] };
}
async function emailModule(domain) {
  const [txt, dmarcTxt, mx] = await Promise.all([doh(domain, "TXT"), doh(`_dmarc.${domain}`, "TXT"), doh(domain, "MX")]);
  const spf = txt.find(r => /v=spf1/i.test(r)) || ""; const spfAll = (spf.match(/([~\-+?])all\b/i) || [])[1] || "";
  const dmarc = dmarcTxt.find(r => /v=DMARC1/i.test(r)) || ""; const pol = (dmarc.match(/[;\s]p=([a-z]+)/i) || [])[1] || "";
  let score = 0; if (spf && (spfAll === "-" || spfAll === "~")) score += 40; else if (spf) score += 15;
  if (pol === "reject" || pol === "quarantine") score += 45; else if (dmarc) score += 15; if (mx.length) score += 15;
  const grade = score >= 85 ? "A" : score >= 65 ? "B" : score >= 45 ? "C" : score >= 25 ? "D" : "F";
  return { id: "email", title: "Email security", rows: [["SPF", spf ? (spfAll + "all") : "missing"], ["DMARC", dmarc ? ("p=" + (pol || "none")) : "missing"], ["MX", mx.length ? (mx.length + " host(s)") : "missing"], ["Grade", grade]] };
}
let KEV = { at: 0, set: null };
async function kevSet() { if (KEV.set && Date.now() - KEV.at < 600000) return KEV.set; const d = await jget("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {}, 9000); const set = new Set((d?.vulnerabilities || []).map(v => v.cveID)); if (d) KEV = { at: Date.now(), set }; return set; }
async function cveModule(id) {
  const [nvd, epssD, kev] = await Promise.all([jget(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`, { headers: { "User-Agent": "RochaCryptRecon/1.0" } }, 9000), jget(`https://api.first.org/data/v1/epss?cve=${id}`), kevSet()]);
  const c = nvd?.vulnerabilities?.[0]?.cve; if (!c) return null;
  const desc = (c.descriptions || []).find(x => x.lang === "en")?.value || "";
  const m = c.metrics?.cvssMetricV31?.[0]?.cvssData || c.metrics?.cvssMetricV30?.[0]?.cvssData || {};
  const epss = epssD?.data?.[0]?.epss ? (parseFloat(epssD.data[0].epss) * 100).toFixed(1) + "%" : "Unknown"; const inKev = kev.has(id);
  return { module: { id: "cve", title: "Vulnerability", rows: [["CVE", id], ["Severity", m.baseSeverity || "Unknown"], ["CVSS", m.baseScore != null ? String(m.baseScore) : "Unknown"], ["EPSS (exploit prob.)", epss], ["In CISA KEV", inKev ? "Yes, actively exploited" : "No"], ["Published", (c.published || "").slice(0, 10)]], items: [desc, ...(c.references || []).slice(0, 6).map(r => r.url)] }, severity: m.baseSeverity || "", epss, kev: inKev };
}

/* discovery providers that also report their HTTP status via diag */
async function crtSh(domain, diag) { const r = await raw(`https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json`); const subs = r.ok ? subsFrom(r.text, domain) : []; diag.add("crt.sh", r, subs.length); return subs; }
async function shodanDns(domain, diag) { const k = env("SHODAN_API_KEY"); if (!k) return []; const r = await raw(`https://api.shodan.io/dns/domain/${domain}?key=${k}`); let subs = []; if (r.ok) { const j = parse(r.text); subs = (j?.subdomains || []).map(s => (s + "." + domain).toLowerCase()); } diag.add("Shodan DNS", r, subs.length); return subs; }
async function vtSubs(domain, diag) { const k = env("VIRUSTOTAL_API_KEY"); if (!k) return []; const r = await raw(`https://www.virustotal.com/api/v3/domains/${domain}/subdomains?limit=40`, { headers: { "x-apikey": k, accept: "application/json" } }); let subs = []; if (r.ok) { const j = parse(r.text); subs = (j?.data || []).map(x => String(x.id || "").toLowerCase()); } diag.add("VirusTotal subdomains", r, subs.length); return subs; }
async function ddDomain(domain, diag) { const k = env("DNSDUMPSTER_API_KEY"); if (!k) return { subs: [], ips: [] }; const r = await raw(`https://api.dnsdumpster.com/domain/${domain}`, { headers: { "X-API-Key": k, accept: "application/json" } }); const subs = r.ok ? subsFrom(r.text, domain) : []; const ips = r.ok ? ipsFrom(r.text) : []; diag.add("DNSDumpster", r, subs.length); return { subs, ips }; }
async function netlasDomain(domain, diag) { const k = env("NETLAS_API_KEY"); if (!k) return []; const r = await raw(`https://app.netlas.io/api/domains/?q=${encodeURIComponent("domain:*." + domain)}&source_type=include&fields=domain`, { headers: { "Authorization": "Bearer " + k, accept: "application/json" } }); const subs = r.ok ? subsFrom(r.text, domain) : []; diag.add("Netlas", r, subs.length); return subs; }
async function vtDomain(domain, diag) { const k = env("VIRUSTOTAL_API_KEY"); if (!k) return null; const r = await raw(`https://www.virustotal.com/api/v3/domains/${domain}`, { headers: { "x-apikey": k, accept: "application/json" } }); const j = r.ok ? parse(r.text) : null; diag.add("VirusTotal domain", r, j?.data ? 1 : 0); return j; }

async function shodanHost(ip) { const k = env("SHODAN_API_KEY"); if (!k) return null; const d = await jget(`https://api.shodan.io/shodan/host/${ip}?key=${k}`); if (!d) return null; const vulns = Array.isArray(d.vulns) ? d.vulns : (d.vulns ? Object.keys(d.vulns) : []); const services = (d.data || []).slice(0, 8).map(s => `${s.port}/${s.transport || "tcp"} ${s.product || ""}${s.version ? " " + s.version : ""}`.trim()); return { ports: d.ports || [], org: d.org || d.isp || "", vulns, services }; }
function btoaUrl(u) { return btoa(u).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }

async function build(det, diag) {
  const modules = []; const signals = []; let risk = 0; const push = m => { if (m) modules.push(m); };

  if (det.type === "domain") {
    const domain = det.value;
    const dns = await dnsModule(domain); push(dns.module);
    const [rdap, email, crt, shd, vts, dd, nl, vtd] = await Promise.all([
      rdapDomain(domain), emailModule(domain), crtSh(domain, diag), shodanDns(domain, diag), vtSubs(domain, diag), ddDomain(domain, diag), netlasDomain(domain, diag), vtDomain(domain, diag)]);
    push(rdap);

    const subs = uniq([...crt, ...shd, ...vts, ...dd.subs, ...nl]).filter(s => s.endsWith(domain)).sort();
    push({ id: "subdomains", title: "Subdomains", note: "Merged from crt.sh, Shodan, VirusTotal, DNSDumpster, Netlas. See Data sources below.", rows: [["Unique subdomains", String(subs.length)]], items: subs.length ? subs.slice(0, 120) : ["No subdomains returned. Check the Data sources panel for failing providers."] });

    let ips = uniq([...dns.A, ...dd.ips]);
    (vtd?.data?.attributes?.last_dns_records || []).filter(r => r.type === "A").forEach(r => ips.push(r.value));
    ips = uniq(ips);
    push({ id: "ips", title: "Resolved IP addresses", rows: [["IPs found", String(ips.length)]], items: ips.length ? ips.slice(0, 40) : ["No A records resolved."] });

    if (env("SHODAN_API_KEY") && ips.length) {
      const pick = ips.slice(0, 5); const hosts = await Promise.all(pick.map(async ip => ({ ip, info: await shodanHost(ip) })));
      const items = []; let allV = [];
      hosts.forEach(h => { if (h.info) { const p = [`${h.ip}  ${h.info.org}`.trim()]; if (h.info.ports.length) p.push("ports: " + h.info.ports.join(",")); if (h.info.vulns.length) { p.push("CVEs: " + h.info.vulns.slice(0, 8).join(",")); allV = allV.concat(h.info.vulns); } items.push(p.join("  |  ")); h.info.services.forEach(s => items.push("   " + h.ip + " -> " + s)); } else items.push(h.ip + "  (no Shodan host data — free plan or no credits)"); });
      push({ id: "exposure", title: "Exposed services (Shodan)", rows: [["Hosts scanned", String(pick.length)], ["Known CVEs", String(uniq(allV).length)]], items });
      if (uniq(allV).length) { risk += Math.min(40, uniq(allV).length * 6); signals.push(`${uniq(allV).length} known CVE(s) exposed across hosts.`); }
    } else if (ips[0]) {
      const idb = await jget(`https://internetdb.shodan.io/${ips[0]}`);
      if (idb && (idb.ports?.length || idb.vulns?.length)) { push({ id: "exposure", title: "Exposure (Shodan InternetDB)", rows: [["IP", ips[0]], ["Open ports", (idb.ports || []).join(", ") || "none"], ["Known CVEs", String((idb.vulns || []).length)]], tags: idb.tags || [], items: idb.vulns || [] }); if (idb.vulns?.length) { risk += 30; signals.push(`${idb.vulns.length} known CVE(s) on the primary host.`); } }
    }
    if (ips[0]) push(await geoModule(ips[0]));

    if (vtd?.data?.attributes) { const a = vtd.data.attributes; const st = a.last_analysis_stats || {}; const mal = (st.malicious || 0) + (st.suspicious || 0);
      push({ id: "reputation", title: "Reputation (VirusTotal)", rows: [["Malicious / suspicious", `${st.malicious || 0} / ${st.suspicious || 0}`], ["Harmless", String(st.harmless || 0)], ["Reputation", String(a.reputation ?? "n/a")], ["Categories", Object.values(a.categories || {}).slice(0, 4).join(", ") || "none"]] });
      if (mal >= 1) { risk += Math.min(45, mal * 10); signals.push(`${mal} security vendor(s) flag this domain.`); } }
    push(email);

  } else if (det.type === "ip") {
    const ip = det.value;
    const sh = await shodanHost(ip); diag.add("Shodan host", { ok: !!sh, status: sh ? 200 : 0 }, sh ? (sh.ports.length) : 0);
    const vr = await raw(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, env("VIRUSTOTAL_API_KEY") ? { headers: { "x-apikey": env("VIRUSTOTAL_API_KEY"), accept: "application/json" } } : {}); if (env("VIRUSTOTAL_API_KEY")) diag.add("VirusTotal IP", vr, 1);
    const [rdap, geo] = await Promise.all([rdapIp(ip), geoModule(ip)]); push(rdap); push(geo);
    if (sh) { push({ id: "exposure", title: "Exposed services (Shodan)", rows: [["Open ports", sh.ports.join(", ") || "none"], ["Organisation", sh.org || "Unknown"], ["Known CVEs", String(sh.vulns.length)]], items: [...sh.services, ...(sh.vulns.length ? ["CVEs: " + sh.vulns.join(", ")] : [])] }); if (sh.vulns.length) { risk += Math.min(40, sh.vulns.length * 6); signals.push(`${sh.vulns.length} known CVE(s) exposed.`); } }
    else { const idb = await jget(`https://internetdb.shodan.io/${ip}`); if (idb && (idb.ports?.length || idb.vulns?.length)) push({ id: "exposure", title: "Exposure (InternetDB)", rows: [["Open ports", (idb.ports || []).join(", ") || "none"], ["Known CVEs", String((idb.vulns || []).length)]], tags: idb.tags || [], items: idb.vulns || [] }); }
    const vj = vr.ok ? parse(vr.text) : null; if (vj?.data?.attributes) { const a = vj.data.attributes; const st = a.last_analysis_stats || {}; const mal = (st.malicious || 0) + (st.suspicious || 0); push({ id: "reputation", title: "Reputation (VirusTotal)", rows: [["Malicious / suspicious", `${st.malicious || 0} / ${st.suspicious || 0}`], ["Owner", a.as_owner || "Unknown"], ["Reputation", String(a.reputation ?? "n/a")]] }); if (mal >= 1) { risk += Math.min(45, mal * 10); signals.push(`${mal} vendor(s) flag this IP.`); } }
    if (env("ABUSEIPDB_KEY")) { const ar = await raw(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, { headers: { Key: env("ABUSEIPDB_KEY"), Accept: "application/json" } }); diag.add("AbuseIPDB", ar, 1); const aj = ar.ok ? parse(ar.text) : null; const s = aj?.data?.abuseConfidenceScore; if (s != null) { push({ id: "abuse", title: "IP reputation (AbuseIPDB)", rows: [["Abuse score", s + "%"], ["Reports", String(aj.data.totalReports ?? 0)], ["Country", aj.data.countryCode || "?"]] }); if (s >= 25) { risk += 30; signals.push(`AbuseIPDB confidence ${s}%.`); } } }

  } else if (det.type === "url") {
    const u = new URL(det.value); const host = u.hostname.toLowerCase();
    modules.push({ id: "url", title: "Link", rows: [["URL", det.value], ["Host", host], ["Scheme", u.protocol.replace(":", "")]] });
    if (u.protocol === "http:") { risk += 15; signals.push("No HTTPS."); }
    if (env("VIRUSTOTAL_API_KEY")) { const vr = await raw(`https://www.virustotal.com/api/v3/urls/${btoaUrl(det.value)}`, { headers: { "x-apikey": env("VIRUSTOTAL_API_KEY"), accept: "application/json" } }); diag.add("VirusTotal URL", vr, 1); const vj = vr.ok ? parse(vr.text) : null; if (vj?.data?.attributes) { const a = vj.data.attributes; const st = a.last_analysis_stats || {}; const mal = (st.malicious || 0) + (st.suspicious || 0); push({ id: "reputation", title: "Reputation (VirusTotal)", rows: [["Malicious / suspicious", `${st.malicious || 0} / ${st.suspicious || 0}`], ["Final URL", a.last_final_url || det.value], ["Title", a.title || "Unknown"]] }); if (mal >= 1) { risk += Math.min(50, mal * 12); signals.push(`${mal} vendor(s) flag this URL.`); } } }
    const ips = await doh(host, "A"); if (ips[0]) { push(await geoModule(ips[0])); const idb = await jget(`https://internetdb.shodan.io/${ips[0]}`); if (idb?.ports?.length) push({ id: "exposure", title: "Host exposure", rows: [["IP", ips[0]], ["Open ports", idb.ports.join(", ")], ["Known CVEs", String((idb.vulns || []).length)]], items: idb.vulns || [] }); }

  } else if (det.type === "hash") {
    if (env("VIRUSTOTAL_API_KEY")) { const fr = await raw(`https://www.virustotal.com/api/v3/files/${det.value}`, { headers: { "x-apikey": env("VIRUSTOTAL_API_KEY"), accept: "application/json" } }); diag.add("VirusTotal file", fr, 1); const fj = fr.ok ? parse(fr.text) : null; if (fj?.data?.attributes) { const a = fj.data.attributes; const st = a.last_analysis_stats || {}; const mal = st.malicious || 0; const total = Object.values(st).reduce((x, y) => x + y, 0); push({ id: "file", title: "File reputation (VirusTotal)", rows: [["Detections", `${mal} / ${total}`], ["Threat label", a.popular_threat_classification?.suggested_threat_label || "none"], ["Type", a.type_description || "Unknown"], ["Name", a.meaningful_name || (a.names || [])[0] || "Unknown"], ["Size", a.size ? a.size + " bytes" : "Unknown"]], items: (a.names || []).slice(0, 6) }); if (mal >= 1) { risk += Math.min(60, mal * 3); signals.push(`${mal} engine(s) detect this file as malicious.`); } return finish(modules, risk, signals, diag); } }
    const d = await jget(`https://hashlookup.circl.lu/lookup/${det.algo}/${det.value}`, { headers: { accept: "application/json" } });
    push({ id: "file", title: "File reputation", rows: [["Hash", det.value], ["Algorithm", det.algo.toUpperCase()], ["Known file", (d && !d.message) ? "Yes (CIRCL hashlookup)" : "Not found"], ["Name", d?.FileName || "Unknown"]] });

  } else if (det.type === "email") {
    const domain = det.value.split("@")[1]; modules.push({ id: "identity", title: "Email", rows: [["Address", det.value], ["Domain", domain]] }); push(await emailModule(domain));
  } else if (det.type === "cve") {
    const c = await cveModule(det.value); push(c?.module); if (c) { const sev = (c.severity || "").toUpperCase(); risk += sev === "CRITICAL" ? 40 : sev === "HIGH" ? 30 : sev ? 15 : 0; if (c.kev) { risk += 40; signals.push("Listed in CISA KEV (actively exploited)."); } signals.push(`Severity ${c.severity || "unknown"}, EPSS ${c.epss}.`); }
  }
  return finish(modules, risk, signals, diag);
}
function finish(modules, risk, signals, diag) {
  const dm = diagModule(diag); if (dm) modules.push(dm);
  risk = Math.min(100, risk); const level = risk >= 60 ? "High" : risk >= 30 ? "Elevated" : "Low";
  return { modules, risk: { level, score: risk, signals } };
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
    const diag = mkDiag();
    const { modules, risk } = await build(det, diag);
    const sources = diag.list.filter(e => e.ok && e.n > 0).map(e => e.source);
    return json({ result: { input: det.value, type: det.type, risk, modules, sources } }, 200);
  } catch (e) { return json({ error: "Aggregation failed: " + String(e && e.message || e) }, 500); }
}
