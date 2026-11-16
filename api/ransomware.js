// RochaCrypt Ransomware Intelligence API
// Vercel serverless function: /api/ransomware

const SOURCE_URL = "https://api.ransomware.live/v2/recentvictims";

function firstValue(object, keys) {
  for (const key of keys) {
    if (object && object[key] !== undefined && object[key] !== null && object[key] !== "") {
      return object[key];
    }
  }
  return null;
}

function normalizeDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString();
}

function normalizeVictim(item) {
  return {
    name: firstValue(item, ["victim", "name", "victim_name"]) || "Unknown organization",
    group: firstValue(item, ["group", "group_name", "ransomware_group"]) || "Unknown actor",
    country: firstValue(item, ["country", "country_code"]) || "Unknown",
    industry: firstValue(item, ["sector", "industry"]) || "Unclassified",
    discoveredAt: normalizeDate(firstValue(item, ["discovered", "discovered_at", "published", "date", "attackdate"])),
    attackDate: normalizeDate(firstValue(item, ["attackdate", "attack_date"])),
    description: firstValue(item, ["description", "post_title"]) || null,
    website: firstValue(item, ["website", "domain"]) || null,
    source: "ransomware.live",
    status: "claimed"
  };
}

module.exports = async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const response = await fetch(SOURCE_URL, {
      headers: {
        Accept: "application/json",
        "User-Agent": "RochaCrypt-Ransomware-Intelligence/1.0"
      },
      signal: AbortSignal.timeout(12000)
    });

    if (!response.ok) {
      throw new Error(`Upstream returned HTTP ${response.status}`);
    }

    const payload = await response.json();
    const sourceItems = Array.isArray(payload)
      ? payload
      : Array.isArray(payload?.data)
        ? payload.data
        : Array.isArray(payload?.victims)
          ? payload.victims
          : [];

    const victims = sourceItems.map(normalizeVictim);

    res.setHeader("Cache-Control", "s-maxage=300, stale-while-revalidate=600");
    res.setHeader("Content-Type", "application/json; charset=utf-8");

    return res.status(200).json({
      status: "success",
      source: "ransomware.live",
      updatedAt: new Date().toISOString(),
      disclaimer: "Leak-site records are ransomware-group claims and are not independent confirmation of compromise.",
      count: victims.length,
      victims
    });
  } catch (error) {
    console.error("Ransomware intelligence API error:", error);
    return res.status(502).json({
      status: "error",
      error: "Unable to retrieve ransomware intelligence",
      detail: process.env.NODE_ENV === "development" ? error.message : undefined
    });
  }
};
