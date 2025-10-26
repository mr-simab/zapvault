/**
 * zapvault/index.js
 * Node wrapper for OWASP ZAP. * Supports: scan (/scan) + scheduled scans (/schedule) +  quick scan (/quick-scan)
 */

import express from "express";
import cors from "cors";
import axios from "axios";
import { URL } from "url";

const app = express();
app.use(express.json());

// ================== CONFIG ==================
const ZAP_HOST = "http://0.0.0.0:8080";
const PORT = 3000;
const MAX_SCAN_TIME_MS = 3 * 60 * 1000; // 3 minutes
const POLL_INTERVAL_MS = 3000;
const VAULT_ORIGIN = process.env.VAULT_ORIGIN;
const API_KEY = process.env.VAULT_KEY;

// ================== CORS ==================
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || origin === VAULT_ORIGIN) callback(null, true);
    else callback(new Error("Not allowed by CORS"));
  },
  methods: ["POST", "GET"],
  allowedHeaders: ["Content-Type", "Authorization"],
};
app.use(cors(corsOptions));

// ================== AUTH ==================
const validateApiKey = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || authHeader !== `Bearer ${API_KEY}`)
    return res.status(401).json({ error: "Unauthorized" });
  next();
};

// ================== HELPERS ==================
async function zapApi(path) {
  const url = `${ZAP_HOST}${path}`;
  const res = await axios.get(url);
  return res.data;
}

function normalizeUrl(u) {
  try {
    const parsed = new URL(u);
    if (!["http:", "https:"].includes(parsed.protocol))
      throw new Error("Invalid protocol");
    return parsed.href;
  } catch {
    throw new Error("Invalid URL");
  }
}

// ================== CORE SCAN FUNCTION ==================
async function performScan(target) {
  const startedAt = Date.now();
  await axios.get(target).catch(() => {});

  // Spider
  await zapApi(`/JSON/spider/action/scan/?url=${encodeURIComponent(target)}`);
  let done = false;
  while (!done) {
    if (Date.now() - startedAt > MAX_SCAN_TIME_MS) throw new Error("Timeout spider");
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    const status = await zapApi(`/JSON/spider/view/status/`);
    const perc = Math.max(...Object.values(status).map((v) => parseInt(v, 10)));
    if (perc >= 100) done = true;
  }

  // Active Scan
  await zapApi(`/JSON/ascan/action/scan/?url=${encodeURIComponent(target)}`);
  let ascanDone = false;
  while (!ascanDone) {
    if (Date.now() - startedAt > MAX_SCAN_TIME_MS) throw new Error("Timeout ascan");
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    const status = await zapApi(`/JSON/ascan/view/status/`);
    const perc = Math.max(...Object.values(status).map((v) => parseInt(v, 10)));
    if (perc >= 100) ascanDone = true;
  }

  const alerts = await zapApi(
    `/JSON/core/view/alerts/?baseurl=${encodeURIComponent(target)}&start=0&count=9999`
  );

  return {
    target,
    completedAt: new Date().toISOString(),
    alerts: alerts.alerts || [],
  };
}
// ================== WAIT FOR ZAP READY ==================
async function waitForZapReady() {
  let attempts = 0;
  while (attempts < 10) {
    try {
      // Check if ZAP responds
      await axios.get(`${ZAP_HOST}/JSON/core/view/version/`);
      console.log("✅ ZAP daemon is ready");
      return true;
    } catch {
      attempts++;
      console.log(`⏳ Waiting for ZAP to start... (${attempts}/10)`);
      await new Promise(r => setTimeout(r, 2000));
    }
  }
  throw new Error("ZAP Daemon not ready after multiple attempts");
}

// ================== ROUTES ==================
//  Health check (used by Dockerfile+host)
app.get("/health", (req, res) => res.json({ status: "ok", service: "zapvault" }));

// Instant Scan
app.post("/scan", validateApiKey, async (req, res) => {
  try {
    const { url } = req.body;
    const target = normalizeUrl(url);
    const result = await performScan(target);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: "Scan failed", detail: err.message });
  }
});

app.post("/quick-scan", validateApiKey, async (req, res) => {
  try {
    const { url } = req.body;
    const target = normalizeUrl(url);
    console.log(`⚡ Performing Quick Passive Scan on ${target}`);

    await axios.get(target).catch(() => {}); // Fetch once to populate passive records
   // Escape special regex characters in the target URL
const regex = target.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&') + '.*';
await zapApi(`/JSON/context/action/includeInContext/?contextName=Default+Context&regex=${encodeURIComponent(regex)}`);

    await zapApi(`/JSON/pscan/action/scanAllInScope/`);

    // Retrieve passive alerts directly
    const alerts = await zapApi(
      `/JSON/core/view/alerts/?baseurl=${encodeURIComponent(target)}&start=0&count=9999`
    );

    res.json({
      target,
      mode: "quick-passive",
      alerts: alerts.alerts || [],
      completedAt: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: "Quick scan failed", detail: err.message });
  }
});


// Continuous scan scheduling (for Real-Time Threat Detector)
const registeredSites = new Map(); // {url: {lastScan, alerts}}
setInterval(async () => {
  for (const [url, info] of registeredSites) {
    try {
      const result = await performScan(url);
      registeredSites.set(url, {
        lastScan: new Date().toISOString(),
        alerts: result.alerts,
      });
      console.log(`[Real-Time] Scanned: ${url}`);
    } catch (err) {
      console.error(`[Real-Time] Failed: ${url}`, err.message);
    }
  }
}, 60 * 60 * 1000); // every 1 hour

app.post("/schedule", validateApiKey, (req, res) => {
  const { url } = req.body;
  try {
    const target = normalizeUrl(url);
    registeredSites.set(target, { lastScan: null, alerts: [] });
    res.json({ message: "Site registered for continuous monitoring", url: target });
  } catch {
    res.status(400).json({ error: "Invalid URL" });
  }
});

app.get("/status", validateApiKey, (req, res) => {
  res.json(Object.fromEntries(registeredSites));
});

// Root info
app.get("/", (req, res) => res.send("✅ ZAP service is active"));
// Global error handler for unexpected errors
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Rejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
});

(async () => {
  try {
    console.log("🚀 Starting ZAP Vault service...");
    await waitForZapReady();
    app.listen(PORT, () =>
      console.log(`⚡ ZAP wrapper running on ${PORT}, connected to ${ZAP_HOST}`)
    );
  } catch (err) {
    console.error("❌ Failed to start service:", err.message);
    process.exit(1);
  }
})();

