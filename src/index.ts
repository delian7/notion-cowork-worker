// Cloudflare Worker: Notion Task Creator + Cowork Webhook Relay
//
// Routes:
//   POST /tasks   — creates a task in the Notion Session Memory & Task Tracker database
//   POST /webhook — receives Notion integration webhooks, forwards to Hermes with HMAC
//
// Notion Integration Webhook Verification:
//   When you register the webhook URL in Notion, they send a verification_token challenge.
//   This worker logs it to Cloudflare's console and echoes it back to complete verification.
//   All subsequent events are HMAC-SHA256 signed with that verification_token.
//
// Deploy:
//   cd cloudflare-notion-worker
//   npx wrangler secret put NOTION_API_KEY
//   npx wrangler secret put HERMES_WEBHOOK_SECRET
//   npx wrangler deploy

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

// ── HMAC-SHA256 helper ──────────────────────────────────────────────
async function hmacSha256(secret: string, message: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const msgData = encoder.encode(message);
  const key = await crypto.subtle.importKey(
    "raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, msgData);
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Route: POST /webhook ────────────────────────────────────────────
async function handleWebhook(request: Request, env: Env): Promise<Response> {
  const rawBody = await request.text();

  let payload: any;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return new Response(
      JSON.stringify({ error: "Invalid JSON body." }),
      { status: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
    );
  }

  // ── Notion verification handshake ───────────────────────────────
  // When you first register the webhook URL, Notion sends a challenge:
  //   { "verification_token": "abc123..." }
  // You must echo the token back to complete verification.
  if (payload.verification_token) {
    console.log("═══════════════════════════════════════════════════════");
    console.log("🔑 NOTION VERIFICATION TOKEN (save this!):");
    console.log(payload.verification_token);
    console.log("═══════════════════════════════════════════════════════");
    console.log("ℹ️  Use this token as HERMES_WEBHOOK_SECRET for HMAC validation.");
    console.log("ℹ️  Run: npx wrangler secret put HERMES_WEBHOOK_SECRET");
    console.log("ℹ️  Then paste the token above.");
    console.log("═══════════════════════════════════════════════════════");

    return new Response(
      JSON.stringify({ verification_token: payload.verification_token }),
      { status: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
    );
  }

  // ── Normal webhook event ────────────────────────────────────────
  console.log("[webhook] Received event:", JSON.stringify(payload).slice(0, 500));

  // Extract page ID from the webhook payload (thin event — no properties included)
  // Notion sends the page ID at entity.id (not data.id)
  const pageId = payload?.entity?.id;
  if (!pageId) {
    console.warn("[webhook] No page ID in payload, skipping.");
    return new Response(
      JSON.stringify({ success: true, message: "No page ID, skipped." }),
      { status: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
    );
  }

  // ── Fetch page properties from Notion to check filter conditions ──
  try {
    const pageResp = await fetch(`https://api.notion.com/v1/pages/${pageId}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${env.NOTION_API_KEY}`,
        "Notion-Version": "2022-06-28",
      },
    });

    if (!pageResp.ok) {
      const errText = await pageResp.text();
      console.error("[webhook] Notion page fetch failed:", pageResp.status, errText);
      return new Response(
        JSON.stringify({ error: "Failed to fetch page from Notion", status: pageResp.status }),
        { status: 502, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
      );
    }

    const pageData = await pageResp.json();
    const props = pageData?.properties || {};

    // Filter 1: "Ready for Cowork" must be checked (true)
    // Checkbox properties: { "checkbox": true/false }
    const readyForCowork = props["Ready for Cowork"]?.checkbox;
    if (!readyForCowork) {
      console.log(`[webhook] Page ${pageId}: Ready for Cowork is not checked, skipping.`);
      return new Response(
        JSON.stringify({ success: true, message: "Skipped: Ready for Cowork not checked." }),
        { status: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
      );
    }

    // Filter 2: "Status" must be "Not Started"
    // Status property type is "status" (not "select"): { "status": { "name": "..." } }
    const status = props["Status"]?.status?.name;
    if (status !== "Not Started") {
      console.log(`[webhook] Page ${pageId}: Status is "${status ?? "(none)"}" (not "Not Started"), skipping.`);
      return new Response(
        JSON.stringify({ success: true, message: `Skipped: Status is "${status ?? "(none)"}" (not "Not Started").` }),
        { status: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
      );
    }

    console.log(`[webhook] Page ${pageId}: Ready for Cowork = true, Status = ${status} → forwarding to Hermes.`);
  } catch (err: any) {
    console.error("[webhook] Error fetching page properties:", err.message);
    return new Response(
      JSON.stringify({ error: "Failed to fetch page properties", details: err.message }),
      { status: 500, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
    );
  }

  // ── Forward to Hermes webhook with HMAC signature ──────────────
  const hermesUrl = `${env.HERMES_BASE_URL}/webhooks/notion-ready-for-cowork`;
  const signature = await hmacSha256(env.HERMES_WEBHOOK_SECRET, rawBody);

  try {
    const resp = await fetch(hermesUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Hub-Signature-256": `sha256=${signature}`,
      },
      body: rawBody,
    });

    if (!resp.ok) {
      const errText = await resp.text();
      console.error("[webhook] Hermes returned", resp.status, errText);
      return new Response(
        JSON.stringify({ error: "Hermes webhook failed", status: resp.status, details: errText }),
        { status: 502, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
      );
    }

    const hermesRespText = await resp.text();
    console.log("[webhook] Hermes returned", resp.status, hermesRespText.slice(0, 500));
    return new Response(
      JSON.stringify({ success: true, message: "Forwarded to Hermes.", hermesStatus: resp.status }),
      { status: 200, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
    );
  } catch (err: any) {
    console.error("[webhook] Forward error:", err.message);
    return new Response(
      JSON.stringify({ error: "Failed to forward to Hermes", details: err.message }),
      { status: 500, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
    );
  }
}

// ── Route: POST /tasks ──────────────────────────────────────────────
async function handleTasks(request: Request, env: Env): Promise<Response> {
  let body: any;
  try {
    body = await request.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "Invalid JSON body." }),
      { status: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
    );
  }

  if (!body.title || typeof body.title !== "string" || !body.title.trim()) {
    return new Response(
      JSON.stringify({ error: "Missing required field: title (non-empty string)." }),
      { status: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
    );
  }

  const notionPayload: any = {
    parent: { database_id: env.NOTION_DATABASE_ID },
    properties: {
      Item: { title: [{ text: { content: body.title.trim() } }] },
      Status: { status: { name: body.status || "Not started" } },
    },
  };

  if (body.type) notionPayload.properties.Type = { select: { name: body.type } };
  if (body.priority) notionPayload.properties.Priority = { select: { name: body.priority } };
  if (body.project) notionPayload.properties.Project = { select: { name: body.project } };
  if (body.notes) notionPayload.properties.Notes = { rich_text: [{ text: { content: body.notes } }] };
  if (typeof body.ready_for_cowork === "boolean") {
    notionPayload.properties["Ready for Cowork"] = { checkbox: body.ready_for_cowork };
  }
  if (body.due_date) notionPayload.properties.Date = { date: { start: body.due_date } };

  try {
    const resp = await fetch("https://api.notion.com/v1/pages", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.NOTION_API_KEY}`,
        "Notion-Version": "2022-06-28",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(notionPayload),
    });

    const data = await resp.json();

    if (!resp.ok) {
      return new Response(
        JSON.stringify({ error: "Notion API error", status: resp.status, details: data }),
        { status: 502, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
      );
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: "Task created in Notion.",
        notion_page_id: data.id,
        notion_url: data.url,
      }),
      { status: 201, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
    );
  } catch (err: any) {
    return new Response(
      JSON.stringify({ error: "Worker runtime error", details: err.message }),
      { status: 500, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
    );
  }
}

// ── Main handler ────────────────────────────────────────────────────
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);

    switch (url.pathname) {
      case "/webhook":
        return handleWebhook(request, env);
      case "/tasks":
        return handleTasks(request, env);
      default:
        return new Response(
          JSON.stringify({ error: "Not found. Use /webhook or /tasks." }),
          { status: 404, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
        );
    }
  },
};

export interface Env {
  NOTION_API_KEY: string;
  NOTION_DATABASE_ID: string;
  HERMES_WEBHOOK_SECRET: string;
  HERMES_BASE_URL: string;
}

