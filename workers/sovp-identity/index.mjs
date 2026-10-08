const REQUIRED_CONTEXT = "https://litzki-systems.com/protocol/v2.0";

function loadIdentityDocument(env) {
  if (!env.SOVP_IDENTITY_JSON) {
    throw new Error("SOVP_IDENTITY_JSON secret is not configured");
  }

  let document;
  try {
    document = JSON.parse(env.SOVP_IDENTITY_JSON);
  } catch {
    throw new Error("SOVP_IDENTITY_JSON is not valid JSON");
  }

  if (document["@context"] !== REQUIRED_CONTEXT) {
    throw new Error("identity document must use the Draft 04 v2.0 context");
  }
  if (document["@type"] !== "SovereignIdentity") {
    throw new Error("identity document must have @type SovereignIdentity");
  }

  const entity = document.entity;
  if (!entity || typeof entity !== "object" || typeof entity.canonical_url !== "string") {
    throw new Error("identity document requires entity.canonical_url");
  }

  const freshness = document.freshness;
  if (!freshness || typeof freshness !== "object" ||
      typeof freshness.created !== "string" || typeof freshness.expiresAt !== "string") {
    throw new Error("v2.0 identity document requires signed freshness");
  }

  const created = Date.parse(freshness.created);
  const expiresAt = Date.parse(freshness.expiresAt);
  if (!Number.isFinite(created) || !Number.isFinite(expiresAt) || expiresAt <= created) {
    throw new Error("identity document contains invalid freshness timestamps");
  }

  const proof = document.integrity_proof;
  if (!proof || typeof proof !== "object" ||
      typeof proof.signature !== "string" || typeof proof.public_key_ref !== "string") {
    throw new Error("identity document requires an integrity_proof");
  }

  return document;
}

function hostFromUrl(value) {
  try {
    return new URL(value).hostname.replace(/\.$/, "").toLowerCase();
  } catch {
    return null;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname !== "/sovp-identity.json" &&
        url.pathname !== "/.well-known/sovp-identity.json") {
      return new Response("Not found", { status: 404 });
    }

    try {
      const document = loadIdentityDocument(env);
      const documentHost = hostFromUrl(document.entity.canonical_url);
      const requestHost = url.hostname.replace(/\.$/, "").toLowerCase();

      if (!documentHost || documentHost !== requestHost) {
        throw new Error("identity document host does not match serving host");
      }

      return new Response(JSON.stringify(document, null, 2), {
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "public, max-age=300",
        },
      });
    } catch (error) {
      return new Response(JSON.stringify({
        error: "SOVP identity endpoint is not configured with a valid Draft 04 document",
        detail: error instanceof Error ? error.message : String(error),
      }), {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "no-store",
        },
      });
    }
  },
};
