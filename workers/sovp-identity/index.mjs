const CERT = {
  "@context": "https://litzki-systems.com/protocol/v1.4",
  "@type": "SovereignIdentity",
  "entity": {
    "uid": "urn:sovp:litzki-systems.com",
    "canonical_url": "https://litzki-systems.com",
    "verification_method": "Ed25519"
  },
  "integrity_proof": {
    "signature": "ZHce8cCUSVdxCJW/s15ZUdvFgr1vSh0zSP3KK2hc4NcZA97Z0MtaZw0qx7tI6kAbER0NZdpeZy9gVSaYfo64AQ==",
    "created": "2026-06-09T16:20:11.632Z",
    "public_key_ref": "dns:txt:_sovp.litzki-systems.com",
    "nonce": "aef6ead6-a5c3-412b-8d50-00bfe3685420"
  },
  "scan": {
    "verdict": "CERTIFIED",
    "tScore": 92,
    "readiness": 93,
    "parameterCount": 268,
    "integrityStatus": "VERIFIED",
    "contentQuality": 86,
    "aiReadiness": 28,
    "infrastructureScore": 75,
    "crawlerAccess": 1,
    "machineDeclaration": 0.333,
    "nodesScanned": 500,
    "spec_url": "https://datatracker.ietf.org/doc/draft-litzki-sovp/",
    "issuedAt": "2026-06-09T16:20:11.632Z",
    "expiresAt": "2026-09-07T16:20:11.632Z"
  }
};

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (
      url.pathname === '/sovp-identity.json' ||
      url.pathname === '/.well-known/sovp-identity.json'
    ) {
      return new Response(JSON.stringify(CERT, null, 2), {
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'public, max-age=3600',
        },
      });
    }
    return new Response('Not found', { status: 404 });
  },
};
