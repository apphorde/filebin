import assert from "node:assert/strict";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { database, startTestServer } from "./adapters.mjs";

const issuer = "https://issuer.test.invalid";
const clientId = "filebin-test-client";
const clientSecret = "filebin-test-client-secret";
const subject = "oidc-test-user";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicJwk = {
  ...publicKey.export({ format: "jwk" }),
  kid: "test-key",
  use: "sig",
  alg: "RS256",
};
const originalFetch = globalThis.fetch;
let authorizationNonce;
let authorizationCodeChallenge;
const tokenRequests = [];

function jsonResponse(body) {
  return new Response(JSON.stringify(body), { headers: { "content-type": "application/json" } });
}

function createIdToken(nonce) {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "test-key", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(
    JSON.stringify({
      iss: issuer,
      aud: clientId,
      sub: subject,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      nonce,
    }),
  ).toString("base64url");
  const signingInput = `${header}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  return `${signingInput}.${signer.sign(privateKey).toString("base64url")}`;
}

globalThis.fetch = async (input, init = {}) => {
  const url = typeof input === "string" ? new URL(input) : input instanceof URL ? input : new URL(input.url);
  const method = init.method || (input instanceof Request ? input.method : undefined) || "GET";
  if (url.origin !== issuer) return originalFetch(input, init);
  if (url.pathname === "/.well-known/openid-configuration") {
    return jsonResponse({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      jwks_uri: `${issuer}/jwks`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      scopes_supported: ["openid", "profile", "offline_access"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["client_secret_post"],
      code_challenge_methods_supported: ["S256"],
    });
  }
  if (url.pathname === "/jwks") {
    return jsonResponse({ keys: [publicJwk] });
  }
  if (url.pathname === "/token" && method === "POST") {
    const parameters = new URLSearchParams(init.body);
    tokenRequests.push(parameters);
    assert.equal(parameters.get("client_id"), clientId);
    assert.equal(parameters.get("client_secret"), clientSecret);
    if (parameters.get("grant_type") === "authorization_code") {
      assert.equal(parameters.get("code"), "test-authorization-code");
      assert.equal(parameters.get("redirect_uri"), "http://filebin.test/auth/callback");
      assert.equal(
        createHash("sha256").update(parameters.get("code_verifier")).digest("base64url"),
        authorizationCodeChallenge,
      );
      return jsonResponse({
        access_token: "test-access-token",
        refresh_token: "test-refresh-token",
        token_type: "Bearer",
        expires_in: 3600,
        id_token: createIdToken(authorizationNonce),
      });
    }
    assert.equal(parameters.get("grant_type"), "refresh_token");
    assert.equal(parameters.get("refresh_token"), "test-refresh-token");
    return jsonResponse({
      access_token: "refreshed-access-token",
      refresh_token: "rotated-refresh-token",
      token_type: "Bearer",
      expires_in: 3600,
    });
  }
  if (url.pathname === "/userinfo") {
    const authorization = new Headers(init.headers || input.headers).get("authorization");
    assert.ok(["Bearer test-access-token", "Bearer refreshed-access-token"].includes(authorization));
    return jsonResponse({ sub: subject, name: "OIDC Test User" });
  }
  throw new Error(`Unexpected mocked OIDC request: ${method} ${url.pathname}`);
};

process.env.NODE_ENV = "test";
process.env.OIDC_ISSUER = issuer;
process.env.OIDC_CLIENT_ID = clientId;
process.env.OIDC_CLIENT_SECRET = clientSecret;
process.env.SESSION_SECRET = "oidc-flow-test-session-secret";
delete process.env.AUTH_PROVIDER;

const server = await startTestServer();
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const forwardedHeaders = { "x-forwarded-proto": "http", "x-forwarded-host": "filebin.test" };

test.after(async () => {
  globalThis.fetch = originalFetch;
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

test("OIDC sign-in uses discovery, PKCE, state, nonce, UserInfo, and refresh grants", async () => {
  const loginResponse = await fetch(`${baseUrl}/auth/login?url=%2Fapp`, {
    redirect: "manual",
    headers: forwardedHeaders,
  });
  assert.equal(loginResponse.status, 302);

  const authorizationUrl = new URL(loginResponse.headers.get("location"));
  assert.equal(authorizationUrl.origin, issuer);
  assert.equal(authorizationUrl.pathname, "/authorize");
  assert.equal(authorizationUrl.searchParams.get("client_id"), clientId);
  assert.equal(authorizationUrl.searchParams.get("redirect_uri"), "http://filebin.test/auth/callback");
  assert.equal(authorizationUrl.searchParams.get("scope"), "openid profile offline_access");
  assert.equal(authorizationUrl.searchParams.get("code_challenge_method"), "S256");
  authorizationNonce = authorizationUrl.searchParams.get("nonce");
  authorizationCodeChallenge = authorizationUrl.searchParams.get("code_challenge");
  const state = authorizationUrl.searchParams.get("state");
  assert.ok(authorizationNonce);
  assert.ok(authorizationCodeChallenge);
  assert.ok(state);

  const oidcCookie = loginResponse.headers.getSetCookie()[0].split(";")[0];
  const callbackUrl = new URL("/auth/callback", baseUrl);
  callbackUrl.searchParams.set("code", "test-authorization-code");
  callbackUrl.searchParams.set("state", `${state}-mismatch`);
  const invalidCallback = await fetch(callbackUrl, {
    redirect: "manual",
    headers: { ...forwardedHeaders, cookie: oidcCookie },
  });
  assert.equal(invalidCallback.status, 401);
  assert.equal(tokenRequests.length, 0);

  callbackUrl.searchParams.set("state", state);
  const callback = await fetch(callbackUrl, {
    redirect: "manual",
    headers: { ...forwardedHeaders, cookie: oidcCookie },
  });
  assert.equal(callback.status, 302);
  assert.equal(callback.headers.get("location"), "http://filebin.test/app");
  assert.equal(tokenRequests.length, 1);

  const sessionCookie = callback.headers
    .getSetCookie()
    .find((cookie) => cookie.startsWith("filebin_session="))
    .split(";")[0];
  const sessionId = sessionCookie.slice("filebin_session=".length).split(".")[0];
  let session = await database.get("SELECT * FROM oidc_sessions WHERE id = ?", [sessionId]);
  assert.deepEqual(JSON.parse(session.profile), {
    sub: subject,
    name: "OIDC Test User",
    iss: issuer,
  });
  assert.equal(session.refresh_token, "test-refresh-token");

  await database.run("UPDATE oidc_sessions SET expires_at = 0 WHERE id = ?", [sessionId]);
  const refreshedProfile = await fetch(`${baseUrl}/auth/profile`, {
    headers: { cookie: sessionCookie, ...forwardedHeaders },
  });
  assert.equal(refreshedProfile.status, 200);
  assert.deepEqual(await refreshedProfile.json(), {
    sub: subject,
    name: "OIDC Test User",
    iss: issuer,
  });
  session = await database.get("SELECT * FROM oidc_sessions WHERE id = ?", [sessionId]);
  assert.equal(session.refresh_token, "rotated-refresh-token");
  assert.equal(tokenRequests.length, 2);
});
