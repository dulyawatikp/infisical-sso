import { OidcConfigurationType, OidcJwtSignatureAlgorithm } from "@app/services/sso-oidc/sso-oidc-types";

const ORG_ID = "180870b7-f464-4740-8ffe-9d11c9245ea7";
const authHeader = { authorization: `Bearer ${jwtAuthToken}` };

describe("OIDC SSO V1 Router", async () => {
  test("GET config without auth returns 401", async () => {
    const res = await testServer.inject({
      method: "GET",
      url: `/api/v1/sso/oidc/config?organizationId=${ORG_ID}`
    });
    expect(res.statusCode).toBe(401);
  });

  test("POST config requires CUSTOM endpoints or discoveryURL", async () => {
    const res = await testServer.inject({
      method: "POST",
      url: "/api/v1/sso/oidc/config",
      headers: authHeader,
      payload: {
        organizationId: ORG_ID,
        configurationType: OidcConfigurationType.CUSTOM,
        clientId: "cid",
        clientSecret: "csecret",
        isActive: false,
        manageGroupMemberships: false,
        jwtSignatureAlgorithm: OidcJwtSignatureAlgorithm.RS256
        // missing issuer/authorizationEndpoint/jwksUri/tokenEndpoint/userinfoEndpoint
      }
    });
    // Zod superRefine rejection surfaces as 400 from the schema layer
    expect([400, 422]).toContain(res.statusCode);
  });

  test("PATCH + GET roundtrip on seeded config", async () => {
    // Seed 6-oidc-config.ts already created a config row for ORG_ID (orgId is unique) with
    // empty-buffer credentials, so PATCH credentials onto the seeded row instead of POSTing
    // a second config. discoveryURL must be a publicly resolvable domain: updateOidcCfg
    // SSRF-checks it via dns.lookup when not in development mode.
    const patchRes = await testServer.inject({
      method: "PATCH",
      url: "/api/v1/sso/oidc/config",
      headers: authHeader,
      payload: {
        organizationId: ORG_ID,
        clientId: "cid",
        clientSecret: "csecret",
        discoveryURL: "https://example.com/.well-known/openid-configuration",
        configurationType: OidcConfigurationType.DISCOVERY_URL,
        isActive: false,
        manageGroupMemberships: true
      }
    });
    expect(patchRes.statusCode).toBe(200);

    const getRes = await testServer.inject({
      method: "GET",
      url: `/api/v1/sso/oidc/config?organizationId=${ORG_ID}`,
      headers: authHeader
    });
    expect(getRes.statusCode).toBe(200);
    const got = JSON.parse(getRes.payload);
    expect(got.clientId).toBe("cid"); // get response decrypts credentials
    expect(got.clientSecret).toBe("csecret");
    expect(got.discoveryURL).toBe("https://example.com/.well-known/openid-configuration");
    expect(got.isActive).toBe(false);
    expect(got.manageGroupMemberships).toBe(true);

    const domainsRes = await testServer.inject({
      method: "PATCH",
      url: "/api/v1/sso/oidc/config",
      headers: authHeader,
      payload: {
        organizationId: ORG_ID,
        allowedEmailDomains: "example.com, test.io , foo.dev"
      }
    });
    expect(domainsRes.statusCode).toBe(200);
    const patched = JSON.parse(domainsRes.payload);
    expect(patched.allowedEmailDomains).toBe("example.com, test.io, foo.dev");

    // reset so the shared seed org is not left with SSO config values
    const resetRes = await testServer.inject({
      method: "PATCH",
      url: "/api/v1/sso/oidc/config",
      headers: authHeader,
      payload: { organizationId: ORG_ID, isActive: false, allowedEmailDomains: "" }
    });
    expect(resetRes.statusCode).toBe(200);
  });

  test("GET manage-group-memberships returns isEnabled flag", async () => {
    const res = await testServer.inject({
      method: "GET",
      url: `/api/v1/sso/oidc/manage-group-memberships?orgId=${ORG_ID}`,
      headers: authHeader
    });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.payload)).toHaveProperty("isEnabled");
  });
});
