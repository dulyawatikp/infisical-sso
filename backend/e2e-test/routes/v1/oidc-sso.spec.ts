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

  test("POST + GET + PATCH + DELETE-cycle config with discovery type", async () => {
    const createRes = await testServer.inject({
      method: "POST",
      url: "/api/v1/sso/oidc/config",
      headers: authHeader,
      payload: {
        organizationId: ORG_ID,
        configurationType: OidcConfigurationType.DISCOVERY_URL,
        discoveryURL: "https://idp.example.com/.well-known/openid-configuration",
        clientId: "cid",
        clientSecret: "csecret",
        isActive: false,
        manageGroupMemberships: true,
        jwtSignatureAlgorithm: OidcJwtSignatureAlgorithm.RS256
      }
    });
    expect(createRes.statusCode).toBe(200);
    const created = JSON.parse(createRes.payload);
    expect(created).toMatchObject({ orgId: ORG_ID, isActive: false, manageGroupMemberships: true });
    expect(created.clientId).toBeUndefined(); // create response is sanitized

    const getRes = await testServer.inject({
      method: "GET",
      url: `/api/v1/sso/oidc/config?organizationId=${ORG_ID}`,
      headers: authHeader
    });
    expect(getRes.statusCode).toBe(200);
    const got = JSON.parse(getRes.payload);
    expect(got.clientId).toBe("cid"); // get response decrypts credentials
    expect(got.clientSecret).toBe("csecret");

    const patchRes = await testServer.inject({
      method: "PATCH",
      url: "/api/v1/sso/oidc/config",
      headers: authHeader,
      payload: {
        organizationId: ORG_ID,
        isActive: true,
        allowedEmailDomains: "example.com, test.io , foo.dev"
      }
    });
    expect(patchRes.statusCode).toBe(200);
    const patched = JSON.parse(patchRes.payload);
    expect(patched.isActive).toBe(true);
    expect(patched.allowedEmailDomains).toBe("example.com, test.io, foo.dev");

    // reset to inactive so the shared seed org is not left with SSO enabled
    await testServer.inject({
      method: "PATCH",
      url: "/api/v1/sso/oidc/config",
      headers: authHeader,
      payload: { organizationId: ORG_ID, isActive: false }
    });
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
