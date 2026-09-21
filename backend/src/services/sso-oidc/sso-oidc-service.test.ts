import { Issuer } from "openid-client";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { blockLocalAndPrivateIpAddresses } from "@app/lib/validator";

import { ssoOidcServiceFactory } from "./sso-oidc-service";
import { OidcConfigurationType } from "./sso-oidc-types";

vi.mock("@app/lib/config/env", () => ({
  getConfig: () => ({
    SITE_URL: "https://app.example.com",
    OTEL_TELEMETRY_COLLECTION_ENABLED: false
  })
}));

vi.mock("@app/lib/validator", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@app/lib/validator")>();
  return {
    ...actual,
    blockLocalAndPrivateIpAddresses: vi.fn()
  };
});

describe("ssoOidcServiceFactory", () => {
  const orgId = "org-id";
  const discoveryURL = "https://idp.example.com/.well-known/openid-configuration";
  const discoveredEndpoints = {
    jwks_uri: "https://keys.example.com/jwks",
    token_endpoint: "https://tokens.example.com/token",
    userinfo_endpoint: "https://users.example.com/userinfo"
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(blockLocalAndPrivateIpAddresses).mockResolvedValue(undefined);
  });

  test("validates discovered provider endpoints before constructing the OIDC strategy", async () => {
    const issuer = new Issuer({
      issuer: "https://idp.example.com",
      authorization_endpoint: "https://idp.example.com/authorize",
      ...discoveredEndpoints
    });
    vi.spyOn(Issuer, "discover").mockResolvedValue(issuer);

    const service = ssoOidcServiceFactory({
      ssoOidcConfigDAL: {
        findOne: vi.fn().mockResolvedValue({
          id: "oidc-config-id",
          orgId,
          configurationType: OidcConfigurationType.DISCOVERY_URL,
          discoveryURL,
          isActive: true,
          encryptedOidcClientId: Buffer.from("client-id"),
          encryptedOidcClientSecret: Buffer.from("client-secret"),
          allowedEmailDomains: "",
          manageGroupMemberships: false,
          jwtSignatureAlgorithm: "RS256"
        })
      } as never,
      orgDAL: {
        findOne: vi.fn().mockResolvedValue({
          id: orgId,
          name: "Test Org",
          slug: "test-org",
          rootOrgId: null,
          defaultMembershipRole: "member",
          googleSsoAuthEnforced: false,
          authEnforced: false,
          scimEnabled: false
        })
      } as never,
      userDAL: {} as never,
      userAliasDAL: {} as never,
      membershipRoleDAL: {} as never,
      groupOps: {} as never,
      orgSsoPermission: {} as never,
      auditLog: {} as never,
      seatGuard: {} as never,
      emailDomainDAL: {} as never,
      loginService: {} as never,
      tokenService: {} as never,
      smtpService: {} as never,
      kmsService: {
        createCipherPairWithDataKey: vi.fn().mockResolvedValue({
          decryptor: ({ cipherTextBlob }: { cipherTextBlob: Buffer }) => cipherTextBlob
        })
      } as never,
      telemetryService: {} as never
    });

    await service.getOrgAuthStrategy("test-org", "orgSlug");

    expect(blockLocalAndPrivateIpAddresses).toHaveBeenNthCalledWith(1, discoveryURL);
    expect(blockLocalAndPrivateIpAddresses).toHaveBeenNthCalledWith(2, discoveredEndpoints.jwks_uri);
    expect(blockLocalAndPrivateIpAddresses).toHaveBeenNthCalledWith(3, discoveredEndpoints.token_endpoint);
    expect(blockLocalAndPrivateIpAddresses).toHaveBeenNthCalledWith(4, discoveredEndpoints.userinfo_endpoint);
  });
});
