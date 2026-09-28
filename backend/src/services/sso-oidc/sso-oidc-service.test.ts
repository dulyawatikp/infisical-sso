import { Issuer } from "openid-client";
import { beforeEach, describe, expect, test, vi } from "vitest";

import { BadRequestError } from "@app/lib/errors";
import { blockLocalAndPrivateIpAddresses } from "@app/lib/validator";

import { ssoOidcServiceFactory } from "./sso-oidc-service";
import { OidcConfigurationType } from "./sso-oidc-types";

const { getConfigMock } = vi.hoisted(() => ({ getConfigMock: vi.fn() }));

vi.mock("@app/lib/config/env", () => ({
  getConfig: getConfigMock
}));

vi.mock("@app/services/super-admin/super-admin-service", () => ({
  getServerCfg: vi.fn().mockResolvedValue({ enabledLoginMethods: ["oidc"] })
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
    getConfigMock.mockReturnValue({
      SITE_URL: "https://app.example.com",
      OTEL_TELEMETRY_COLLECTION_ENABLED: false,
      PORTAL_SSO_ENABLED: false
    });
  });

  const createUpdateService = (isSmtpConnected: boolean) => {
    const updatedConfig = { id: "oidc-config-id" };
    const update = vi.fn().mockResolvedValue([updatedConfig]);
    const updateById = vi.fn().mockResolvedValue(undefined);
    const verify = vi.fn().mockResolvedValue(isSmtpConnected);
    const service = ssoOidcServiceFactory({
      ssoOidcConfigDAL: { update } as never,
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
        }),
        updateById
      } as never,
      userDAL: {} as never,
      userAliasDAL: {} as never,
      membershipRoleDAL: {} as never,
      groupOps: {} as never,
      orgSsoPermission: { assertCan: vi.fn().mockResolvedValue(undefined) } as never,
      auditLog: {} as never,
      seatGuard: {} as never,
      emailDomainDAL: {} as never,
      loginService: {} as never,
      tokenService: {} as never,
      smtpService: { verify } as never,
      kmsService: {
        createCipherPairWithDataKey: vi.fn().mockResolvedValue({ encryptor: vi.fn() })
      } as never,
      telemetryService: {} as never
    });

    return { service, update, updatedConfig, verify };
  };

  const activeUpdateDto = {
    organizationId: orgId,
    isActive: true,
    actor: "user",
    actorId: "user-id",
    actorOrgId: orgId,
    actorAuthMethod: "email"
  } as const;

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

  test("rejects OIDC activation when SMTP verification fails", async () => {
    const { service, update, verify } = createUpdateService(false);

    let thrownError: unknown;
    try {
      await service.updateOidcCfg(activeUpdateDto as never);
    } catch (error) {
      thrownError = error;
    }

    expect(verify).toHaveBeenCalledOnce();
    expect(update).not.toHaveBeenCalled();
    expect(thrownError).toBeInstanceOf(BadRequestError);
    expect(thrownError).toMatchObject({
      message:
        "Cannot enable OIDC when there are issues with the instance's SMTP configuration. Bypass this by turning on trust for OIDC emails in the server admin console."
    });
  });

  test("continues OIDC activation when SMTP verification succeeds", async () => {
    const { service, update, updatedConfig, verify } = createUpdateService(true);

    await expect(service.updateOidcCfg(activeUpdateDto as never)).resolves.toEqual(updatedConfig);

    expect(verify).toHaveBeenCalledOnce();
    expect(update).toHaveBeenCalledOnce();
  });

  const createLoginService = (opts: { portalSsoEnabled: boolean; emailDomainVerified: boolean }) => {
    const createdUser = { id: "user-id", email: "u@portal.local", username: "u@portal.local", isAccepted: true };
    const createdAlias = { id: "alias-id", userId: "user-id", isEmailVerified: true };
    const userCreate = vi.fn().mockResolvedValue(createdUser);
    const aliasCreate = vi.fn().mockResolvedValue(createdAlias);
    const createMembership = vi.fn().mockResolvedValue({ id: "membership-id" });
    const processProviderCallback = vi.fn().mockResolvedValue({
      result: "session",
      tokens: { access: "a", refresh: "r" },
      callbackPort: undefined
    });
    const sendMail = vi.fn().mockResolvedValue(undefined);
    const emailDomainDAL = {
      findOne: vi.fn().mockResolvedValue(opts.emailDomainVerified ? { orgId, domain: "portal.local" } : undefined)
    };

    getConfigMock.mockReturnValue({
      SITE_URL: "https://app.example.com",
      OTEL_TELEMETRY_COLLECTION_ENABLED: false,
      PORTAL_SSO_ENABLED: opts.portalSsoEnabled
    });

    const service = ssoOidcServiceFactory({
      ssoOidcConfigDAL: { update: vi.fn().mockResolvedValue([]) } as never,
      orgDAL: {
        findOrgById: vi.fn().mockResolvedValue({
          id: orgId,
          name: "Test Org",
          slug: "test-org",
          rootOrgId: null,
          defaultMembershipRole: "member"
        }),
        findMembership: vi.fn().mockResolvedValue([{ id: "membership-id", isActive: true }]),
        createMembership
      } as never,
      userDAL: {
        transaction: (cb: (tx: unknown) => Promise<unknown>) => cb(undefined),
        findOne: vi.fn().mockResolvedValue(undefined),
        create: userCreate,
        updateById: vi.fn().mockResolvedValue(undefined)
      } as never,
      userAliasDAL: {
        findOne: vi.fn().mockResolvedValue(undefined),
        create: aliasCreate,
        updateById: vi.fn().mockResolvedValue(createdAlias)
      } as never,
      membershipRoleDAL: { create: vi.fn() } as never,
      groupOps: {} as never,
      orgSsoPermission: {} as never,
      auditLog: {} as never,
      seatGuard: { updateSubscriptionOrgMemberCount: vi.fn() } as never,
      emailDomainDAL: emailDomainDAL as never,
      loginService: { processProviderCallback } as never,
      tokenService: { createTokenForUser: vi.fn() } as never,
      smtpService: { sendMail } as never,
      kmsService: {} as never,
      telemetryService: { sendPostHogEvents: vi.fn().mockResolvedValue(undefined) } as never
    });

    return { service, userCreate, aliasCreate, processProviderCallback, sendMail };
  };

  test("portal login bypasses the email-domain gate and issues a session", async () => {
    const { service, userCreate, aliasCreate, processProviderCallback, sendMail } = createLoginService({
      portalSsoEnabled: true,
      emailDomainVerified: false
    });

    const result = await service.oidcLogin({
      externalId: "portal-sub",
      email: "u@portal.local",
      firstName: "U",
      orgId,
      ip: "1.2.3.4",
      userAgent: "vitest",
      isPortalLogin: true
    });

    expect(result.result).toBe("session");
    expect(userCreate).toHaveBeenCalledWith(
      expect.objectContaining({ isEmailVerified: true, isAccepted: true }),
      undefined
    );
    expect(aliasCreate).toHaveBeenCalledWith(expect.objectContaining({ isEmailVerified: true }), undefined);
    expect(sendMail).not.toHaveBeenCalled();
    expect(processProviderCallback).toHaveBeenCalledWith(expect.objectContaining({ isEmailVerified: true }));
  });

  test("non-portal login still enforces the email-domain gate", async () => {
    const { service, processProviderCallback } = createLoginService({
      portalSsoEnabled: true,
      emailDomainVerified: false
    });

    await expect(
      service.oidcLogin({
        externalId: "idp-sub",
        email: "u@portal.local",
        firstName: "U",
        orgId,
        ip: "1.2.3.4",
        userAgent: "vitest"
      })
    ).rejects.toBeInstanceOf(BadRequestError);

    expect(processProviderCallback).not.toHaveBeenCalled();
  });

  test("portal flag is ignored when PORTAL_SSO_ENABLED is off", async () => {
    const { service, processProviderCallback } = createLoginService({
      portalSsoEnabled: false,
      emailDomainVerified: false
    });

    await expect(
      service.oidcLogin({
        externalId: "portal-sub",
        email: "u@portal.local",
        firstName: "U",
        orgId,
        ip: "1.2.3.4",
        userAgent: "vitest",
        isPortalLogin: true
      })
    ).rejects.toBeInstanceOf(BadRequestError);

    expect(processProviderCallback).not.toHaveBeenCalled();
  });
});
