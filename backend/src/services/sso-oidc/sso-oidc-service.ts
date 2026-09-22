import { requestContext } from "@fastify/request-context";
import { Issuer, Issuer as OpenIdIssuer, Strategy as OpenIdStrategy, TokenSet } from "openid-client";

import { AccessScope, OrgMembershipStatus, TableName } from "@app/db/schemas";
import { TOidcConfigsUpdate } from "@app/db/schemas/oidc-configs";
import { getConfig } from "@app/lib/config/env";
import { BadRequestError, ForbiddenRequestError, NotFoundError, OidcAuthError } from "@app/lib/errors";
import { logger } from "@app/lib/logger";
import { requestMemoKeys } from "@app/lib/request-context/memo-keys";
import { RequestContextKey } from "@app/lib/request-context/request-context-keys";
import { requestMemoize } from "@app/lib/request-context/request-memoizer";
import { AuthAttemptAuthMethod, AuthAttemptAuthResult, authAttemptCounter } from "@app/lib/telemetry/metrics";
import { OrgServiceActor } from "@app/lib/types";
import { blockLocalAndPrivateIpAddresses, sanitizeEmail, validateEmail } from "@app/lib/validator";
import { TAuthLoginFactory } from "@app/services/auth/auth-login-service";
import { AuthMethod } from "@app/services/auth/auth-type";
import { TAuthTokenServiceFactory } from "@app/services/auth-token/auth-token-service";
import { TokenType } from "@app/services/auth-token/auth-token-types";
import { TKmsServiceFactory } from "@app/services/kms/kms-service";
import { KmsDataKey } from "@app/services/kms/kms-types";
import { getDefaultOrgMembershipRole } from "@app/services/org/org-role-fns";
import { SmtpTemplates, TSmtpService } from "@app/services/smtp/smtp-service";
import { getServerCfg } from "@app/services/super-admin/super-admin-service";
import { LoginMethod } from "@app/services/super-admin/super-admin-types";
import { TTelemetryServiceFactory } from "@app/services/telemetry/telemetry-service";
import { PostHogEventTypes } from "@app/services/telemetry/telemetry-types";
import { TUserDALFactory } from "@app/services/user/user-dal";
import { TUserAliasDALFactory } from "@app/services/user-alias/user-alias-dal";
import { UserAliasType } from "@app/services/user-alias/user-alias-types";

import { TSsoOidcConfigDALFactory } from "./sso-oidc-dal";
import {
  extractOidcUserClaims,
  resolveOidcGroupChanges,
  resolveOrgIdForIdentifier,
  verifyEmailDomainOwnershipInOrg
} from "./sso-oidc-fns";
import {
  OidcConfigurationType,
  TCreateOidcCfgDTO,
  TGetOidcCfgDTO,
  TOidcLoginDTO,
  TOidcSsoAuditLog,
  TOidcSsoEmailDomainDAL,
  TOidcSsoGroupOps,
  TOidcSsoMembershipRoleDAL,
  TOidcSsoOrgDAL,
  TOidcSsoOrgSsoPermission,
  TOidcSsoSeatGuard,
  TUpdateOidcCfgDTO
} from "./sso-oidc-types";

type TSsoOidcServiceFactoryDep = {
  ssoOidcConfigDAL: Pick<TSsoOidcConfigDALFactory, "findOne" | "update" | "create">;
  orgDAL: TOidcSsoOrgDAL;
  userDAL: Pick<TUserDALFactory, "create" | "findOne" | "findById" | "updateById" | "transaction">;
  userAliasDAL: Pick<TUserAliasDALFactory, "create" | "findOne">;
  membershipRoleDAL: TOidcSsoMembershipRoleDAL;
  groupOps: TOidcSsoGroupOps;
  orgSsoPermission: TOidcSsoOrgSsoPermission;
  auditLog: TOidcSsoAuditLog;
  seatGuard: TOidcSsoSeatGuard;
  emailDomainDAL: TOidcSsoEmailDomainDAL;
  loginService: Pick<TAuthLoginFactory, "processProviderCallback">;
  tokenService: Pick<TAuthTokenServiceFactory, "createTokenForUser">;
  smtpService: Pick<TSmtpService, "sendMail" | "verify">;
  kmsService: Pick<TKmsServiceFactory, "createCipherPairWithDataKey">;
  telemetryService: Pick<TTelemetryServiceFactory, "sendPostHogEvents">;
};

export type TSsoOidcServiceFactory = ReturnType<typeof ssoOidcServiceFactory>;

export const ssoOidcServiceFactory = ({
  ssoOidcConfigDAL,
  orgDAL,
  userDAL,
  userAliasDAL,
  membershipRoleDAL,
  groupOps,
  orgSsoPermission,
  auditLog,
  seatGuard,
  emailDomainDAL,
  loginService,
  tokenService,
  smtpService,
  kmsService,
  telemetryService
}: TSsoOidcServiceFactoryDep) => {
  const getOidc = async (dto: TGetOidcCfgDTO) => {
    const oidcCfg = await ssoOidcConfigDAL.findOne({ orgId: dto.organizationId });
    if (!oidcCfg) {
      throw new NotFoundError({ message: "Failed to find OIDC SSO data" });
    }

    if (dto.type === "external") {
      await orgSsoPermission.assertCan(
        {
          actor: dto.actor,
          actorId: dto.actorId,
          orgId: dto.organizationId,
          actorOrgId: dto.actorOrgId,
          actorAuthMethod: dto.actorAuthMethod
        },
        "read"
      );
    }

    const { decryptor } = await kmsService.createCipherPairWithDataKey({
      type: KmsDataKey.Organization,
      orgId: oidcCfg.orgId
    });

    let clientId = "";
    if (oidcCfg.encryptedOidcClientId) {
      clientId = decryptor({ cipherTextBlob: oidcCfg.encryptedOidcClientId }).toString();
    }

    let clientSecret = "";
    if (oidcCfg.encryptedOidcClientSecret) {
      clientSecret = decryptor({ cipherTextBlob: oidcCfg.encryptedOidcClientSecret }).toString();
    }

    return {
      id: oidcCfg.id,
      issuer: oidcCfg.issuer,
      authorizationEndpoint: oidcCfg.authorizationEndpoint,
      configurationType: oidcCfg.configurationType,
      discoveryURL: oidcCfg.discoveryURL,
      jwksUri: oidcCfg.jwksUri,
      tokenEndpoint: oidcCfg.tokenEndpoint,
      userinfoEndpoint: oidcCfg.userinfoEndpoint,
      orgId: oidcCfg.orgId,
      isActive: oidcCfg.isActive,
      allowedEmailDomains: oidcCfg.allowedEmailDomains,
      clientId,
      clientSecret,
      manageGroupMemberships: oidcCfg.manageGroupMemberships,
      jwtSignatureAlgorithm: oidcCfg.jwtSignatureAlgorithm
    };
  };

  const oidcLogin = async ({
    email,
    externalId,
    firstName,
    lastName,
    orgId,
    ip,
    userAgent,
    callbackPort,
    groups = [],
    manageGroupMemberships
  }: TOidcLoginDTO) => {
    const serverCfg = await getServerCfg();

    if (serverCfg.enabledLoginMethods && !serverCfg.enabledLoginMethods.includes(LoginMethod.OIDC)) {
      throw new ForbiddenRequestError({ message: "Login with OIDC is disabled by administrator." });
    }

    await verifyEmailDomainOwnershipInOrg({ email, orgId, emailDomainDAL });
    const sanitizedEmail = sanitizeEmail(email);
    validateEmail(sanitizedEmail);

    let userAlias = await userAliasDAL.findOne({
      externalId,
      orgId,
      aliasType: UserAliasType.OIDC
    });

    const organization = await requestMemoize(requestMemoKeys.orgFindOrgById(orgId), () => orgDAL.findOrgById(orgId));
    if (!organization) throw new NotFoundError({ message: `Organization with ID '${orgId}' not found` });

    let user;
    if (userAlias) {
      // Existing alias branch — spec §5.4 step 6. NOTE: no seat check here (documented quirk).
      user = await userDAL.transaction(async (tx) => {
        const foundUser = await userDAL.findById(userAlias.userId, tx);
        await verifyEmailDomainOwnershipInOrg({ email: foundUser.username ?? "", orgId, emailDomainDAL });

        const [orgMembership] = await orgDAL.findMembership(
          {
            [`${TableName.Membership}.actorUserId`]: userAlias.userId,
            [`${TableName.Membership}.scopeOrgId`]: orgId,
            [`${TableName.Membership}.scope`]: AccessScope.Organization
          },
          { tx }
        );
        if (!orgMembership) {
          const { role, roleId } = await getDefaultOrgMembershipRole(organization.defaultMembershipRole);
          const membership = await orgDAL.createMembership(
            {
              actorUserId: userAlias.userId,
              scopeOrgId: orgId,
              scope: AccessScope.Organization,
              status: OrgMembershipStatus.Invited,
              isActive: true
            },
            tx
          );
          await membershipRoleDAL.create({ membershipId: membership.id, role, customRoleId: roleId }, tx);
        }

        return foundUser;
      });
    } else {
      // New alias branch — spec §5.4 step 7 (includes seat guard).
      let isNewUser = false;
      user = await userDAL.transaction(async (tx) => {
        let newUser = await userDAL.findOne({ username: sanitizedEmail }, tx);

        if (!newUser) {
          newUser = await userDAL.create(
            {
              email: sanitizedEmail,
              firstName,
              username: sanitizedEmail,
              lastName,
              authMethods: [],
              isGhost: false
            },
            tx
          );
          isNewUser = true;
        }

        userAlias = await userAliasDAL.create(
          {
            userId: newUser.id,
            aliasType: UserAliasType.OIDC,
            externalId,
            emails: sanitizedEmail ? [sanitizedEmail] : [],
            orgId
          },
          tx
        );

        const [orgMembership] = await orgDAL.findMembership(
          {
            [`${TableName.Membership}.actorUserId`]: userAlias.userId,
            [`${TableName.Membership}.scopeOrgId`]: orgId,
            [`${TableName.Membership}.scope`]: AccessScope.Organization
          },
          { tx }
        );

        if (!orgMembership) {
          await seatGuard.throwOnMemberLimitReached(orgId);

          const { role, roleId } = await getDefaultOrgMembershipRole(organization.defaultMembershipRole);
          const membership = await orgDAL.createMembership(
            {
              actorUserId: newUser.id,
              scopeOrgId: orgId,
              scope: AccessScope.Organization,
              status: OrgMembershipStatus.Invited,
              isActive: true,
              inviteEmail: sanitizedEmail
            },
            tx
          );
          await membershipRoleDAL.create({ membershipId: membership.id, role, customRoleId: roleId }, tx);
        }

        return newUser;
      });

      if (isNewUser) {
        void telemetryService
          .sendPostHogEvents({
            event: PostHogEventTypes.UserSignedUp,
            distinctId: user.username ?? "",
            organizationId: orgId,
            properties: {
              username: user.username,
              email: user.email ?? "",
              signupMethod: "oidc"
            }
          })
          .catch((err: Error) => logger.error(err, "Failed to send UserSignedUp telemetry event [signupMethod=oidc]"));
      }
    }

    if (manageGroupMemberships) {
      // Spec §5.4 step 8: diff via resolveOidcGroupChanges, then add/remove + audit events.
      const userGroups = await groupOps.findGroupMembershipsByUserIdInOrg(user.id, orgId);
      const orgGroups = await groupOps.findByOrgId(orgId);
      const { groupsToAddUserTo, groupsToRemoveUserFrom } = resolveOidcGroupChanges({
        idpGroups: groups,
        userGroupMemberships: userGroups,
        orgGroups
      });

      for await (const group of groupsToAddUserTo) {
        await groupOps.addUsersToGroupByUserIds({ userIds: [user.id], group });
      }
      if (groupsToAddUserTo.length) {
        await auditLog.createAuditLog({
          actor: { type: "platform", metadata: {} },
          orgId,
          event: {
            type: "oidc-group-membership-mapping-assign-user",
            metadata: {
              userId: user.id,
              userEmail: user.email ?? user.username,
              assignedToGroups: groupsToAddUserTo.map(({ id, name }) => ({ id, name })),
              userGroupsClaim: groups
            }
          }
        });
      }

      for await (const group of groupsToRemoveUserFrom) {
        await groupOps.removeUsersFromGroupByUserIds({ userIds: [user.id], group });
      }
      if (groupsToRemoveUserFrom.length) {
        await auditLog.createAuditLog({
          actor: { type: "platform", metadata: {} },
          orgId,
          event: {
            type: "oidc-group-membership-mapping-remove-user",
            metadata: {
              userId: user.id,
              userEmail: user.email ?? user.username,
              removedFromGroups: groupsToRemoveUserFrom.map(({ id, name }) => ({ id, name })),
              userGroupsClaim: groups
            }
          }
        });
      }
    }

    await seatGuard.updateSubscriptionOrgMemberCount(organization.id);

    await ssoOidcConfigDAL.update({ orgId }, { lastUsed: new Date() });

    if (user.email && !userAlias.isEmailVerified) {
      const token = await tokenService.createTokenForUser({
        type: TokenType.TOKEN_EMAIL_VERIFICATION,
        userId: user.id,
        aliasId: userAlias.id
      });

      await smtpService
        .sendMail({
          template: SmtpTemplates.EmailVerification,
          subjectLine: `Infisical confirmation code: ${token}`,
          recipients: [user.email],
          substitutions: { code: token }
        })
        .catch((err: Error) => {
          throw new OidcAuthError({
            message: `Error sending email confirmation code for user registration - contact the Infisical instance admin. ${err.message}`
          });
        });
    }

    const callbackResult = await loginService.processProviderCallback({
      user,
      authMethod: AuthMethod.OIDC,
      isEmailVerified: Boolean(userAlias.isEmailVerified),
      aliasId: userAlias.id,
      ip,
      userAgent,
      organizationId: organization.id,
      callbackPort: callbackPort ? Number(callbackPort) : undefined
    });

    return { ...callbackResult, userId: user.id };
  };

  const createOidcCfg = async (dto: TCreateOidcCfgDTO) => {
    const org = await orgDAL.findOne({ id: dto.organizationId });
    if (!org) {
      throw new NotFoundError({ message: `Organization with ID '${dto.organizationId}' not found` });
    }

    await orgSsoPermission.assertCan(
      {
        actor: dto.actor,
        actorId: dto.actorId,
        orgId: org.id,
        actorOrgId: dto.actorOrgId,
        actorAuthMethod: dto.actorAuthMethod
      },
      "create"
    );

    if (org.googleSsoAuthEnforced && dto.isActive) {
      throw new BadRequestError({
        message:
          "You cannot enable OIDC SSO while Google OAuth is enforced. Disable Google OAuth enforcement to enable OIDC SSO."
      });
    }

    if (dto.discoveryURL) await blockLocalAndPrivateIpAddresses(dto.discoveryURL);
    if (dto.jwksUri) await blockLocalAndPrivateIpAddresses(dto.jwksUri);
    if (dto.tokenEndpoint) await blockLocalAndPrivateIpAddresses(dto.tokenEndpoint);
    if (dto.userinfoEndpoint) await blockLocalAndPrivateIpAddresses(dto.userinfoEndpoint);

    const { encryptor } = await kmsService.createCipherPairWithDataKey({
      type: KmsDataKey.Organization,
      orgId: org.id
    });

    return ssoOidcConfigDAL.create({
      issuer: dto.issuer,
      isActive: dto.isActive,
      configurationType: dto.configurationType,
      discoveryURL: dto.discoveryURL,
      authorizationEndpoint: dto.authorizationEndpoint,
      allowedEmailDomains: dto.allowedEmailDomains,
      jwksUri: dto.jwksUri,
      tokenEndpoint: dto.tokenEndpoint,
      userinfoEndpoint: dto.userinfoEndpoint,
      orgId: org.id,
      manageGroupMemberships: dto.manageGroupMemberships,
      jwtSignatureAlgorithm: dto.jwtSignatureAlgorithm,
      encryptedOidcClientId: encryptor({ plainText: Buffer.from(dto.clientId) }).cipherTextBlob,
      encryptedOidcClientSecret: encryptor({ plainText: Buffer.from(dto.clientSecret) }).cipherTextBlob
    });
  };

  const updateOidcCfg = async (dto: TUpdateOidcCfgDTO) => {
    const org = await orgDAL.findOne({ id: dto.organizationId });
    if (!org) {
      throw new NotFoundError({ message: `Organization with ID '${dto.organizationId}' not found` });
    }

    await orgSsoPermission.assertCan(
      {
        actor: dto.actor,
        actorId: dto.actorId,
        orgId: org.id,
        actorOrgId: dto.actorOrgId,
        actorAuthMethod: dto.actorAuthMethod
      },
      "edit"
    );

    if (org.googleSsoAuthEnforced && dto.isActive) {
      throw new BadRequestError({
        message:
          "You cannot enable OIDC SSO while Google OAuth is enforced. Disable Google OAuth enforcement to enable OIDC SSO."
      });
    }

    if (dto.isActive) {
      const isSmtpConnected = await smtpService.verify();
      if (!isSmtpConnected) {
        throw new BadRequestError({
          message:
            "Cannot enable OIDC when there are issues with the instance's SMTP configuration. Bypass this by turning on trust for OIDC emails in the server admin console."
        });
      }
    }

    if (dto.discoveryURL) await blockLocalAndPrivateIpAddresses(dto.discoveryURL);
    if (dto.jwksUri) await blockLocalAndPrivateIpAddresses(dto.jwksUri);
    if (dto.tokenEndpoint) await blockLocalAndPrivateIpAddresses(dto.tokenEndpoint);
    if (dto.userinfoEndpoint) await blockLocalAndPrivateIpAddresses(dto.userinfoEndpoint);

    const { encryptor } = await kmsService.createCipherPairWithDataKey({
      type: KmsDataKey.Organization,
      orgId: org.id
    });

    const updateQuery: TOidcConfigsUpdate = {
      allowedEmailDomains: dto.allowedEmailDomains,
      configurationType: dto.configurationType,
      discoveryURL: dto.discoveryURL,
      issuer: dto.issuer,
      authorizationEndpoint: dto.authorizationEndpoint,
      tokenEndpoint: dto.tokenEndpoint,
      userinfoEndpoint: dto.userinfoEndpoint,
      jwksUri: dto.jwksUri,
      isActive: dto.isActive,
      lastUsed: null,
      manageGroupMemberships: dto.manageGroupMemberships,
      jwtSignatureAlgorithm: dto.jwtSignatureAlgorithm
    };

    if (dto.clientId !== undefined) {
      updateQuery.encryptedOidcClientId = encryptor({ plainText: Buffer.from(dto.clientId) }).cipherTextBlob;
    }

    if (dto.clientSecret !== undefined) {
      updateQuery.encryptedOidcClientSecret = encryptor({ plainText: Buffer.from(dto.clientSecret) }).cipherTextBlob;
    }

    const [ssoConfig] = await ssoOidcConfigDAL.update({ orgId: org.id }, updateQuery);
    await orgDAL.updateById(org.id, { authEnforced: false, scimEnabled: false });
    return ssoConfig;
  };

  const getOrgAuthStrategy = async (
    identifier: string,
    identifierType: "domain" | "orgSlug" = "domain",
    callbackPort?: string
  ) => {
    const appCfg = getConfig();

    const resolvedOrgId = await resolveOrgIdForIdentifier({ identifier, identifierType, emailDomainDAL, orgDAL });

    const oidcCfg = await getOidc({ type: "internal", organizationId: resolvedOrgId });

    if (!oidcCfg || !oidcCfg.isActive) {
      throw new ForbiddenRequestError({ message: "Failed to authenticate with OIDC SSO" });
    }
    const org = await orgDAL.findOne({ id: resolvedOrgId });

    let issuer: Issuer;
    if (oidcCfg.configurationType === OidcConfigurationType.DISCOVERY_URL) {
      if (!oidcCfg.discoveryURL) {
        throw new BadRequestError({ message: "OIDC not configured correctly" });
      }
      await blockLocalAndPrivateIpAddresses(oidcCfg.discoveryURL);
      issuer = await Issuer.discover(oidcCfg.discoveryURL);
      for await (const endpoint of [
        issuer.metadata.jwks_uri,
        issuer.metadata.token_endpoint,
        issuer.metadata.userinfo_endpoint
      ]) {
        if (endpoint) await blockLocalAndPrivateIpAddresses(endpoint);
      }
    } else {
      if (
        !oidcCfg.issuer ||
        !oidcCfg.authorizationEndpoint ||
        !oidcCfg.jwksUri ||
        !oidcCfg.tokenEndpoint ||
        !oidcCfg.userinfoEndpoint
      ) {
        throw new BadRequestError({ message: "OIDC not configured correctly" });
      }
      await blockLocalAndPrivateIpAddresses(oidcCfg.jwksUri);
      await blockLocalAndPrivateIpAddresses(oidcCfg.tokenEndpoint);
      await blockLocalAndPrivateIpAddresses(oidcCfg.userinfoEndpoint);
      issuer = new OpenIdIssuer({
        issuer: oidcCfg.issuer,
        authorization_endpoint: oidcCfg.authorizationEndpoint,
        jwks_uri: oidcCfg.jwksUri,
        token_endpoint: oidcCfg.tokenEndpoint,
        userinfo_endpoint: oidcCfg.userinfoEndpoint
      });
    }

    const client = new issuer.Client({
      client_id: oidcCfg.clientId,
      client_secret: oidcCfg.clientSecret,
      redirect_uris: [`${appCfg.SITE_URL}/api/v1/sso/oidc/callback`],
      id_token_signed_response_alg: oidcCfg.jwtSignatureAlgorithm
    });

    const codeChallengeMethods = client.issuer.metadata.code_challenge_methods_supported;
    const supportsPKCE = Array.isArray(codeChallengeMethods) && codeChallengeMethods.includes("S256");

    const strategy = new OpenIdStrategy(
      {
        client,
        passReqToCallback: true,
        usePKCE: supportsPKCE,
        params: { prompt: "login", ...(supportsPKCE ? { code_challenge_method: "S256" } : {}) }
      },
      (_req: unknown, tokenSet: TokenSet, cb: (err: unknown, result?: unknown) => void) => {
        try {
          const claims = tokenSet.claims();
          const { email, externalId, firstName, lastName, groups } = extractOidcUserClaims(
            claims as unknown as Record<string, unknown>,
            oidcCfg.allowedEmailDomains ?? ""
          );

          oidcLogin({
            email,
            externalId,
            firstName,
            lastName,
            orgId: org?.id ?? resolvedOrgId,
            ip: requestContext.get("ip") || "",
            userAgent: requestContext.get("userAgent") || "",
            groups,
            callbackPort,
            manageGroupMemberships: oidcCfg.manageGroupMemberships
          })
            .then((loginResult) => {
              if (appCfg.OTEL_TELEMETRY_COLLECTION_ENABLED) {
                authAttemptCounter.add(1, {
                  "infisical.user.email": email,
                  "infisical.user.id": loginResult.userId,
                  "infisical.organization.id": resolvedOrgId,
                  "infisical.organization.name": org?.name ?? "",
                  "infisical.auth.method": AuthAttemptAuthMethod.OIDC,
                  "infisical.auth.result": AuthAttemptAuthResult.SUCCESS,
                  "client.address": requestContext.get(RequestContextKey.Ip),
                  "user_agent.original": requestContext.get(RequestContextKey.UserAgent)
                });
              }
              cb(null, loginResult);
            })
            .catch((error) => {
              if (appCfg.OTEL_TELEMETRY_COLLECTION_ENABLED) {
                authAttemptCounter.add(1, {
                  "infisical.user.email": email,
                  "infisical.organization.id": resolvedOrgId,
                  "infisical.organization.name": org?.name ?? "",
                  "infisical.auth.method": AuthAttemptAuthMethod.OIDC,
                  "infisical.auth.result": AuthAttemptAuthResult.FAILURE,
                  "client.address": requestContext.get(RequestContextKey.Ip),
                  "user_agent.original": requestContext.get(RequestContextKey.UserAgent)
                });
              }
              cb(error);
            });
        } catch (error) {
          cb(error);
        }
      }
    );

    return strategy;
  };

  const isOidcManageGroupMembershipsEnabled = async (orgId: string, actor: OrgServiceActor) => {
    await orgSsoPermission.ensureMember({
      actor: "user",
      actorId: actor.id,
      orgId,
      actorAuthMethod: actor.authMethod,
      actorOrgId: actor.orgId
    });

    const oidcConfig = await ssoOidcConfigDAL.findOne({ orgId, isActive: true });
    return Boolean(oidcConfig?.manageGroupMemberships);
  };

  return { oidcLogin, getOrgAuthStrategy, getOidc, updateOidcCfg, createOidcCfg, isOidcManageGroupMembershipsEnabled };
};
