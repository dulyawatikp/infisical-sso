import type { Knex } from "knex";

import { TGenericPermission } from "@app/lib/types";
import { TOrgDALFactory } from "@app/services/org/org-dal";

export enum OidcConfigurationType {
  CUSTOM = "custom",
  DISCOVERY_URL = "discoveryURL"
}

export enum OidcJwtSignatureAlgorithm {
  RS256 = "RS256",
  HS256 = "HS256",
  RS512 = "RS512",
  EDDSA = "EdDSA"
}

export type TGetOidcCfgDTO =
  | ({
      type: "external";
      organizationId: string;
    } & TGenericPermission)
  | {
      type: "internal";
      organizationId: string;
    };

export type TCreateOidcCfgDTO = {
  issuer?: string;
  authorizationEndpoint?: string;
  discoveryURL?: string;
  configurationType: OidcConfigurationType;
  allowedEmailDomains?: string;
  jwksUri?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  clientId: string;
  clientSecret: string;
  isActive: boolean;
  organizationId: string;
  manageGroupMemberships: boolean;
  jwtSignatureAlgorithm: OidcJwtSignatureAlgorithm;
} & TGenericPermission;

export type TUpdateOidcCfgDTO = Partial<{
  issuer: string;
  authorizationEndpoint: string;
  allowedEmailDomains: string;
  discoveryURL: string;
  jwksUri: string;
  configurationType: OidcConfigurationType;
  tokenEndpoint: string;
  userinfoEndpoint: string;
  clientId: string;
  clientSecret: string;
  isActive: boolean;
  organizationId: string;
  manageGroupMemberships: boolean;
  jwtSignatureAlgorithm: OidcJwtSignatureAlgorithm;
}> &
  TGenericPermission;

export type TOidcLoginDTO = {
  externalId: string;
  email: string;
  firstName: string;
  lastName?: string;
  orgId: string;
  ip: string;
  userAgent: string;
  callbackPort?: string;
  groups?: string[];
  manageGroupMemberships?: boolean | null;
};

// Structural contracts for capabilities injected at wiring time.
// The service module must never import enterprise modules — see spec §4.2.

export type TOidcSsoGroupMembership = {
  groupId: string;
  groupName: string;
};

export type TOidcSsoGroup = {
  id: string;
  name: string;
  slug?: string;
  orgId?: string;
};

export type TOidcSsoEmailDomainDAL = {
  findOne: (filter: {
    domain?: string;
    orgId?: string;
    status?: string;
  }) => Promise<{ orgId: string; domain: string } | undefined>;
};

export type TOidcSsoOrgDAL = {
  findOne: (
    filter: Parameters<TOrgDALFactory["findOne"]>[0]
  ) => Promise<Awaited<ReturnType<TOrgDALFactory["findOne"]>> | undefined>;
  findOrgById: TOrgDALFactory["findOrgById"];
  findMembership(
    filter: Record<string, unknown>,
    opts?: Parameters<TOrgDALFactory["findMembership"]>[1]
  ): ReturnType<TOrgDALFactory["findMembership"]>;
  createMembership: TOrgDALFactory["createMembership"];
  updateMembershipById: TOrgDALFactory["updateMembershipById"];
  updateById: TOrgDALFactory["updateById"];
};

// userDAL / userAliasDAL are injected as community Pick types (see spec §4.2):
//   userDAL: Pick<TUserDALFactory, "create" | "findOne" | "findById" | "updateById" | "transaction">
//   userAliasDAL: Pick<TUserAliasDALFactory, "create" | "findOne">

export type TOidcSsoMembershipRoleDAL = {
  create: (data: { membershipId: string; role: string; customRoleId?: string | null }, tx?: Knex) => Promise<unknown>;
};

export type TOidcSsoOrgSsoPermission = {
  /** Resolves org permission for the actor and throws unless the action on subject "sso" is allowed. */
  assertCan: (
    perm: { actor: string; actorId: string; orgId: string; actorOrgId: string; actorAuthMethod: string | null },
    action: "read" | "create" | "edit"
  ) => Promise<void>;
  /** Resolves org permission for a USER actor without enforcement (parity: EE called getOrgPermission and discarded the result — throws only if the actor has no org membership). */
  ensureMember: (perm: {
    actor: string;
    actorId: string;
    orgId: string;
    actorOrgId: string;
    actorAuthMethod: string | null;
  }) => Promise<void>;
};

export type TOidcSsoGroupOps = {
  findByOrgId: (orgId: string) => Promise<TOidcSsoGroup[]>;
  findGroupMembershipsByUserIdInOrg: (userId: string, orgId: string) => Promise<TOidcSsoGroupMembership[]>;
  addUsersToGroupByUserIds: (arg: { userIds: string[]; group: TOidcSsoGroup }) => Promise<void>;
  removeUsersFromGroupByUserIds: (arg: { userIds: string[]; group: TOidcSsoGroup }) => Promise<void>;
};

export type TOidcSsoAuditLog = {
  createAuditLog: (arg: {
    actor: { type: "platform"; metadata: Record<string, never> };
    orgId: string;
    event: {
      type: "oidc-group-membership-mapping-assign-user" | "oidc-group-membership-mapping-remove-user";
      metadata: Record<string, unknown>;
    };
  }) => Promise<void>;
};

export type TOidcSsoSeatGuard = {
  /** Throws BadRequestError when the org member limit is reached. */
  throwOnMemberLimitReached: (orgId: string) => Promise<void>;
  updateSubscriptionOrgMemberCount: (orgId: string) => Promise<void>;
};
