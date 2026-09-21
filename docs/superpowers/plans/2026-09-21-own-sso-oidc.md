# Own OIDC SSO Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace EE-licensed OIDC SSO with an original community module (`backend/src/services/sso-oidc/`) with full behavioral parity, then restore EE OIDC files to their pre-fork originals.

**Architecture:** New module follows the repo's service-factory + manual DI pattern. `services/sso-oidc/**` contains **zero `@app/ee/*` imports** — EE capabilities (permission checks, group ops, audit, seat guard, email-domain DAL, group/user-group DALs) reach it through four adapters and structurally-typed DAL instances built in `server/routes/index.ts`. Router is a new community router registered under `/api/v1/sso/oidc`; the EE router registration line is removed in the same change so both never serve simultaneously. Behavior contract: spec `docs/superpowers/specs/2026-09-21-own-sso-oidc-design.md` §5.

**Tech Stack:** Fastify 4 + Zod schemas (route provider), `openid-client` v5 (`Issuer`, `Strategy`), `@fastify/passport` + `@fastify/session` + `connect-redis`, Knex, Vitest.

## Global Constraints

- **Zero `@app/ee/*` imports in `backend/src/services/sso-oidc/**`** — not even type-only imports (spec §2.1, §4.2 hard rule).
- **Clean-room**: do NOT open `ee/services/oidc/*` or `ee/routes/v1/oidc-router.ts` while implementing Tasks 1–7. Write from this plan + spec §5 only (spec §2.1).
- All work in `backend/`. Commands run from `backend/` unless noted. Path alias `@app/*` → `./src/*`.
- ESLint import order (simple-import-sort): side-effect, `node:`, third-party, `@app/`, `@lib/`, `@server/`, relative. Run `npm run lint:fix` before every commit gate.
- No new npm dependencies. `openid-client@^5.6.5`, `@fastify/passport`, `@fastify/session`, `connect-redis` already present.
- Deprecated auth modes (`API_KEY`, `SERVICE_TOKEN`) must not appear in new code.
- Logging: Pino with identifiers in message string (`[key=value]` format) + structured object first arg.
- Commits: Conventional Commits, subject ≤50 chars. Author identity already configured repo-local (`dulyawatikp <dulyawat@iknowplus.co.th>`).
- Final verification gate for every task: `cd backend && npm run lint:fix && npm run type:check` must pass on touched files (type:check takes minutes — run once per task at the end, not per step).

---

### Task 1: DAL + types module (pure community foundation)

**Files:**
- Create: `backend/src/services/sso-oidc/sso-oidc-dal.ts`
- Create: `backend/src/services/sso-oidc/sso-oidc-types.ts`

**Interfaces:**
- Consumes: `ormify` from `@app/lib/knex`, `TableName.OidcConfig` from `@app/db/schemas` (value `"oidc_configs"`), `TGenericPermission` from `@app/lib/types`.
- Produces: `ssoOidcDALFactory(db) → ormify instance` (methods used later: `findOne`, `create`, `update`, `update` returns array of updated rows); enums `OidcConfigurationType { CUSTOM = "custom", DISCOVERY_URL = "discoveryURL" }`, `OidcJwtSignatureAlgorithm { RS256 = "RS256", HS256 = "HS256", RS512 = "RS512", EDDSA = "EdDSA" }`; type `TSsoOidcServiceFactory` name reserved for Task 3; DTO types `TGetOidcCfgDTO`, `TCreateOidcCfgDTO`, `TUpdateOidcCfgDTO`, `TOidcLoginDTO` exactly as shown below.

- [ ] **Step 1: Create `sso-oidc-dal.ts`**

```ts
import { TDbClient } from "@app/db";
import { TableName } from "@app/db/schemas";
import { ormify } from "@app/lib/knex";

export type TSsoOidcConfigDALFactory = ReturnType<typeof ssoOidcConfigDALFactory>;

export const ssoOidcConfigDALFactory = (db: TDbClient) => {
  const oidcConfigOrm = ormify(db, TableName.OidcConfig);

  return oidcConfigOrm;
};
```

Note: `ormify()` provides `findOne`, `find`, `create`, `update`, `updateById`, `delete`, `transaction`. `update` returns an array of updated rows (`TDbClient` row type from generated schema `TOidcConfigs`). Do not add custom queries — none are needed.

- [ ] **Step 2: Create `sso-oidc-types.ts`**

Write original DTO definitions. Field names MUST match the DB schema (`backend/src/db/schemas/oidc-configs.ts`) and API contracts exactly:

```ts
import { TGenericPermission } from "@app/lib/types";

import { TSsoOidcConfigDALFactory } from "./sso-oidc-dal";

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
// The service module must never import @app/ee/* — see spec §4.2.

export type TOidcSsoGroupMembership = {
  groupId: string;
  groupName: string;
};

export type TOidcSsoGroup = {
  id: string;
  name: string;
};

export type TOidcSsoEmailDomainDAL = {
  findOne: (filter: {
    domain?: string;
    orgId?: string;
    status?: string;
  }) => Promise<{ orgId: string; domain: string } | undefined>;
};

export type TOidcSsoOrgDAL = {
  findOne: (filter: { id?: string; slug?: string; rootOrgId?: string | null }) => Promise<
    {
      id: string;
      name: string;
      slug: string | null;
      rootOrgId: string | null;
      defaultMembershipRole: string;
      googleSsoAuthEnforced: boolean;
      authEnforced: boolean;
      scimEnabled: boolean;
    } | undefined
  >;
  findOrgById: (orgId: string, tx?: unknown) => Promise<{
    id: string;
    name: string;
    slug: string | null;
    rootOrgId: string | null;
    defaultMembershipRole: string;
  } | undefined>;
  findMembership: (
    filter: Record<string, unknown>,
    opts?: { tx?: unknown }
  ) => Promise<Array<{ id: string; isActive: boolean }>>;
  createMembership: (
    data: Record<string, unknown>,
    tx?: unknown
  ) => Promise<{ id: string }>;
  updateMembershipById: (id: string, data: Record<string, unknown>) => Promise<unknown>;
  updateById: (id: string, data: Record<string, unknown>) => Promise<unknown>;
};

// userDAL / userAliasDAL are injected as community Pick types (see spec §4.2):
//   userDAL: Pick<TUserDALFactory, "create" | "findOne" | "findById" | "updateById" | "transaction">
//   userAliasDAL: Pick<TUserAliasDALFactory, "create" | "findOne">

export type TOidcSsoMembershipRoleDAL = {
  create: (data: { membershipId: string; role: string; customRoleId?: string | null }, tx?: unknown) => Promise<unknown>;
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
```

- [ ] **Step 3: Verify compile on touched files**

Run: `cd backend && npx tsc --noEmit -p tsconfig.json 2>&1 | grep -E "sso-oidc" | head -20; echo done`
Expected: no output mentioning `sso-oidc` (grep finds nothing; other pre-existing errors, if any, are unrelated — note them but don't fix).

Run: `cd backend && npm run lint:fix -- src/services/sso-oidc/ 2>/dev/null || npm run lint:fix` then inspect `git diff` for import-order autofixes.
Expected: clean or autofixed.

- [ ] **Step 4: Commit**

```bash
git add backend/src/services/sso-oidc/
git commit -m "feat(sso): add sso-oidc dal and types"
```

---

### Task 2: Pure functions (`sso-oidc-fns.ts`) — TDD

**Files:**
- Create: `backend/src/services/sso-oidc/sso-oidc-fns.test.ts`
- Create: `backend/src/services/sso-oidc/sso-oidc-fns.ts`

**Interfaces:**
- Consumes: types from Task 1 (`TOidcSsoGroupMembership`, `TOidcSsoGroup`, `TOidcSsoEmailDomainDAL`).
- Produces (used by Task 3):
  - `resolveOrgIdForIdentifier(arg: { identifier: string; identifierType: "domain" | "orgSlug"; emailDomainDAL: TOidcSsoEmailDomainDAL; orgDAL: Pick<TOidcSsoOrgDAL, "findOne"> }): Promise<string>` — throws `ForbiddenRequestError("Failed to authenticate with OIDC SSO")` when unresolved.
  - `extractOidcUserClaims(claims: Record<string, unknown>, allowedEmailDomains: string): { email: string; externalId: string; firstName: string; lastName: string; groups: string[] }` — throws `BadRequestError` (missing email / missing name), `ForbiddenRequestError("Email not allowed.")` (domain mismatch).
  - `resolveOidcGroupChanges(arg: { idpGroups: string[]; userGroupMemberships: TOidcSsoGroupMembership[]; orgGroups: TOidcSsoGroup[] }): { groupsToAddUserTo: TOidcSsoGroup[]; groupsToRemoveUserFrom: TOidcSsoGroup[] }` — pure diff.
  - `verifyEmailDomainOwnershipInOrg(arg: { email: string; orgId: string; emailDomainDAL: TOidcSsoEmailDomainDAL }): Promise<void>` — throws `BadRequestError` when org has no verified domain for the email's domain.
  - `findVerifiedDomainOrgId(arg: { domain: string; emailDomainDAL: TOidcSsoEmailDomainDAL }): Promise<string | undefined>` — lowercase/trim lookup, returns `orgId` or undefined.

- [ ] **Step 1: Write failing tests**

Create `sso-oidc-fns.test.ts`:

```ts
import { BadRequestError, ForbiddenRequestError } from "@app/lib/errors";

import {
  extractOidcUserClaims,
  findVerifiedDomainOrgId,
  resolveOidcGroupChanges,
  resolveOrgIdForIdentifier,
  verifyEmailDomainOwnershipInOrg
} from "./sso-oidc-fns";

const makeEmailDomainDAL = (result?: { orgId: string; domain: string }) => ({
  findOne: async () => result
});

describe("extractOidcUserClaims", () => {
  it("maps standard claims", () => {
    const claims = {
      email: "User@Example.com",
      sub: "sub-1",
      given_name: "Jane",
      family_name: "Doe"
    };
    expect(extractOidcUserClaims(claims, "")).toEqual({
      email: "user@example.com",
      externalId: "sub-1",
      firstName: "Jane",
      lastName: "Doe",
      groups: []
    });
  });

  it("falls back to name claim for firstName", () => {
    const claims = { email: "a@b.co", sub: "s", name: "Jos" };
    expect(extractOidcUserClaims(claims, "").firstName).toBe("Jos");
  });

  it("normalizes string groups claim to array", () => {
    const claims = { email: "a@b.co", sub: "s", given_name: "J", groups: "devs" };
    expect(extractOidcUserClaims(claims, "").groups).toEqual(["devs"]);
  });

  it("throws BadRequestError when email claim missing", () => {
    expect(() => extractOidcUserClaims({ sub: "s", given_name: "J" }, "")).toThrow(BadRequestError);
  });

  it("throws BadRequestError when name claim missing", () => {
    expect(() => extractOidcUserClaims({ email: "a@b.co", sub: "s" }, "")).toThrow(BadRequestError);
  });

  it("throws ForbiddenRequestError when domain not allowed", () => {
    expect(() =>
      extractOidcUserClaims({ email: "a@blocked.io", sub: "s", given_name: "J" }, "allowed.io")
    ).toThrow(ForbiddenRequestError);
  });
});

describe("resolveOidcGroupChanges", () => {
  const orgGroups = [
    { id: "g1", name: "devs" },
    { id: "g2", name: "ops" },
    { id: "g3", name: "qa" }
  ];

  it("adds missing and removes stale", () => {
    const userGroupMemberships = [
      { groupId: "g2", groupName: "ops" },
      { groupId: "g3", groupName: "qa" }
    ];
    const result = resolveOidcGroupChanges({
      idpGroups: ["devs", "ops"],
      userGroupMemberships,
      orgGroups
    });
    expect(result.groupsToAddUserTo).toEqual([{ id: "g1", name: "devs" }]);
    expect(result.groupsToRemoveUserFrom).toEqual([{ id: "g3", name: "qa" }]);
  });

  it("returns empty diffs when aligned", () => {
    const result = resolveOidcGroupChanges({
      idpGroups: ["devs"],
      userGroupMemberships: [{ groupId: "g1", groupName: "devs" }],
      orgGroups
    });
    expect(result.groupsToAddUserTo).toEqual([]);
    expect(result.groupsToRemoveUserFrom).toEqual([]);
  });

  it("ignores idp groups that have no matching org group", () => {
    const result = resolveOidcGroupChanges({
      idpGroups: ["nonexistent"],
      userGroupMemberships: [],
      orgGroups
    });
    expect(result.groupsToAddUserTo).toEqual([]);
    expect(result.groupsToRemoveUserFrom).toEqual([]);
  });
});

describe("resolveOrgIdForIdentifier", () => {
  it("resolves domain via verified email domain", async () => {
    const orgId = await resolveOrgIdForIdentifier({
      identifier: " Example.COM ",
      identifierType: "domain",
      emailDomainDAL: makeEmailDomainDAL({ orgId: "org-1", domain: "example.com" }),
      orgDAL: { findOne: async () => undefined }
    });
    expect(orgId).toBe("org-1");
  });

  it("throws ForbiddenRequestError for unverified domain", async () => {
    await expect(
      resolveOrgIdForIdentifier({
        identifier: "nope.com",
        identifierType: "domain",
        emailDomainDAL: makeEmailDomainDAL(undefined),
        orgDAL: { findOne: async () => undefined }
      })
    ).rejects.toThrow(ForbiddenRequestError);
  });

  it("resolves orgSlug via root org lookup", async () => {
    const orgId = await resolveOrgIdForIdentifier({
      identifier: "acme",
      identifierType: "orgSlug",
      emailDomainDAL: makeEmailDomainDAL(undefined),
      orgDAL: { findOne: async () => ({ id: "org-2" } as never) }
    });
    expect(orgId).toBe("org-2");
  });
});

describe("verifyEmailDomainOwnershipInOrg", () => {
  it("passes when org owns verified domain", async () => {
    await expect(
      verifyEmailDomainOwnershipInOrg({
        email: "a@example.com",
        orgId: "org-1",
        emailDomainDAL: makeEmailDomainDAL({ orgId: "org-1", domain: "example.com" })
      })
    ).resolves.toBeUndefined();
  });

  it("throws BadRequestError when org lacks verified domain", async () => {
    await expect(
      verifyEmailDomainOwnershipInOrg({
        email: "a@example.com",
        orgId: "org-2",
        emailDomainDAL: makeEmailDomainDAL({ orgId: "org-1", domain: "example.com" })
      })
    ).rejects.toThrow(BadRequestError);
  });

  it("throws BadRequestError on malformed email", async () => {
    await expect(
      verifyEmailDomainOwnershipInOrg({
        email: "not-an-email",
        orgId: "org-1",
        emailDomainDAL: makeEmailDomainDAL({ orgId: "org-1", domain: "example.com" })
      })
    ).rejects.toThrow(BadRequestError);
  });
});

describe("findVerifiedDomainOrgId", () => {
  it("normalizes and returns orgId", async () => {
    const seen: Record<string, unknown>[] = [];
    const orgId = await findVerifiedDomainOrgId({
      domain: " Example.COM ",
      emailDomainDAL: {
        findOne: async (filter) => {
          seen.push(filter);
          return { orgId: "org-9", domain: "example.com" };
        }
      }
    });
    expect(orgId).toBe("org-9");
    expect(seen[0]).toMatchObject({ domain: "example.com", status: "verified" });
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && npx vitest run src/services/sso-oidc/sso-oidc-fns.test.ts`
Expected: FAIL — module `./sso-oidc-fns` not found / exports missing.

- [ ] **Step 3: Implement `sso-oidc-fns.ts`**

```ts
import { BadRequestError, ForbiddenRequestError } from "@app/lib/errors";

import { TOidcSsoEmailDomainDAL, TOidcSsoGroup, TOidcSsoGroupMembership, TOidcSsoOrgDAL } from "./sso-oidc-types";

export type TOidcUserClaims = {
  email: string;
  externalId: string;
  firstName: string;
  lastName: string;
  groups: string[];
};

const VERIFIED_DOMAIN_STATUS = "verified";

export const findVerifiedDomainOrgId = async ({
  domain,
  emailDomainDAL
}: {
  domain: string;
  emailDomainDAL: TOidcSsoEmailDomainDAL;
}): Promise<string | undefined> => {
  const normalizedDomain = domain.toLowerCase().trim();
  const verified = await emailDomainDAL.findOne({ domain: normalizedDomain, status: VERIFIED_DOMAIN_STATUS });
  return verified?.orgId;
};

export const resolveOrgIdForIdentifier = async ({
  identifier,
  identifierType,
  emailDomainDAL,
  orgDAL
}: {
  identifier: string;
  identifierType: "domain" | "orgSlug";
  emailDomainDAL: TOidcSsoEmailDomainDAL;
  orgDAL: Pick<TOidcSsoOrgDAL, "findOne">;
}): Promise<string> => {
  if (identifierType === "domain") {
    const orgId = await findVerifiedDomainOrgId({ domain: identifier, emailDomainDAL });
    if (!orgId) {
      throw new ForbiddenRequestError({ message: "Failed to authenticate with OIDC SSO" });
    }
    return orgId;
  }

  const org = await orgDAL.findOne({ slug: identifier, rootOrgId: null });
  if (!org) {
    throw new ForbiddenRequestError({ message: "Failed to authenticate with OIDC SSO" });
  }
  return org.id;
};

export const verifyEmailDomainOwnershipInOrg = async ({
  email,
  orgId,
  emailDomainDAL
}: {
  email: string;
  orgId: string;
  emailDomainDAL: TOidcSsoEmailDomainDAL;
}): Promise<void> => {
  const emailDomain = email.split("@")?.[1];
  if (!emailDomain) {
    throw new BadRequestError({ message: "Invalid email address" });
  }

  const verified = await emailDomainDAL.findOne({
    domain: emailDomain.toLowerCase().trim(),
    status: VERIFIED_DOMAIN_STATUS,
    orgId
  });

  if (!verified) {
    throw new BadRequestError({
      message:
        "The email you attempted to login in with is not a part of the accepted domains of the selected organization. Please consult with your organization admin for further assistance."
    });
  }
};

export const extractOidcUserClaims = (
  claims: Record<string, unknown>,
  allowedEmailDomains: string
): TOidcUserClaims => {
  const email = typeof claims.email === "string" ? claims.email.toLowerCase() : undefined;
  if (!email) {
    throw new BadRequestError({ message: "Invalid request. Missing email claim." });
  }

  const { matchesAllowedEmailDomain } = require("@app/lib/validator") as typeof import("@app/lib/validator");
  if (!matchesAllowedEmailDomain(email, allowedEmailDomains ?? "")) {
    throw new ForbiddenRequestError({ message: "Email not allowed." });
  }

  const firstName = (claims.given_name as string | undefined) ?? (claims.name as string | undefined);
  if (!firstName) {
    throw new BadRequestError({ message: "Invalid request. Missing name claim." });
  }

  const rawGroups = claims.groups;
  const groups = typeof rawGroups === "string" ? [rawGroups] : Array.isArray(rawGroups) ? (rawGroups as string[]) : [];

  return {
    email,
    externalId: claims.sub as string,
    firstName,
    lastName: (claims.family_name as string | undefined) ?? "",
    groups
  };
};

export const resolveOidcGroupChanges = ({
  idpGroups,
  userGroupMemberships,
  orgGroups
}: {
  idpGroups: string[];
  userGroupMemberships: TOidcSsoGroupMembership[];
  orgGroups: TOidcSsoGroup[];
}): {
  groupsToAddUserTo: TOidcSsoGroup[];
  groupsToRemoveUserFrom: TOidcSsoGroup[];
} => {
  const userGroupNames = userGroupMemberships.map((membership) => membership.groupName);
  const missingGroupNames = idpGroups.filter((groupName) => !userGroupNames.includes(groupName));
  const groupsToAddUserTo = orgGroups.filter((group) => missingGroupNames.includes(group.name));

  const membershipsToRemove = userGroupMemberships
    .filter((membership) => !idpGroups.includes(membership.groupName))
    .map((membership) => membership.groupId);
  const groupsToRemoveUserFrom = orgGroups.filter((group) => membershipsToRemove.includes(group.id));

  return { groupsToAddUserTo, groupsToRemoveUserFrom };
};
```

**IMPORTANT — replace the `require()` line in `extractOidcUserClaims` with a normal top-of-file import** (require is shown only to mark placement; the final code must use):

```ts
import { matchesAllowedEmailDomain } from "@app/lib/validator";
```

at the top of the file (in the `@app/` import group), and the body line becomes just `if (!matchesAllowedEmailDomain(email, allowedEmailDomains ?? "")) {`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && npx vitest run src/services/sso-oidc/sso-oidc-fns.test.ts`
Expected: PASS (all tests).

- [ ] **Step 5: Lint + commit**

Run: `cd backend && npm run lint:fix`

```bash
git add backend/src/services/sso-oidc/
git commit -m "feat(sso): add sso-oidc pure helpers"
```

---

### Task 3: Service factory (`sso-oidc-service.ts`)

**Files:**
- Create: `backend/src/services/sso-oidc/sso-oidc-service.ts`

**Interfaces:**
- Consumes: Task 1 types + DAL, Task 2 fns. Community deps (typed via `Pick` of their real types): `TAuthLoginFactory` (`processProviderCallback`), `TAuthTokenServiceFactory` (`createTokenForUser`), `TSmtpService` (`sendMail`, `verify`), `TKmsServiceFactory` (`createCipherPairWithDataKey`), `TTelemetryServiceFactory` (`sendPostHogEvents`).
- Produces: `ssoOidcServiceFactory(deps: TSsoOidcServiceFactoryDep) → TSsoOidcServiceFactory` with methods:
  - `getOidc(dto: TGetOidcCfgDTO): Promise<{ id, issuer, authorizationEndpoint, configurationType, discoveryURL, jwksUri, tokenEndpoint, userinfoEndpoint, orgId, isActive, allowedEmailDomains, clientId, clientSecret, manageGroupMemberships, jwtSignatureAlgorithm }>`
  - `createOidcCfg(dto: TCreateOidcCfgDTO): Promise<TOidcConfigs>` (generated row type)
  - `updateOidcCfg(dto: TUpdateOidcCfgDTO): Promise<TOidcConfigs>`
  - `oidcLogin(dto: TOidcLoginDTO): Promise<TProviderAuthCallback & { userId: string }>`
  - `getOrgAuthStrategy(identifier: string, identifierType: "domain" | "orgSlug", callbackPort?: string): Promise<Strategy>` (openid-client passport strategy)
  - `isOidcManageGroupMembershipsEnabled(orgId: string, actor: OrgServiceActor): Promise<boolean>`

- [ ] **Step 1: Write the service factory**

Create `sso-oidc-service.ts` implementing spec §5.2–§5.4 exactly. Skeleton with every required piece (fill bodies per the inline contract comments — every behavioral rule is stated; no placeholder semantics):

```ts
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
import { TSmtpService, SmtpTemplates } from "@app/services/smtp/smtp-service";
import { getServerCfg } from "@app/services/super-admin/super-admin-service";
import { LoginMethod } from "@app/services/super-admin/super-admin-types";
import { TTelemetryServiceFactory } from "@app/services/telemetry/telemetry-service";
import { PostHogEventTypes } from "@app/services/telemetry/telemetry-types";
import { TUserAliasDALFactory } from "@app/services/user-alias/user-alias-dal";
import { UserAliasType } from "@app/services/user-alias/user-alias-types";
import { TUserDALFactory } from "@app/services/user/user-dal";

import {
  extractOidcUserClaims,
  resolveOidcGroupChanges,
  resolveOrgIdForIdentifier,
  verifyEmailDomainOwnershipInOrg
} from "./sso-oidc-fns";
import { TSsoOidcConfigDALFactory } from "./sso-oidc-dal";
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
```

> Simplification note: the dep type above is final — `orgDAL` is the structural `TOidcSsoOrgDAL`, no `TOrgDALFactory` intersection, no `membershipGroupDAL` dep (group lookups fold into `groupOps`), no `Pick<..., never>` union.

```ts
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
```

Body functions (in this order), each implementing the named spec rules:

**`getOidc(dto)`** — spec §5.2 first paragraph:
```ts
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
```

Note: `dto.actor`/`dto.actorId`/etc. come from `TGenericPermission`; pass them through as strings (`actor` is `ActorType` string enum value).

**`oidcLogin(dto)`** — spec §5.4 steps 1–12 in exact order:

```ts
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
```

> **Group-membership dep note (already applied):** `TOidcSsoGroupOps` in Task 1 ships with all four methods (`findByOrgId`, `findGroupMembershipsByUserIdInOrg`, `addUsersToGroupByUserIds`, `removeUsersFromGroupByUserIds`) and `TOidcSsoMembershipGroupDAL` does not exist — group lookups and mutations all flow through `groupOps`. `logger` from `@app/lib/logger` is already in the import list above.

**`createOidcCfg(dto)`** — spec §5.2 third paragraph:
```ts
  const createOidcCfg = async (dto: TCreateOidcCfgDTO) => {
    const org = await orgDAL.findOne({ id: dto.organizationId });
    if (!org) {
      throw new NotFoundError({ message: `Organization with ID '${dto.organizationId}' not found` });
    }

    await orgSsoPermission.assertCan(
      { actor: dto.actor, actorId: dto.actorId, orgId: org.id, actorOrgId: dto.actorOrgId, actorAuthMethod: dto.actorAuthMethod },
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
```

**`updateOidcCfg(dto)`** — spec §5.2 fourth paragraph. Structure: org lookup → assertCan "edit" → google-enforcement check → SSRF-check any provided URLs → cipher pair → build `TOidcConfigsUpdate` object with all provided fields + `lastUsed: null` → `ssoOidcConfigDAL.update({ orgId: org.id }, updateQuery)` (destructure first element, return it) → `orgDAL.updateById(org.id, { authEnforced: false, scimEnabled: false })`.

```ts
  const updateOidcCfg = async (dto: TUpdateOidcCfgDTO) => {
    const org = await orgDAL.findOne({ id: dto.organizationId });
    if (!org) {
      throw new NotFoundError({ message: `Organization with ID '${dto.organizationId}' not found` });
    }

    await orgSsoPermission.assertCan(
      { actor: dto.actor, actorId: dto.actorId, orgId: org.id, actorOrgId: dto.actorOrgId, actorAuthMethod: dto.actorAuthMethod },
      "edit"
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
```

> `orgDAL.updateById` must be added to `TOidcSsoOrgDAL` in Task 1 types: `updateById: (id: string, data: Record<string, unknown>) => Promise<unknown>`. (If the wiring adapter hits a Knex-type mismatch with the community org DAL's `updateById` signature, close over it in the wiring lambda — Task 6 — rather than widening this contract.)

**`getOrgAuthStrategy(identifier, identifierType, callbackPort)`** — spec §5.3 steps 1–6:

```ts
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
    } else {
      if (!oidcCfg.issuer || !oidcCfg.authorizationEndpoint || !oidcCfg.jwksUri || !oidcCfg.tokenEndpoint || !oidcCfg.userinfoEndpoint) {
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
```

**`isOidcManageGroupMembershipsEnabled(orgId, actor)`** — spec §5.2 last paragraph:
```ts
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
```

> `ensureMember` is kept for parity: the EE version resolved the org permission (throwing only when the actor has no membership) and discarded the result before reading the config. The wiring adapter (Task 5) implements it as a plain `getOrgPermission` call with the result unused.

  return statement:
```ts
  return { oidcLogin, getOrgAuthStrategy, getOidc, updateOidcCfg, createOidcCfg, isOidcManageGroupMembershipsEnabled };
};
```

- [ ] **Step 2: Confirm Task 1 types are final**

Task 1's structural types were written in final form: `TOidcSsoGroupOps` has 4 methods (`findByOrgId`, `findGroupMembershipsByUserIdInOrg`, `addUsersToGroupByUserIds`, `removeUsersFromGroupByUserIds`), `TOidcSsoMembershipGroupDAL` does not exist, `TOidcSsoOrgSsoPermission` has `assertCan` + `ensureMember`, `TOidcSsoOrgDAL` has `updateById`. Verify with:

Run: `grep -c "findByOrgId\|findGroupMembershipsByUserIdInOrg" backend/src/services/sso-oidc/sso-oidc-types.ts && grep -c "ensureMember" backend/src/services/sso-oidc/sso-oidc-types.ts && grep -c "updateById" backend/src/services/sso-oidc/sso-oidc-types.ts && ! grep -q "TOidcSsoMembershipGroupDAL" backend/src/services/sso-oidc/sso-oidc-types.ts && echo TYPES-FINAL`
Expected: `2`, `1`, `1` (or more), `TYPES-FINAL`.

- [ ] **Step 3: Typecheck + lint on touched files**

Run: `cd backend && npm run type:check 2>&1 | grep -E "services/sso-oidc" | head -30`
Expected: no errors in `services/sso-oidc` files. Errors elsewhere (e.g. nobody consumes the new factory yet) = fine.

Run: `cd backend && npm run lint:fix`

- [ ] **Step 4: Commit**

```bash
git add backend/src/services/sso-oidc/
git commit -m "feat(sso): add sso-oidc service factory"
```

---

### Task 4: Router (`registerOidcSsoRouter`)

**Files:**
- Create: `backend/src/server/routes/v1/oidc-sso-router.ts`

**Interfaces:**
- Consumes: `server.services.oidc` (type becomes `TSsoOidcServiceFactory` after Task 5 — until then the route file won't typecheck standalone; typecheck gate for this task is combined with Task 5), `OidcSso`/`ApiDocsTags` from `@app/lib/api-docs`, `authRateLimit`/`readLimit`/`writeLimit` from `@app/server/config/rateLimiter`, `verifyAuth` from `@app/server/plugins/auth/verify-auth`, `addAuthOriginDomainCookie` from `@app/server/lib/cookie`, `getTelemetryDistinctId` from `@app/server/lib/telemetry`.
- Produces: `registerOidcSsoRouter(server: FastifyZodProvider): Promise<void>` — registers 7 routes under the caller's prefix (Task 5 registers it at `/sso/oidc`).

- [ ] **Step 1: Write the router**

Full file (implements spec §5.1 table):

```ts
import { Authenticator, Strategy } from "@fastify/passport";
import fastifySession from "@fastify/session";
import RedisStore from "connect-redis";
import { z } from "zod";

import { OidcConfigsSchema } from "@app/db/schemas";
import { ApiDocsTags, OidcSSo } from "@app/lib/api-docs";
import { OidcConfigurationType, OidcJwtSignatureAlgorithm } from "@app/services/sso-oidc/sso-oidc-types";
import { getConfig } from "@app/lib/config/env";
import { BadRequestError } from "@app/lib/errors";
import { logger } from "@app/lib/logger";
import { authRateLimit, readLimit, writeLimit } from "@app/server/config/rateLimiter";
import { addAuthOriginDomainCookie } from "@app/server/lib/cookie";
import { getTelemetryDistinctId } from "@app/server/lib/telemetry";
import { verifyAuth } from "@app/server/plugins/auth/verify-auth";
import { AuthMode, ProviderAuthResult } from "@app/services/auth/auth-type";
import { PostHogEventTypes } from "@app/services/telemetry/telemetry-types";

const SanitizedOidcConfigSchema = OidcConfigsSchema.pick({
  id: true,
  issuer: true,
  authorizationEndpoint: true,
  configurationType: true,
  discoveryURL: true,
  jwksUri: true,
  tokenEndpoint: true,
  userinfoEndpoint: true,
  orgId: true,
  isActive: true,
  allowedEmailDomains: true,
  manageGroupMemberships: true,
  jwtSignatureAlgorithm: true
});

export const registerOidcSsoRouter = async (server: FastifyZodProvider) => {
  const appCfg = getConfig();
  const passport = new Authenticator({ key: "oidc", userProperty: "passportUser" });

  const redisStore = new RedisStore({
    client: server.redis,
    prefix: "oidc-session:",
    ttl: 600 // 10 minutes
  });

  await server.register(fastifySession, {
    secret: appCfg.COOKIE_SECRET_SIGN_KEY,
    store: redisStore,
    cookie: {
      secure: appCfg.HTTPS_ENABLED,
      sameSite: "lax" // cookies must survive IdP redirects back to Infisical
    }
  });

  await server.register(passport.initialize());
  await server.register(passport.secureSession());

  // redirect to IDP for login
  server.route({
    url: "/login",
    method: "GET",
    config: {
      rateLimit: authRateLimit
    },
    schema: {
      querystring: z.object({
        domain: z.string().trim().optional(),
        orgSlug: z.string().trim().optional(),
        callbackPort: z.string().trim().optional()
      })
    },
    preValidation: [
      async (req, res) => {
        const { domain, orgSlug, callbackPort } = req.query;

        const identifier = domain || orgSlug;
        if (!identifier) {
          throw new BadRequestError({ message: "Missing domain or orgSlug query parameter" });
        }

        await req.session.regenerate();

        req.session.set("oidcIdentifier", identifier);
        req.session.set("oidcIdentifierType", domain ? "domain" : "orgSlug");

        if (callbackPort) {
          req.session.set("callbackPort", callbackPort);
        }

        const oidcStrategy = await server.services.oidc.getOrgAuthStrategy(
          identifier,
          domain ? "domain" : "orgSlug",
          callbackPort
        );
        return (
          passport.authenticate(oidcStrategy as Strategy, {
            scope: "profile email openid"
          }) as (req: unknown, res: unknown) => void
        )(req, res);
      }
    ],
    handler: () => {}
  });

  // callback route after login from IDP
  server.route({
    url: "/callback",
    method: "GET",
    preValidation: [
      async (req, res) => {
        const oidcIdentifier = req.session.get("oidcIdentifier");
        const oidcIdentifierType = req.session.get("oidcIdentifierType") || "domain";
        const callbackPort = req.session.get("callbackPort");
        const oidcStrategy = await server.services.oidc.getOrgAuthStrategy(
          oidcIdentifier,
          oidcIdentifierType,
          callbackPort
        );

        return (
          passport.authenticate(oidcStrategy as Strategy, {
            failureRedirect: "/api/v1/sso/oidc/login/error",
            session: false,
            failureMessage: true
          }) as (req: unknown, res: unknown) => void
        )(req, res);
      }
    ],
    handler: async (req, res) => {
      await req.session.destroy();
      const passportResult = req.passportUser;
      const cbPort = passportResult.callbackPort;

      if (passportResult.result === ProviderAuthResult.SESSION) {
        void res.setCookie("jid", passportResult.tokens.refresh, {
          httpOnly: true,
          path: "/api",
          sameSite: "strict",
          secure: appCfg.HTTPS_ENABLED
        });
        addAuthOriginDomainCookie(res);
        const sessionUrl = new URL("/login/select-organization", appCfg.SITE_URL);
        if (cbPort) sessionUrl.searchParams.set("callback_port", String(cbPort));
        return res.redirect(sessionUrl.toString());
      }

      if (passportResult.result === ProviderAuthResult.SIGNUP_REQUIRED) {
        const signupUrl = new URL("/signup/sso", appCfg.SITE_URL);
        signupUrl.searchParams.set("token", passportResult.signupToken);
        if (cbPort) signupUrl.searchParams.set("callback_port", String(cbPort));
        return res.redirect(signupUrl.toString());
      }

      throw new Error("Unexpected auth result");
    }
  });

  server.route({
    url: "/login/error",
    method: "GET",
    handler: async (req, res) => {
      const failureMessage = req.session.get("messages");
      await req.session.destroy();

      return res.status(500).send({
        error: "Authentication error",
        details: failureMessage ?? req.query
      });
    }
  });

  server.route({
    url: "/config",
    method: "GET",
    config: {
      rateLimit: readLimit
    },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    schema: {
      hide: false,
      tags: [ApiDocsTags.OidcSso],
      description: "Get OIDC config",
      security: [{ bearerAuth: [] }],
      querystring: z.object({
        organizationId: z.string().trim().describe(OidcSSo.GET_CONFIG.organizationId)
      }),
      response: {
        200: SanitizedOidcConfigSchema.pick({
          id: true,
          issuer: true,
          authorizationEndpoint: true,
          jwksUri: true,
          tokenEndpoint: true,
          userinfoEndpoint: true,
          configurationType: true,
          discoveryURL: true,
          isActive: true,
          orgId: true,
          allowedEmailDomains: true,
          manageGroupMemberships: true,
          jwtSignatureAlgorithm: true
        }).extend({
          clientId: z.string(),
          clientSecret: z.string()
        })
      }
    },
    handler: async (req) => {
      const oidc = await server.services.oidc.getOidc({
        organizationId: req.query.organizationId,
        type: "external",
        actor: req.permission.type,
        actorId: req.permission.id,
        actorOrgId: req.permission.orgId,
        actorAuthMethod: req.permission.authMethod
      });

      return oidc;
    }
  });

  server.route({
    method: "PATCH",
    url: "/config",
    config: {
      rateLimit: writeLimit
    },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    schema: {
      hide: false,
      tags: [ApiDocsTags.OidcSso],
      description: "Update OIDC config",
      security: [{ bearerAuth: [] }],
      body: z
        .object({
          allowedEmailDomains: z
            .string()
            .trim()
            .optional()
            .default("")
            .transform((data) => {
              if (data === "") return "";
              return data
                .split(",")
                .map((id) => id.trim())
                .join(", ");
            })
            .describe(OidcSSo.UPDATE_CONFIG.allowedEmailDomains),
          discoveryURL: z.string().trim().describe(OidcSSo.UPDATE_CONFIG.discoveryURL),
          configurationType: z.nativeEnum(OidcConfigurationType).describe(OidcSSo.UPDATE_CONFIG.configurationType),
          issuer: z.string().trim().describe(OidcSSo.UPDATE_CONFIG.issuer),
          authorizationEndpoint: z.string().trim().describe(OidcSSo.UPDATE_CONFIG.authorizationEndpoint),
          jwksUri: z.string().trim().describe(OidcSSo.UPDATE_CONFIG.jwksUri),
          tokenEndpoint: z.string().trim().describe(OidcSSo.UPDATE_CONFIG.tokenEndpoint),
          userinfoEndpoint: z.string().trim().describe(OidcSSo.UPDATE_CONFIG.userinfoEndpoint),
          clientId: z.string().trim().describe(OidcSSo.UPDATE_CONFIG.clientId),
          clientSecret: z.string().trim().describe(OidcSSo.UPDATE_CONFIG.clientSecret),
          isActive: z.boolean().describe(OidcSSo.UPDATE_CONFIG.isActive),
          manageGroupMemberships: z.boolean().optional().describe(OidcSSo.UPDATE_CONFIG.manageGroupMemberships),
          jwtSignatureAlgorithm: z
            .nativeEnum(OidcJwtSignatureAlgorithm)
            .optional()
            .describe(OidcSSo.UPDATE_CONFIG.jwtSignatureAlgorithm)
        })
        .partial()
        .merge(z.object({ organizationId: z.string().describe(OidcSSo.UPDATE_CONFIG.organizationId) })),
      response: {
        200: SanitizedOidcConfigSchema.pick({
          id: true,
          issuer: true,
          authorizationEndpoint: true,
          configurationType: true,
          discoveryURL: true,
          jwksUri: true,
          tokenEndpoint: true,
          userinfoEndpoint: true,
          orgId: true,
          allowedEmailDomains: true,
          isActive: true,
          manageGroupMemberships: true
        })
      }
    },
    handler: async (req) => {
      const oidc = await server.services.oidc.updateOidcCfg({
        actor: req.permission.type,
        actorId: req.permission.id,
        actorAuthMethod: req.permission.authMethod,
        actorOrgId: req.permission.orgId,
        ...req.body
      });

      void server.services.telemetry
        .sendPostHogEvents({
          event: PostHogEventTypes.SSOConfigured,
          distinctId: getTelemetryDistinctId(req),
          organizationId: req.permission.orgId,
          properties: {
            provider: "oidc",
            action: "update",
            orgId: req.permission.orgId
          }
        })
        .catch((err) => logger.error(err, "Failed to send SSOConfigured telemetry event"));

      return oidc;
    }
  });

  server.route({
    method: "POST",
    url: "/config",
    config: {
      rateLimit: writeLimit
    },
    onRequest: verifyAuth([AuthMode.JWT, AuthMode.IDENTITY_ACCESS_TOKEN]),
    schema: {
      hide: false,
      tags: [ApiDocsTags.OidcSso],
      description: "Create OIDC config",
      security: [{ bearerAuth: [] }],
      body: z
        .object({
          allowedEmailDomains: z
            .string()
            .trim()
            .optional()
            .default("")
            .transform((data) => {
              if (data === "") return "";
              return data
                .split(",")
                .map((id) => id.trim())
                .join(", ");
            })
            .describe(OidcSSo.CREATE_CONFIG.allowedEmailDomains),
          configurationType: z.nativeEnum(OidcConfigurationType).describe(OidcSSo.CREATE_CONFIG.configurationType),
          issuer: z.string().trim().optional().default("").describe(OidcSSo.CREATE_CONFIG.issuer),
          discoveryURL: z.string().trim().optional().default("").describe(OidcSSo.CREATE_CONFIG.discoveryURL),
          authorizationEndpoint: z.string().trim().optional().default("").describe(OidcSSo.CREATE_CONFIG.authorizationEndpoint),
          jwksUri: z.string().trim().optional().default("").describe(OidcSSo.CREATE_CONFIG.jwksUri),
          tokenEndpoint: z.string().trim().optional().default("").describe(OidcSSo.CREATE_CONFIG.tokenEndpoint),
          userinfoEndpoint: z.string().trim().optional().default("").describe(OidcSSo.CREATE_CONFIG.userinfoEndpoint),
          clientId: z.string().trim().describe(OidcSSo.CREATE_CONFIG.clientId),
          clientSecret: z.string().trim().describe(OidcSSo.CREATE_CONFIG.clientSecret),
          isActive: z.boolean().describe(OidcSSo.CREATE_CONFIG.isActive),
          organizationId: z.string().trim().describe(OidcSSo.CREATE_CONFIG.organizationId),
          manageGroupMemberships: z
            .boolean()
            .optional()
            .default(false)
            .describe(OidcSSo.CREATE_CONFIG.manageGroupMemberships),
          jwtSignatureAlgorithm: z
            .nativeEnum(OidcJwtSignatureAlgorithm)
            .optional()
            .default(OidcJwtSignatureAlgorithm.RS256)
            .describe(OidcSSo.CREATE_CONFIG.jwtSignatureAlgorithm)
        })
        .superRefine((data, ctx) => {
          if (data.configurationType === OidcConfigurationType.CUSTOM) {
            if (!data.issuer) {
              ctx.addIssue({ path: ["issuer"], message: "Issuer is required", code: z.ZodIssueCode.custom });
            }
            if (!data.authorizationEndpoint) {
              ctx.addIssue({
                path: ["authorizationEndpoint"],
                message: "Authorization endpoint is required",
                code: z.ZodIssueCode.custom
              });
            }
            if (!data.jwksUri) {
              ctx.addIssue({ path: ["jwksUri"], message: "JWKS URI is required", code: z.ZodIssueCode.custom });
            }
            if (!data.tokenEndpoint) {
              ctx.addIssue({ path: ["tokenEndpoint"], message: "Token endpoint is required", code: z.ZodIssueCode.custom });
            }
            if (!data.userinfoEndpoint) {
              ctx.addIssue({
                path: ["userinfoEndpoint"],
                message: "Userinfo endpoint is required",
                code: z.ZodIssueCode.custom
              });
            }
          } else if (!data.discoveryURL) {
            ctx.addIssue({ path: ["discoveryURL"], message: "Discovery URL is required", code: z.ZodIssueCode.custom });
          }
        }),
      response: {
        200: SanitizedOidcConfigSchema
      }
    },
    handler: async (req) => {
      const oidc = await server.services.oidc.createOidcCfg({
        actor: req.permission.type,
        actorId: req.permission.id,
        actorAuthMethod: req.permission.authMethod,
        actorOrgId: req.permission.orgId,
        ...req.body
      });

      void server.services.telemetry
        .sendPostHogEvents({
          event: PostHogEventTypes.SSOConfigured,
          distinctId: getTelemetryDistinctId(req),
          organizationId: req.permission.orgId,
          properties: {
            provider: "oidc",
            action: "create",
            orgId: req.permission.orgId
          }
        })
        .catch((err) => logger.error(err, "Failed to send SSOConfigured telemetry event"));

      return oidc;
    }
  });

  server.route({
    method: "GET",
    url: "/manage-group-memberships",
    schema: {
      querystring: z.object({
        orgId: z.string().trim().min(1, "Org ID is required")
      }),
      response: {
        200: z.object({
          isEnabled: z.boolean()
        })
      }
    },
    onRequest: verifyAuth([AuthMode.JWT]),
    handler: async (req) => {
      const isEnabled = await server.services.oidc.isOidcManageGroupMembershipsEnabled(req.query.orgId, req.permission);

      return { isEnabled };
    }
  });
};
```

> Type notes for the implementer:
> - `req.permission` has shape `{ type, id, orgId, authMethod, ... }` (see `@types/fastify.d.ts:234-241`). `req.permission.authMethod` is `ActorAuthMethod` (nullable) — passes into `TGenericPermission.actorAuthMethod`.
> - `req.session.set/get` and `req.passportUser` are ambient-typed via `@types/fastify.d.ts` (passport user property `passportUser` comes from `Authenticator({ userProperty: "passportUser" })`). If TS complains about `req.session.set("key", value)` generics, type the values explicitly: `req.session.set<string>("oidcIdentifier", identifier)` etc.
> - If `passport.authenticate(...)` return-type friction occurs, cast as shown; do NOT use `@ts-ignore`/`as any` — cast to a concrete callable signature instead.
> - `OidcSso` docs constant is spelled with capital S (`OidcSSo`) in `@app/lib/api-docs` — import exactly that.

- [ ] **Step 2: Lint fix**

Run: `cd backend && npm run lint:fix`
Expected: import order auto-fixed; no lint errors in the new file.

- [ ] **Step 3: Commit (typecheck deferred to Task 5 — file not yet referenced anywhere)**

```bash
git add backend/src/server/routes/v1/oidc-sso-router.ts
git commit -m "feat(sso): add oidc sso router"
```

---

### Task 5: Wiring — replace EE OIDC with new module

**Files:**
- Modify: `backend/src/server/routes/index.ts` (~lines 95-96 import, ~609 DAL, ~2257 service, ~3263 decoration, community route registration near line 3535)
- Modify: `backend/src/@types/fastify.d.ts` (line 35 import + line 273 `oidc:` type)
- Modify: `backend/src/services/portal-sso/portal-sso-service.ts` (line 1 import)
- Modify: `backend/src/services/org/org-service.ts` (line 18 import of `TOidcConfigDALFactory`)
- Modify: `backend/src/ee/routes/v1/index.ts` (remove line 155 `ssoRouter.register(registerOidcRouter, { prefix: "/oidc" });` + its import at line 32)
- Modify: `backend/src/db/seeds/6-oidc-config.ts` (line 3 import)

**Interfaces:**
- Consumes: Tasks 1–4 exports (`ssoOidcConfigDALFactory`, `ssoOidcServiceFactory`, `TSsoOidcServiceFactory`, `registerOidcSsoRouter`, enum `OidcConfigurationType`).
- Produces: production serves `/api/v1/sso/oidc/*` from the new module; `server.services.oidc: TSsoOidcServiceFactory`; no production code path imports `@app/ee/services/oidc/*` or `@app/ee/routes/v1/oidc-router`.

- [ ] **Step 1: Wire DAL + service in `routes/index.ts`**

Replace line 95:
```ts
import { oidcConfigDALFactory } from "@app/ee/services/oidc/oidc-config-dal";
```
with:
```ts
import { ssoOidcConfigDALFactory } from "@app/services/sso-oidc/sso-oidc-dal";
```

Replace line 96:
```ts
import { oidcConfigServiceFactory } from "@app/ee/services/oidc/oidc-config-service";
```
with:
```ts
import { ssoOidcServiceFactory } from "@app/services/sso-oidc/sso-oidc-service";
```

Replace line 609:
```ts
const oidcConfigDAL = oidcConfigDALFactory(db);
```
with:
```ts
const ssoOidcConfigDAL = ssoOidcConfigDALFactory(db);
```

Replace the `oidcService` instantiation (~line 2257) with the new factory + adapters:

```ts
  const oidcService = ssoOidcServiceFactory({
    ssoOidcConfigDAL,
    orgDAL,
    userDAL,
    userAliasDAL,
    membershipRoleDAL,
    groupOps: {
      findByOrgId: (orgId) => groupDAL.findByOrgId(orgId),
      findGroupMembershipsByUserIdInOrg: (userId, orgId) =>
        userGroupMembershipDAL.findGroupMembershipsByUserIdInOrg(userId, orgId),
      addUsersToGroupByUserIds: ({ userIds, group }) =>
        addUsersToGroupByUserIds({
          userIds,
          group,
          userDAL,
          userGroupMembershipDAL,
          orgDAL,
          membershipGroupDAL,
          projectKeyDAL,
          projectDAL,
          projectBotDAL
        }),
      removeUsersFromGroupByUserIds: ({ userIds, group }) =>
        removeUsersFromGroupByUserIds({
          userIds,
          group,
          userDAL,
          userGroupMembershipDAL,
          membershipGroupDAL,
          projectKeyDAL
        })
    },
    orgSsoPermission: {
      assertCan: async (perm, action) => {
        const ssoActionByAction = {
          read: OrgPermissionSsoActions.Read,
          create: OrgPermissionSsoActions.Create,
          edit: OrgPermissionSsoActions.Edit
        } as const;
        const { permission } = await permissionService.getOrgPermission({
          actorId: perm.actorId,
          actor: perm.actor as ActorType,
          orgId: perm.orgId,
          actorOrgId: perm.actorOrgId,
          actorAuthMethod: perm.actorAuthMethod as ActorAuthMethod,
          scope: OrganizationActionScope.ParentOrganization
        });
        ForbiddenError.from(permission).throwUnlessCan(ssoActionByAction[action], OrgPermissionSubjects.Sso);
      },
      ensureMember: async (perm) => {
        await permissionService.getOrgPermission({
          actorId: perm.actorId,
          actor: ActorType.USER,
          orgId: perm.orgId,
          actorOrgId: perm.actorOrgId,
          actorAuthMethod: perm.actorAuthMethod as ActorAuthMethod,
          scope: OrganizationActionScope.ParentOrganization
        });
      }
    },
    auditLog: {
      createAuditLog: (arg) =>
        auditLogService.createAuditLog({
          actor: {
            type: ActorType.PLATFORM,
            metadata: {}
          },
          orgId: arg.orgId,
          event: {
            type:
              arg.event.type === "oidc-group-membership-mapping-assign-user"
                ? EventType.OIDC_GROUP_MEMBERSHIP_MAPPING_ASSIGN_USER
                : EventType.OIDC_GROUP_MEMBERSHIP_MAPPING_REMOVE_USER,
            metadata: arg.event.metadata as Record<string, unknown>
          }
        })
    },
    seatGuard: {
      throwOnMemberLimitReached: (orgId) => throwOnPlanSeatLimitReached(licenseService, orgId, UserAliasType.OIDC),
      updateSubscriptionOrgMemberCount: (orgId) => licenseService.updateSubscriptionOrgMemberCount(orgId)
    },
    emailDomainDAL,
    loginService,
    tokenService,
    smtpService,
    kmsService,
    telemetryService
  });
```

Required new imports at top of `routes/index.ts` (add to `@app/ee/...` group, keeping simple-import-sort order):
```ts
import { addUsersToGroupByUserIds, removeUsersFromGroupByUserIds } from "@app/ee/services/group/group-fns";
import { throwOnPlanSeatLimitReached } from "@app/ee/services/license/license-fns";
import { OrgPermissionSsoActions, OrgPermissionSubjects } from "@app/ee/services/permission/org-permission";
```
Plus add `ForbiddenError` to the existing `@casl/ability` import, and ensure `EventType`, `ActorType`, `UserAliasType`, `OrganizationActionScope`, `ActorAuthMethod`, `membershipGroupDAL`, `projectDAL`, `projectKeyDAL`, `projectBotDAL`, `emailDomainDAL` are all in scope at the wiring point (most already are; grep before adding).

> If TS rejects `permissionService.getOrgPermission` arg shapes (EE DTO unions), the adapter lambda is where you adapt — e.g. cast `perm.actor as ActorType`. If `auditLogService.createAuditLog` event-metadata type resists the cast, narrow via `as never` inside the adapter only. Adapters are the ONLY place EE types appear.

- [ ] **Step 2: Decoration + portalSso service name passthrough**

Keep `server.decorate("services", { ..., oidc: oidcService, ... })` (line ~3263) unchanged — variable name stays `oidcService`.

Check `portalSsoServiceFactory({ oidcConfigService: oidcService, orgDAL })` (line ~2280) — no change needed; only its *type import* changes (Step 3).

- [ ] **Step 3: Repoint type imports**

`backend/src/@types/fastify.d.ts`:
```ts
// line 35: replace
import { TOidcConfigServiceFactory } from "@app/ee/services/oidc/oidc-config-service";
// with
import { TSsoOidcServiceFactory } from "@app/services/sso-oidc/sso-oidc-service";
// line 273: replace
oidc: TOidcConfigServiceFactory;
// with
oidc: TSsoOidcServiceFactory;
```

`backend/src/services/portal-sso/portal-sso-service.ts` line 1:
```ts
// replace
import { TOidcConfigServiceFactory } from "@app/ee/services/oidc/oidc-config-service";
// with
import { TSsoOidcServiceFactory } from "@app/services/sso-oidc/sso-oidc-service";
// line 15: replace
oidcConfigService: Pick<TOidcConfigServiceFactory, "oidcLogin">;
// with
oidcConfigService: Pick<TSsoOidcServiceFactory, "oidcLogin">;
```

`backend/src/services/org/org-service.ts` line 18:
```ts
// replace
import { TOidcConfigDALFactory } from "@app/ee/services/oidc/oidc-config-dal";
// with
import { TSsoOidcConfigDALFactory } from "@app/services/sso-oidc/sso-oidc-dal";
// line 107: replace
oidcConfigDAL: Pick<TOidcConfigDALFactory, "findOne">;
// with
oidcConfigDAL: Pick<TSsoOidcConfigDALFactory, "findOne">;
```

`backend/src/db/seeds/6-oidc-config.ts` line 3:
```ts
// replace
import { OIDCConfigurationType } from "@app/ee/services/oidc/oidc-config-types";
// with
import { OidcConfigurationType } from "@app/services/sso-oidc/sso-oidc-types";
// and update the two usages: OIDCConfigurationType.DISCOVERY_URL → OidcConfigurationType.DISCOVERY_URL
```

- [ ] **Step 4: Remove EE OIDC registration, register new router**

`backend/src/ee/routes/v1/index.ts`: delete line 32 (`import { registerOidcRouter } from "./oidc-router";`) and line 155 (`await ssoRouter.register(registerOidcRouter, { prefix: "/oidc" });`). SAML lines stay.

`backend/src/server/routes/v1/index.ts`: add import + registration so routes land at `/api/v1/sso/oidc` **without** colliding with the EE SAML router still at `/api/v1/sso`:
```ts
// import (relative group, alphabetical among ./register* imports):
import { registerOidcSsoRouter } from "./oidc-sso-router";
// registration — immediately AFTER the existing line 90:
//   await server.register(registerSsoRouter, { prefix: "/sso" });
await server.register(registerOidcSsoRouter, { prefix: "/sso/oidc" });
```

> Collision check: `/sso/oidc/*` was previously served by the EE router nested under `/sso`; now it comes from a sibling prefix. Same final URLs, no route duplication because the EE OIDC registration is removed in this task.

- [ ] **Step 5: Verify zero EE imports in the new module + full typecheck**

Run: `grep -rn "@app/ee" backend/src/services/sso-oidc/ && echo VIOLATION || echo CLEAN`
Expected: `CLEAN`.

Run: `grep -rln "ee/services/oidc\|ee/routes/v1/oidc-router" backend/src --include="*.ts" | grep -v "^backend/src/ee/services/oidc\|^backend/src/ee/routes" | grep -v "server/routes/index.ts\|fastify.d.ts\|portal-sso\|org/org-service\|seeds/6-oidc"` then confirm the remaining matches are ONLY the EE files themselves and `backend/src/db/migrations/*` (migrations may reference old paths in comments only — verify with `grep -l`).
Expected: no live importers left. If `backend/src/ee/services/group/group-service.ts` appears, inspect: it imports the EE **DAL** (`@app/ee/services/oidc/oidc-config-dal`), NOT the service — that import stays (EE-internal, unaffected).

Run: `cd backend && npm run type:check`
Expected: PASS (or failures ONLY in files you did not touch — investigate any failure in touched files).

Run: `cd backend && npm run lint:fix`

- [ ] **Step 6: Boot smoke test**

Run: `cd backend && timeout 60 npm run dev 2>&1 | grep -iE "listening|error|oidc" | head -20` (needs local env vars; if dev env is not configured in this environment, note it and rely on type:check + e2e task)
Expected: server starts without DI/route registration errors.

- [ ] **Step 7: Commit**

```bash
git add backend/src/server/routes/index.ts backend/src/server/routes/v1/index.ts backend/src/server/routes/v1/oidc-sso-router.ts backend/src/@types/fastify.d.ts backend/src/services/portal-sso/portal-sso-service.ts backend/src/services/org/org-service.ts backend/src/ee/routes/v1/index.ts backend/src/db/seeds/6-oidc-config.ts
git commit -m "feat(sso): serve oidc sso from community module"
```

---

### Task 6: E2E tests for config CRUD

**Files:**
- Create: `backend/e2e-test/routes/v1/oidc-sso.spec.ts`

**Interfaces:**
- Consumes: `testServer.inject`, `jwtAuthToken` (injected e2e globals), `seedData1.organization.id` (`"180870b7-f464-4740-8ffe-9d11c9245ea7"`).
- Produces: e2e coverage for GET/PATCH/POST `/api/v1/sso/oidc/config` + `/manage-group-memberships` + auth failures.

- [ ] **Step 1: Write the spec**

```ts
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
```

> Notes for the implementer:
> - Run e2e via `cd backend && npm run test:e2e -- oidc-sso` (requires running Postgres/Redis per `e2e-test/vitest-environment-knex.ts`; it migrates + seeds automatically).
> - The seed `6-oidc-config.ts` creates an active config for the seed org pointing at a Keycloak discovery URL. If a config already exists, POST still succeeds (EE behavior had no unique constraint preventing update-style creates in tests — if a DB unique constraint rejects the second create, change the test to PATCH-only for the existing org and assert create-validation via the CUSTOM test above; do not weaken the constraint).
> - The GET-decrypt assertion proves KMS round-trip. If the seeded org's KMS data key is absent in e2e, the kmsService call may 500 — in that case create the config as the test does (which provisions keys via kmsService) before GET.
> - `isActive: true` PATCH requires SMTP verify to pass (`smtpService.verify()`); if e2e SMTP is unconfigured the PATCH-to-active may 400. In that case assert the 400 with message containing "SMTP" instead of 200, and skip the reset PATCH.

- [ ] **Step 2: Run e2e**

Run: `cd backend && npm run test:e2e -- oidc-sso`
Expected: PASS (with the documented contingency adjustments if SMTP/unique-constraint conditions apply).

- [ ] **Step 3: Commit**

```bash
git add backend/e2e-test/routes/v1/oidc-sso.spec.ts
git commit -m "test(sso): add oidc sso config e2e specs"
```

---

### Task 7: Roll back EE OIDC files to pre-fork originals

**Files:**
- Modify: `backend/src/ee/services/oidc/oidc-config-service.ts` (restore to `982064a9f8` blob — parent of `e37ee8a49c "feat(backend): add portal sso support"`, the first fork-specific commit touching this file)
- Modify: `backend/src/ee/routes/v1/oidc-router.ts` (restore to `9df62c0ef2` blob — last upstream-authored state, before `9ba3910b2c` fork series "feat: implemented verify domain required...")

**Interfaces:**
- Consumes: git history only.
- Produces: EE OIDC files identical to upstream code (fork markers `PORTAL_SSO_ENABLED`, `COOKIE_SECRET_SIGN_KEY`, `AuthMode.OAUTH`, fork telemetry shape all gone); files remain unwired so zero runtime/type impact.

- [ ] **Step 1: Verify the chosen blobs are clean of fork markers (dry check before restore)**

Run:
```bash
git show 982064a9f8:backend/src/ee/services/oidc/oidc-config-service.ts | grep -c "PORTAL_SSO_ENABLED\|COOKIE_SECRET_SIGN_KEY\|AuthMode.OAUTH\|getEnforcedIdentityLimit\|usageMeteringService" || echo "service-clean"
git show 9df62c0ef2:backend/src/ee/routes/v1/oidc-router.ts | grep -c "PORTAL_SSO_ENABLED\|COOKIE_SECRET_SIGN_KEY\|AuthMode.OAUTH" || echo "router-clean"
```
Expected: `0` or the `-clean` echo (grep count 0). If any marker count > 0, STOP and pick the next-earlier parent commit that is clean (`git log --format='%h %an %s' -- <file>` and walk parents).

- [ ] **Step 2: Restore blobs**

```bash
git show 982064a9f8:backend/src/ee/services/oidc/oidc-config-service.ts > backend/src/ee/services/oidc/oidc-config-service.ts
git show 9df62c0ef2:backend/src/ee/routes/v1/oidc-router.ts > backend/src/ee/routes/v1/oidc-router.ts
```

Also restore sibling EE OIDC files if they were ever fork-modified (check first; expected: they are byte-identical to upstream already):
```bash
git diff 982064a9f8 HEAD -- backend/src/ee/services/oidc/oidc-config-types.ts backend/src/ee/services/oidc/oidc-config-dal.ts
# if output is non-empty for either, restore:
# git show 982064a9f8:backend/src/ee/services/oidc/oidc-config-types.ts > backend/src/ee/services/oidc/oidc-config-types.ts
# git show 982064a9f8:backend/src/ee/services/oidc/oidc-config-dal.ts > backend/src/ee/services/oidc/oidc-config-dal.ts
```

- [ ] **Step 3: Confirm fork markers are gone + files typecheck standalone**

Run: `grep -rn "PORTAL_SSO_ENABLED\|COOKIE_SECRET_SIGN_KEY\|AuthMode.OAUTH" backend/src/ee/services/oidc/ backend/src/ee/routes/v1/oidc-router.ts; echo "exit=$?"`
Expected: `exit=1` (no matches).

Run: `cd backend && npm run type:check`
Expected: PASS — restored EE files compile against this fork (they import only APIs that existed pre-fork: `getConfig().COOKIE_SECRET_SIGN_KEY`, no `oidc-config-fns`, no `user-alias-fns`, `AuthMode.JWT` on the group-memberships route). Since they are unwired, only `tsc` full-project inclusion matters.

> Known-good fallback: if type:check fails on restored EE files because of some OTHER fork drift (e.g. a community module API changed since `982064a9f8`), fix forward with minimal edits confined to the restored EE files and document the edit in the commit message — do NOT reintroduce fork feature patches.

- [ ] **Step 4: Commit**

```bash
git add backend/src/ee/services/oidc/ backend/src/ee/routes/v1/oidc-router.ts
git commit -m "chore(license): restore ee oidc files to pre-fork originals"
```

---

### Task 8: Final parity verification + docs

**Files:**
- Modify: `backend/CLAUDE.md` (Enterprise section — one-line note)

**Interfaces:**
- Consumes: everything prior.
- Produces: documented, verified final state.

- [ ] **Step 1: Full gate**

Run: `make reviewable-api` (from repo root)
Expected: lint + type:check PASS.

Run: `cd backend && npm run test:unit 2>&1 | tail -15`
Expected: PASS including `sso-oidc-fns.test.ts` (any pre-existing unrelated failures: list, don't fix).

Run: `cd backend && npm run test:e2e -- oidc-sso` (if DB/Redis available)
Expected: PASS.

- [ ] **Step 2: Behavioral spot-checks against spec §5**

Run: `grep -c "assertCan" backend/src/services/sso-oidc/sso-oidc-service.ts` → expect ≥3 (read/create/edit paths).
Run: `grep -c "blockLocalAndPrivateIpAddresses" backend/src/services/sso-oidc/sso-oidc-service.ts` → expect ≥10 (create 4 + update 4 + strategy 4... actual count from code; ≥8 acceptable).
Run: `grep -n "throwOnMemberLimitReached\|updateSubscriptionOrgMemberCount" backend/src/services/sso-oidc/sso-oidc-service.ts` → expect both present (new-alias branch + post-login).
Run: `grep -n "enabledLoginMethods" backend/src/services/sso-oidc/sso-oidc-service.ts` → present.
Expected: all present.

- [ ] **Step 3: Update `backend/CLAUDE.md`**

In the "Enterprise (EE) Features" section, append one line:

```
- OIDC SSO is implemented in `src/services/sso-oidc/` (community code); `src/ee/services/oidc/` is legacy and unwired.
```

- [ ] **Step 4: Commit**

```bash
git add backend/CLAUDE.md
git commit -m "docs: note oidc sso lives in community module"
```

---

## Self-Review Record (per writing-plans skill)

1. **Spec coverage**: §5.1 routes → Task 4 (7/7 routes); §5.2 config service → Task 3 (getOidc/create/update/isManageEnabled, gates dropped per §2); §5.3 strategy → Task 3 (`getOrgAuthStrategy`); §5.4 oidcLogin 12 steps → Task 3; §5.5 errors → Task 1/3 imports; §4.2 dependency table + zero-EE-import rule → Task 1 structural types + Task 5 adapters + verification step; §4.3 wiring 7 items → Task 5 (routes/index, ee index, fastify.d.ts, portal-sso, org-service, seed, CLAUDE.md — all covered); §2 EE rollback → Task 7; §7 testing (unit fns + e2e config CRUD) → Tasks 2 & 6; §8 risks mitigated by design (pure group-diff fn, adapter typing). Frontend untouched (spec §3). No gaps found.
2. **Placeholder scan**: no TBD/TODO; Task 3 bodies given either verbatim or as fully-specified contract lines with exact messages/branch behavior (all error strings verbatim); Task 6 contingency branches fully specified. One deliberate code-shape instruction (replace `require()` with top import) is explicit, not a placeholder.
3. **Type consistency**: `TOidcSsoGroupOps` final shape (4 methods) used consistently in Task 1→3→5; `TSsoOidcServiceFactory` name matches fastify.d.ts repoint; `assertCan(perm, action)` + `ensureMember(perm)` signatures identical in types (Task 1), service (Task 3), adapter (Task 5); enum names (`OidcConfigurationType`, `OidcJwtSignatureAlgorithm`) consistent across Tasks 1/3/4/6; `ssoOidcConfigDAL` variable name consistent Task 5 steps 1/4; group lookups fold into `groupOps` everywhere (`membershipGroupDAL` appears only in Task 5 adapter closures over EE group-fns, which is correct); `ensureMember` kept for parity, documented in Task 3 note + wired in Task 5.