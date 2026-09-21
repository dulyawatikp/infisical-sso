# Own OIDC SSO — Community Reimplementation Design

**Date:** 2026-09-21
**Status:** Approved scope, awaiting spec review
**Repo:** infisical-sso (backend)

## 1. Context & Problem

The repo's `ee/` directory is licensed under the Infisical Enterprise License: production use requires a paid Infisical subscription (`backend/src/ee/LICENSE.md`). The instance currently uses the EE OIDC SSO implementation:

- `backend/src/ee/services/oidc/` — service (845 lines), DAL, types
- `backend/src/ee/routes/v1/oidc-router.ts` — routes (488 lines)

Goal: replace the EE OIDC SSO with an original, community-licensed implementation with **full behavioral parity**, so the frontend and API consumers keep working unchanged and production use no longer depends on EE-licensed code.

License rationale: the new code reuses **behavior, contracts, and schema** (API paths, DB tables, DTO shapes) — not EE source text. DB tables (`oidc_configs`), Zod schemas (`db/schemas/oidc-configs.ts`), and community libraries (`openid-client`, `@fastify/passport`) are not EE-licensed.

## 2. Decisions Locked

| Decision | Choice |
|---|---|
| Protocols | OIDC only (SAML/LDAP out of scope) |
| Feature depth | Full parity: config CRUD, login/callback, JWT validation, email-domain checks, group membership sync, audit logs, seat accounting |
| Placement | New community module `backend/src/services/sso-oidc/` |
| API paths | Identical (`/api/v1/sso/oidc/*`) |
| Approach | SSO module owns its logic; auxiliary platform capabilities (permissions, audit, groups, email-domain, license) injected via DI as structural interfaces |
| EE paywall gate (`plan.oidcSSO` check) | **Dropped** — commercial restriction, not behavior |
| Seat-limit guard (`throwOnPlanSeatLimitReached`) | **Kept** via injected dependency — functional parity |
| EE OIDC files | Remain on disk, **unwired** (no imports from production wiring). Deletion is a separate future cleanup |
| EE OIDC fork patches | After the new module is wired **and verified**, restore the locally-patched EE OIDC files (`oidc-config-service.ts`, `oidc-router.ts`) to their original pre-fork-modification state from git history — so no fork-derived patches remain under `ee/`. Files stay unwired; no functional impact. Restore fork-point versions (not current upstream main) because current upstream EE code depends on upstream-only APIs absent in this fork (e.g. `server.cookieSigningKey`, `oidc-config-fns`, `user-alias-fns` helpers) and would fail `type:check` |
| Parity target | **This fork's local `ee/` behavior** (what production runs today). Upstream-only EE changes are out of scope (see §8) |

### 2.1 Implementation boundary (clean-room discipline)

Implementers write code from **§5 Behavioral Spec only**. Do not open `ee/services/oidc/*` or `ee/routes/v1/oidc-router.ts` while implementing; do not carry over EE code text, comments, or idiosyncratic naming. API paths, DB schema, DTO shapes, and error semantics are contracts/facts — not protected expression — and are fully specified here. All code in the new module is original authorship.

## 3. Non-Goals

- No SAML or LDAP reimplementation.
- No rewrite of group management, audit logging, permission system, or email-domain verification — they are injected as-is.
- No DB migration (tables already exist).
- No frontend changes.
- No removal of other EE features.

## 4. Architecture

### 4.1 Module layout

```
backend/src/services/sso-oidc/
├── sso-oidc-dal.ts        # ormify(db, TableName.OidcConfig) — same shape as EE DAL
├── sso-oidc-types.ts      # DTOs, OIDCConfigurationType, OIDCJWTSignatureAlgorithm enums,
│                          # structural DI interfaces (TOidcSsoDeps)
├── sso-oidc-fns.ts        # pure helpers: issuer construction, claim extraction/validation,
│                          # org identifier resolution, group-diff computation
└── sso-oidc-service.ts    # factory: getOidc, createOidcCfg, updateOidcCfg, oidcLogin,
                           # getOrgAuthStrategy, isOidcManageGroupMembershipsEnabled
```

Router (community):

```
backend/src/server/routes/v1/oidc-sso-router.ts   # registerOidcSsoRouter
```

### 4.2 Dependency contract (structural interfaces)

The SSO module defines **its own minimal structural types** for injected deps; it never imports from `@app/ee/*`. Interfaces use method syntax (bivariant params) so the real services assign cleanly; a thin adapter lambda at the wiring site resolves any residual type friction (e.g., audit event unions).

| Dependency | Contract | Wired from |
|---|---|---|
| `oidcConfigDAL` | `findOne / update / create` (own DAL type) | new `sso-oidc-dal.ts` |
| `orgDAL` | structural: `findOne / findOrgById / findMembership / createMembership / updateMembershipById / updateById` | community org-dal instance |
| `userDAL / userAliasDAL / membershipRoleDAL` | `Pick`-shaped from community DAL types | community DALs (already instantiated) |
| `emailDomainDAL` | structural: `findOne({ domain, status?, orgId? })` | EE email-domain-dal instance |
| `orgSsoPermission` | adapter: `assertCan(perm, "read"\|"create"\|"edit")`, `ensureMember(perm)` — closes over EE permissionService + CASL enums | wiring adapter |
| `groupOps` | adapter: `findByOrgId(orgId)`, `findGroupMembershipsByUserIdInOrg(userId, orgId)`, `addUsersToGroupByUserIds({ userIds, group })`, `removeUsersFromGroupByUserIds({ userIds, group })` — closes over EE group-dal, user-group-membership-dal, group-fns and their supporting DALs (membershipGroupDAL, projectDAL, projectKeyDAL, projectBotDAL) | wiring adapter |
| `auditLog` | adapter: `createAuditLog({ actor, orgId, event })` with the two OIDC group event literals | wiring adapter over EE audit-log service |
| `seatGuard` | adapter: `throwOnMemberLimitReached(orgId)`, `updateSubscriptionOrgMemberCount(orgId)` — closes over EE license-fns/service | wiring adapter |
| `loginService` | `Pick<TAuthLoginFactory, "processProviderCallback">` | community `auth-login-service` |
| `tokenService` | `Pick<TAuthTokenServiceFactory, "createTokenForUser">` | community `auth-token-service` |
| `smtpService` | `Pick<TSmtpService, "sendMail", "verify">` | community `smtp-service` |
| `kmsService` | `Pick<TKmsServiceFactory, "createCipherPairWithDataKey">` | community `kms-service` |
| `telemetryService` | `Pick<TTelemetryServiceFactory, "sendPostHogEvents">` | community `telemetry-service` |

**Boundary rule (hard):** `services/sso-oidc/**` contains **zero** `@app/ee/*` imports — zero code imports, zero type imports. EE capabilities reach the module only through the four adapters (`orgSsoPermission`, `groupOps`, `auditLog`, `seatGuard`) plus structurally-typed DAL instances, all constructed in `server/routes/index.ts` (a community file that already imports EE today).

Shared community helpers reused directly (imported, not injected): `getConfig`, `getServerCfg` + `LoginMethod`, `blockLocalAndPrivateIpAddresses`, `matchesAllowedEmailDomain`, `sanitizeEmail`, `validateEmail`, `requestMemoize`, `authAttemptCounter`, error classes. Email-domain ownership helpers are the exception — reimplemented locally (see note below), not imported from EE.

Note on `verifyEmailDomainOwnership`/`findOrgIdByVerifiedDomain`: reimplemented locally (pure DAL logic, ~40 lines total). They depend only on `EmailDomainStatus.Verified` string value (`"verified"`) — defined as a local constant, not imported from EE.

### 4.3 Wiring changes

1. **`backend/src/server/routes/index.ts`**
   - Replace `oidcConfigServiceFactory` import (EE) with the new `ssoOidcServiceFactory`; instantiate with the injected deps (all already instantiated in this file today).
   - Keep decoration key `server.services.oidc` (type now `TSsoOidcServiceFactory`).
   - Register `registerOidcSsoRouter` under prefix `/sso/oidc` in the community route-registration section (alongside the existing `/sso` community router).
2. **`backend/src/ee/routes/v1/index.ts`** — remove only the OIDC registration line (`ssoRouter.register(registerOidcRouter, { prefix: "/oidc" })`). SAML registration untouched.
3. **`backend/src/@types/fastify.d.ts`** — repoint `TOidcConfigServiceFactory` import to the new module type.
4. **`backend/src/services/portal-sso/portal-sso-service.ts`** — repoint service-type import.
5. **`backend/src/services/org/org-service.ts`** — repoint `TOidcConfigDALFactory` import to the new DAL type (structurally identical).
6. **`backend/src/db/seeds/6-oidc-config.ts`** — repoint DAL import.
7. **`backend/CLAUDE.md`** — add note: OIDC SSO now lives in `services/sso-oidc/`; `ee/services/oidc` is legacy, unwired.

After this change, no production code path imports `ee/services/oidc` or `ee/routes/v1/oidc-router`. The only remaining EE runtime touchpoints are the injected platform services (permission, audit, groups, license, email-domain DAL) — identical to how every other community feature consumes them today.

## 5. Behavioral Spec (parity contract)

### 5.1 Routes — `registerOidcSsoRouter(server)`

Same middleware shape as EE router: router-scoped `Authenticator({ key: "oidc" })`, `fastifySession` with RedisStore (`prefix: "oidc-session:"`, `ttl: 600`), cookie `secure: HTTPS_ENABLED`, `sameSite: "lax"`, then `passport.initialize()` + `passport.secureSession()`.

| Route | Method | Auth | Rate limit | Behavior |
|---|---|---|---|---|
| `/login` | GET | none (public, rate-limited) | `authRateLimit` | Query `domain?`, `orgSlug?`, `callbackPort?`. Identifier resolution: `domain \|\| orgSlug` (domain takes precedence when both provided; neither → `BadRequestError`). `session.regenerate()`, store identifier/type/callbackPort in session, build strategy via `getOrgAuthStrategy`, respond through `passport.authenticate(strategy, { scope: "profile email openid" })`. Empty handler. |
| `/callback` | GET | none | — | Pre-validation: read session state, rebuild strategy, `passport.authenticate(strategy, { failureRedirect: "/api/v1/sso/oidc/login/error", session: false, failureMessage: true })`. Handler: destroy session; on `SESSION` result set `jid` cookie (refresh token; `httpOnly`, `path: /api`, `sameSite: strict`, `secure`), `addAuthOriginDomainCookie`, redirect `/login/select-organization` (+`callback_port`); on `SIGNUP_REQUIRED` redirect `/signup/sso?token=<signupToken>` (+`callback_port`); otherwise 500. |
| `/login/error` | GET | none | — | Return 500 `{ error: "Authentication error", details: session failure message ?? query }`; destroy session. |
| `/config` | GET | `verifyAuth([JWT, IDENTITY_ACCESS_TOKEN])` | `readLimit` | Query `organizationId`. Calls `getOidc({ type: "external", ... })`. Response: sanitized config + decrypted `clientId`, `clientSecret`. |
| `/config` | PATCH | same | `writeLimit` | Partial update body (same Zod shapes/transforms as EE: `allowedEmailDomains` comma-normalization, `.partial()` merge with `organizationId`). Calls `updateOidcCfg`; emits `SSOConfigured` telemetry (`action: "update"`). |
| `/config` | POST | same | `writeLimit` | Create body with `superRefine`: `CUSTOM` requires issuer + authorizationEndpoint + jwksUri + tokenEndpoint + userinfoEndpoint; `DISCOVERY_URL` requires discoveryURL. Calls `createOidcCfg`; emits `SSOConfigured` (`action: "create"`). |
| `/manage-group-memberships` | GET | `verifyAuth([JWT])` | — | Query `orgId`; returns `{ isEnabled }`. |

Schemas/descriptions reuse `OidcSSo` api-docs constants and `ApiDocsTags.OidcSso` so OpenAPI output stays identical.

### 5.2 Config service

**`getOidc(dto)`** — `type: "internal"`: fetch by orgId, 404 if missing, decrypt clientId/clientSecret with org KMS data key, return full config fields. `type: "external"`: additionally `getOrgPermission` (scope `ParentOrganization`) and require CASL action `read` on subject `sso`.

**`createOidcCfg(dto)`** — org lookup (404); EE plan gate intentionally skipped (§2); permission `create` on `sso`; reject `isActive` when `org.googleSsoAuthEnforced`; SSRF-check (blockLocalAndPrivateIpAddresses) each provided URL (discoveryURL, jwksUri, tokenEndpoint, userinfoEndpoint); encrypt clientId + clientSecret via `KmsDataKey.Organization` cipher pair; insert row.

**`updateOidcCfg(dto)`** — org lookup (404); EE plan gate intentionally skipped (§2); permission `edit` on `sso`; same google-enforcement and SSRF checks; encrypt credentials only when provided; update row with `lastUsed: null` reset; set org `authEnforced: false, scimEnabled: false`.

**`isOidcManageGroupMembershipsEnabled(orgId, actor)`** — permission check (USER actor, ParentOrganization scope), find active config, return `Boolean(manageGroupMemberships)`.

### 5.3 Login flow — `getOrgAuthStrategy(identifier, identifierType, callbackPort)`

1. Resolve org: `domain` → verified email-domain lookup (`findOrgIdByVerifiedDomain` logic); `orgSlug` → org by slug with `rootOrgId: null`. Unresolvable → `ForbiddenRequestError("Failed to authenticate with OIDC SSO")`.
2. Load config (internal `getOidc`); inactive/missing → same Forbidden error.
3. Build `openid-client` Issuer: `DISCOVERY_URL` → `Issuer.discover` (SSRF-checked); `CUSTOM` → manual Issuer from stored endpoints (each SSRF-checked; all five endpoints required else `BadRequestError("OIDC not configured correctly")`).
4. Client: `redirect_uris: [${SITE_URL}/api/v1/sso/oidc/callback]`, `id_token_signed_response_alg: config.jwtSignatureAlgorithm`.
5. PKCE: enable S256 when issuer metadata `code_challenge_methods_supported` includes it.
6. `OpenIdStrategy` with `passReqToCallback`, `params: { prompt: "login", ...(pkce) }`; verify callback: `claims.email` required (BadRequest), `matchesAllowedEmailDomain` enforced (Forbidden "Email not allowed."), name from `given_name || name` required (BadRequest), `groups` normalized (string → [string]); invoke `oidcLogin`; on success/failure emit OTEL `authAttemptCounter` (method OIDC, result SUCCESS/FAILURE) when telemetry collection enabled; forward result/error to passport callback.

### 5.4 `oidcLogin(dto)` — account resolution + provisioning

Order preserved exactly:

1. Admin gate: `serverCfg.enabledLoginMethods` set and excludes `OIDC` → Forbidden "Login with OIDC is disabled by administrator."
2. `verifyEmailDomainOwnership` logic (org must own a verified domain for the email).
3. `sanitizeEmail` + `validateEmail`.
4. Find user alias (`UserAliasType.OIDC`, externalId, orgId).
5. Org lookup via memoized `orgFindOrgById` (404 if missing).
6. **Alias exists**: transaction — load user, re-verify stored email domain, create invited org membership (default membership role) if absent. *Preserved quirk: no seat check on this branch (matches EE).*
7. **No alias**: transaction — find user by username=email; create user if new (`authMethods: []`, ghost false); create alias (emails: [email]); if no membership → **seat guard** (`throwOnPlanSeatLimitReached` equivalent) → create invited membership + default role. Emit `UserSignedUp` PostHog event (`signupMethod: "oidc"`) for new users.
8. **Group sync** (only when `manageGroupMemberships`): diff current org group memberships vs `groups` claim; add missing (via `addUsersToGroupByUserIds`) and remove stale (via `removeUsersFromGroupByUserIds`); audit events `oidc-group-membership-mapping-assign-user` / `oidc-group-membership-mapping-remove-user` with metadata (userId, userEmail, group lists, userGroupsClaim).
9. `licenseService.updateSubscriptionOrgMemberCount(orgId)`.
10. `oidcConfigDAL.update` → `lastUsed: new Date()`.
11. Unverified alias email: create `TOKEN_EMAIL_VERIFICATION` token (alias-scoped), send `EmailVerification` SMTP; SMTP failure → `OidcAuthError`.
12. `loginService.processProviderCallback({ user, authMethod: AuthMethod.OIDC, isEmailVerified, aliasId, ip, userAgent, organizationId, callbackPort })`; return `{ ...result, userId }`.

### 5.5 Errors

Same classes and messages as EE surface (community error classes only): `BadRequestError`, `ForbiddenRequestError`, `NotFoundError`, `OidcAuthError` (exists in community `lib/errors`).

## 6. Security Considerations

- **SSRF**: every IdP URL (config save + strategy build) passes `blockLocalAndPrivateIpAddresses`.
- **Secrets at rest**: clientId/clientSecret encrypted with org-scoped KMS data key; never logged; decrypted only in `getOidc` responses (auth-gated) and strategy construction.
- **JWT validation**: delegated to `openid-client` with pinned `id_token_signed_response_alg`; alg configurable (RS256 default).
- **PKCE** when IdP supports S256; `state` handled by openid-client/passport.
- **Session cookies**: `secure` per env, `sameSite: lax` (required for IdP redirects), 10-min Redis TTL, regenerate per attempt, destroy on completion.
- **Rate limits**: `authRateLimit` on login, read/write limits on config endpoints.
- **Authorization**: CASL `read/create/edit` on subject `sso`, org scope `ParentOrganization`, via injected permission service (identical enforcement as today).
- **SSRF-relevant note**: the `/login` identifier→org resolution only exposes orgs with verified domains or valid slugs; failures are uniform ("Failed to authenticate with OIDC SSO") to avoid org enumeration.

## 7. Testing

- **Unit** (`*.test.ts` next to source, Vitest):
  - `sso-oidc-fns`: claim extraction (missing email/name → error; groups string→array; email domain matching pass-through), org identifier resolution (domain vs slug, unverified domain → undefined), group diff (add/remove sets).
  - Config update body normalization (`allowedEmailDomains` transform) — covered by router schema test.
- **E2E** (`e2e-test/routes/`): config CRUD via `testServer.inject` with `jwtAuthToken` — create (CUSTOM validation failures, discovery variant), get (secrets decrypted), patch (lastUsed reset, org flags), manage-group-memberships flag. Auth failures (no JWT → 401).
- **Manual verification**: dev server; configure OIDC against a test IdP (Keycloak container); exercise `/login` → IdP → `/callback` → select-organization redirect; verify `jid` cookie; verify group sync + audit rows in DB.
- Gates: `make reviewable-api` clean.

## 8. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Subtle parity drift (quirks: no seat check on existing-alias branch, `lastUsed` reset on update, org flag resets) | Behavioral spec §5 is the contract; e2e asserts observable outputs; quirks documented here |
| Structural-typing friction injecting EE services | Method-syntax interfaces + adapter lambdas at wiring site only |
| `openid-client` v5 API knowledge (Issuer/Strategy/PKCE) | Same major version already in `package.json`; verify against package types during implementation |
| Double session/passport registration conflicts | EE OIDC router unwired in same change; new router self-contained (router-scoped plugins, distinct Authenticator key `oidc`, distinct Redis prefix `oidc-session:`) |
| Seed/type import breakage from repointing | Steps 3–6 in §4.3 are compile-time; `type:check` catches all |

## 9. License Validation (done 2026-09-21)

Local EE OIDC files diffed against upstream `Infisical/infisical` (clone of `main` @ `ccd5690`, 2026-09-20):

- `ee/LICENSE.md` — **byte-identical** to upstream. Terms: EE-directory code requires a paid subscription for production use; modifications remain Infisical's property. Fork-local edits do **not** relicense EE code.
- `oidc-config-types.ts`, `oidc-config-dal.ts` — byte-identical to upstream.
- `oidc-config-service.ts`, `oidc-router.ts` — this fork carries small local modifications (portal-SMO/`PORTAL_SSO_ENABLED` plan-gate bypass, session-secret source, telemetry shape, JWT/OAUTH route auth, and other portal fixes); all other content matches upstream. So the SSO code in production here **is EE-licensed upstream code** → the concern is valid; this design's replacement is the right move.

Conclusion: reimplementing the behavior as an original community module (§2.1 clean-room boundary) is permitted — EE protection covers *its* code text, not the OIDC protocol behavior or the API/schema contracts. Copying or transliterating EE source into the new module would NOT be permitted.

## 10. Upstream Divergence Note (out of scope)

Upstream `main` has evolved its EE OIDC well beyond this fork's base (~mid-2025): `user-alias-fns` helpers (stale-alias detection, shadow-account adoption, SSO profile sync), enforced-SSO email-verification skip, inactive-membership rejection, `getEnforcedIdentityLimit` seat accounting, extra audit event types (`OIDC_PROVISIONED_PLACEHOLDER_ADOPTED`), usage metering, alert-channel pruning on group removal, `recordAuthAttemptMetric`/`recordSsoConfigChangeMetric`, `OAUTH` auth mode on `/manage-group-memberships`, and a pure `oidc-config-fns.ts` (unit-tested upstream). This design deliberately targets **fork parity** (§2); adopting upstream improvements is a separate future decision. Only carry-over: implement group-diff logic as a pure function (`sso-oidc-fns.ts`) like upstream does — testable and matching this spec's §7 unit tests.

## 11. Open Items

None. All scope and placement decisions are locked (§2). Implementation sequencing goes to the writing-plans phase.