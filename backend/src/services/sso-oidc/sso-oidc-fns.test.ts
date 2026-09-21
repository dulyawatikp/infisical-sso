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
    expect(() => extractOidcUserClaims({ email: "a@blocked.io", sub: "s", given_name: "J" }, "allowed.io")).toThrow(
      ForbiddenRequestError
    );
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
      orgDAL: { findOne: async () => ({ id: "org-2" }) as never }
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
