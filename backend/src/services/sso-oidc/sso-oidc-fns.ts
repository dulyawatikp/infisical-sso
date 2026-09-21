import { BadRequestError, ForbiddenRequestError } from "@app/lib/errors";
import { matchesAllowedEmailDomain } from "@app/lib/validator";

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

  if (!verified || verified.orgId !== orgId) {
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

  if (!matchesAllowedEmailDomain(email, allowedEmailDomains ?? "")) {
    throw new ForbiddenRequestError({ message: "Email not allowed." });
  }

  const firstName = (claims.given_name as string | undefined) ?? (claims.name as string | undefined);
  if (!firstName) {
    throw new BadRequestError({ message: "Invalid request. Missing name claim." });
  }

  const rawGroups = claims.groups;
  let groups: string[] = [];
  if (typeof rawGroups === "string") {
    groups = [rawGroups];
  } else if (Array.isArray(rawGroups)) {
    groups = rawGroups as string[];
  }

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
