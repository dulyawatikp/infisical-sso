import { Knex } from "knex";

import { OidcConfigurationType } from "@app/services/sso-oidc/sso-oidc-types";

import { TableName } from "../schemas";

const KEYCLOAK_ISSUER = process.env.PORTAL_SSO_KEYCLOAK_ISSUER || "https://keycloak.portal.ikp.rke2/realms/SSO";
const DISCOVERY_URL = `${KEYCLOAK_ISSUER}/.well-known/openid-configuration`;

export async function seed(knex: Knex): Promise<void> {
  const org = await knex(TableName.Organization).first();
  if (!org) return;

  const existing = await knex(TableName.OidcConfig).where({ orgId: org.id }).first();

  if (!existing) {
    await knex(TableName.OidcConfig).insert({
      orgId: org.id,
      isActive: true,
      configurationType: OidcConfigurationType.DISCOVERY_URL,
      discoveryURL: DISCOVERY_URL,
      issuer: KEYCLOAK_ISSUER,
      allowedEmailDomains: null,
      manageGroupMemberships: false,
      encryptedOidcClientId: Buffer.alloc(0),
      encryptedOidcClientSecret: Buffer.alloc(0)
    });
  } else {
    await knex(TableName.OidcConfig).where({ orgId: org.id }).update({
      isActive: true,
      configurationType: OidcConfigurationType.DISCOVERY_URL,
      discoveryURL: DISCOVERY_URL,
      issuer: KEYCLOAK_ISSUER,
      manageGroupMemberships: false
    });
  }

  const superAdmin = await knex(TableName.SuperAdmin).first();
  if (!superAdmin) return;

  const current: string[] = superAdmin.enabledLoginMethods ?? [];
  if (!current.includes("oidc")) {
    await knex(TableName.SuperAdmin)
      .where({ id: superAdmin.id })
      .update({ enabledLoginMethods: [...current, "oidc"] });
  }
}
