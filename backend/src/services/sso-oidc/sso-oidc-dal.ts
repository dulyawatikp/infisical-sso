import { TDbClient } from "@app/db";
import { TableName } from "@app/db/schemas";
import { ormify } from "@app/lib/knex";

export type TSsoOidcConfigDALFactory = ReturnType<typeof ssoOidcConfigDALFactory>;

export const ssoOidcConfigDALFactory = (db: TDbClient) => {
  const oidcConfigOrm = ormify(db, TableName.OidcConfig);

  return oidcConfigOrm;
};
