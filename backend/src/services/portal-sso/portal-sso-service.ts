import { TOidcConfigServiceFactory } from "@app/ee/services/oidc/oidc-config-service";
import { getConfig } from "@app/lib/config/env";
import { UnauthorizedError } from "@app/lib/errors";
import { TOrgDALFactory } from "@app/services/org/org-dal";

const PORTAL_COOKIE_NAME = "__Secure-next-auth.session-token";

type TPortalMeResponse = {
  sub: string;
  email: string;
  name: string;
  username: string;
  roles?: string[];
};

export type TPortalSsoServiceFactoryDep = {
  oidcConfigService: Pick<TOidcConfigServiceFactory, "oidcLogin">;
  orgDAL: Pick<TOrgDALFactory, "findOne">;
};

export type TPortalSsoServiceFactory = ReturnType<typeof portalSsoServiceFactory>;

export const portalSsoServiceFactory = ({ oidcConfigService, orgDAL }: TPortalSsoServiceFactoryDep) => {
  const relayPortalSession = async ({
    cookie,
    ip,
    userAgent
  }: {
    cookie: string;
    ip: string;
    userAgent: string;
  }) => {
    const appCfg = getConfig();

    const meUrl = `${appCfg.PORTAL_SSO_NAVBAR_API_HOST}${appCfg.PORTAL_SSO_NAVBAR_API_PATH}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    let response: Response;
    try {
      response = await fetch(meUrl, {
        headers: {
          Cookie: `${PORTAL_COOKIE_NAME}=${cookie}`
        },
        signal: controller.signal
      });
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new UnauthorizedError({ message: "Portal API timeout" });
      }
      throw new UnauthorizedError({ message: `Failed to connect to portal API: ${(err as Error).message}` });
    } finally {
      clearTimeout(timeout);
    }

    if (!response.ok) {
      throw new UnauthorizedError({
        message: `Portal session validation failed: ${response.status} ${response.statusText}`
      });
    }

    const portalUser = (await response.json()) as TPortalMeResponse;

    if (!portalUser.sub || !portalUser.email) {
      throw new UnauthorizedError({
        message: "Portal /api/me response missing required fields (sub, email)"
      });
    }

    const org = await orgDAL.findOne({});
    if (!org) {
      throw new UnauthorizedError({ message: "No organisation found for portal SSO" });
    }

    const nameParts = (portalUser.name ?? "").trim().split(/\s+/);
    const firstName = nameParts[0] ?? portalUser.username ?? portalUser.email.split("@")[0];
    const lastName = nameParts.length > 1 ? nameParts.slice(1).join(" ") : undefined;

    return oidcConfigService.oidcLogin({
      externalId: portalUser.sub,
      email: portalUser.email,
      firstName,
      lastName,
      orgId: org.id,
      ip,
      userAgent
    });
  };

  return { relayPortalSession };
};
