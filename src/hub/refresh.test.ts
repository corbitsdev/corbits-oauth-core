import { describe, expect, it } from "bun:test";

import { OAuthTokenEndpointError, type BaseTokens } from "../index.js";
import {
  createRefreshTicker,
  refreshCredential,
  type OAuthRefreshStore,
} from "./refresh.js";
import type { OAuthLoginProviders } from "../provider.js";

const MINUTE = 60_000;

const oauthConfig = {
  clientId: "client",
  authorizeUrl: "https://auth.example.com/authorize",
  tokenUrl: "https://auth.example.com/token",
  redirectUri: "http://127.0.0.1:1455/callback",
  scopes: ["openid"],
  tokenTimeoutMs: 1_000,
};

/** A store over one in-memory row, standing in for the claimed Postgres row. */
function fakeStore(row: {
  id: string;
  tenantId: string;
  provider: string;
  expiresAt: Date | null;
  metadata?: Record<string, string>;
}) {
  const written: { tokens: BaseTokens; metadata: Record<string, string> }[] =
    [];
  const store: OAuthRefreshStore = {
    listDue: () =>
      Promise.resolve([
        { id: row.id, tenantId: row.tenantId, provider: row.provider },
      ]),
    claim: async (credentialId, refresh) => {
      expect(credentialId).toBe(row.id);
      const result = await refresh({
        id: row.id,
        tenantId: row.tenantId,
        expiresAt: row.expiresAt,
        refreshSecret: "refresh-token",
        metadata: row.metadata ?? {},
      });
      if (result === null) return false;
      written.push(result);
      return true;
    },
  };
  return { store, written };
}

function providers(
  refresh?: (refreshSecret: string, now: number) => Promise<BaseTokens>,
): OAuthLoginProviders {
  return {
    acme: {
      oauthConfig,
      exchange: () => Promise.reject(new Error("not used")),
      metadata: () => ({ accountId: "renewed" }),
      ...(refresh !== undefined ? { refresh } : {}),
    },
  };
}

/** One tick: the ticker runs one immediately on start. */
async function tickOnce(
  store: OAuthRefreshStore,
  opts: Parameters<typeof createRefreshTicker>[1],
) {
  const ticker = createRefreshTicker(store, opts);
  ticker.start();
  ticker.stop();
  await flush();
}

/** The tick start() fires is detached; let it settle. */
function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

describe("createRefreshTicker", () => {
  it("leaves a token that is not yet within the margin alone", async () => {
    const { store, written } = fakeStore({
      id: "cred_1",
      tenantId: "tenant_1",
      provider: "acme",
      expiresAt: new Date(Date.now() + 60 * MINUTE),
    });
    const refreshed: string[] = [];
    await tickOnce(store, {
      providers: providers(() => {
        refreshed.push("called");
        return Promise.resolve({ access: "a", refresh: "r" });
      }),
      marginMs: 10 * MINUTE,
      onRefreshed: ({ credentialId }) => {
        refreshed.push(credentialId);
      },
    });
    expect(refreshed).toEqual([]);
    expect(written).toEqual([]);
  });

  it("refreshes a token inside the margin and reports it for pushing", async () => {
    const { store, written } = fakeStore({
      id: "cred_1",
      tenantId: "tenant_1",
      provider: "acme",
      expiresAt: new Date(Date.now() + MINUTE),
      metadata: { accountId: "original", oauthProvider: "acme" },
    });
    const pushed: { tenantId: string; credentialId: string }[] = [];
    await tickOnce(store, {
      providers: providers((refreshSecret) =>
        Promise.resolve({
          access: `access-for-${refreshSecret}`,
          refresh: "next-refresh",
          expiresAt: Date.now() + 60 * MINUTE,
        }),
      ),
      marginMs: 10 * MINUTE,
      onRefreshed: (context) => {
        pushed.push(context);
      },
    });
    expect(written).toHaveLength(1);
    expect(written[0]?.tokens.access).toBe("access-for-refresh-token");
    // The provider's fresh metadata wins; what it does not restate survives.
    expect(written[0]?.metadata).toEqual({
      accountId: "renewed",
      oauthProvider: "acme",
    });
    expect(pushed).toEqual([{ tenantId: "tenant_1", credentialId: "cred_1" }]);
  });

  it("reports a failed refresh against its credential and keeps ticking", async () => {
    const { store, written } = fakeStore({
      id: "cred_1",
      tenantId: "tenant_1",
      provider: "acme",
      expiresAt: new Date(Date.now() + MINUTE),
    });
    const errors: { error: unknown; credentialId: string | undefined }[] = [];
    const ticker = createRefreshTicker(store, {
      providers: providers(() =>
        Promise.reject(new Error("the token endpoint said no")),
      ),
      marginMs: 10 * MINUTE,
      onError: (error, context) => {
        errors.push({ error, credentialId: context.credentialId });
      },
    });
    ticker.start();
    ticker.stop();
    await flush();
    expect(written).toEqual([]);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.credentialId).toBe("cred_1");
    expect(String(errors[0]?.error)).toContain("the token endpoint said no");
  });

  it("skips a provider that cannot refresh", async () => {
    const { store, written } = fakeStore({
      id: "cred_1",
      tenantId: "tenant_1",
      provider: "acme",
      expiresAt: new Date(Date.now() - MINUTE),
    });
    const errors: unknown[] = [];
    await tickOnce(store, {
      providers: providers(),
      marginMs: 10 * MINUTE,
      onError: (error) => {
        errors.push(error);
      },
    });
    expect(written).toEqual([]);
    expect(errors).toEqual([]);
  });
});

describe("refreshCredential", () => {
  it("reports reauth when the provider rejects the refresh token", async () => {
    const { store, written } = fakeStore({
      id: "cred_1",
      tenantId: "tenant_1",
      provider: "acme",
      expiresAt: new Date(Date.now() + MINUTE),
    });
    const result = await refreshCredential(
      store,
      {
        providers: providers(() =>
          Promise.reject(new OAuthTokenEndpointError(400, "invalid_grant")),
        ),
        marginMs: 10 * MINUTE,
      },
      { id: "cred_1", tenantId: "tenant_1", provider: "acme" },
    );
    expect(result).toEqual({
      ok: false,
      reason: "reauth",
      message: String(new OAuthTokenEndpointError(400, "invalid_grant")),
    });
    expect(written).toEqual([]);
  });

  it("reports error on a thrown failure that is not a provider rejection", async () => {
    const { store, written } = fakeStore({
      id: "cred_1",
      tenantId: "tenant_1",
      provider: "acme",
      expiresAt: new Date(Date.now() + MINUTE),
    });
    const result = await refreshCredential(
      store,
      {
        providers: providers(() => Promise.reject(new Error("network down"))),
        marginMs: 10 * MINUTE,
      },
      { id: "cred_1", tenantId: "tenant_1", provider: "acme" },
    );
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toBe("error");
    expect(written).toEqual([]);
  });
});

describe("createRefreshTicker start()", () => {
  it("performs a pass before the first interval tick", async () => {
    const { store, written } = fakeStore({
      id: "cred_1",
      tenantId: "tenant_1",
      provider: "acme",
      expiresAt: new Date(Date.now() + MINUTE),
    });
    const ticker = createRefreshTicker(store, {
      providers: providers((refreshSecret) =>
        Promise.resolve({
          access: `access-for-${refreshSecret}`,
          refresh: "next-refresh",
        }),
      ),
      marginMs: 10 * MINUTE,
      intervalMs: 10 * MINUTE,
    });
    ticker.start();
    // No timer tick has fired yet; the boot-time pass already ran.
    await flush();
    ticker.stop();
    expect(written).toHaveLength(1);
  });
});
