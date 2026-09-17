import { openInBrowser } from "./browser";
import type { CallbackServer } from "./callback-server";
import { generatePkce, generateState, type Pkce } from "./pkce";
import type { AuthProfile, BaseTokens } from "./tokens";

export type StagedOAuthProfile<TTokens extends BaseTokens> = {
  readonly profile: AuthProfile<TTokens>;
  readonly commit: () => Promise<void>;
};

export type OAuthLoginHandle<TTokens extends BaseTokens> = {
  authorizeUrl: string;
  completed: Promise<StagedOAuthProfile<TTokens>>;
  cancel: () => void;
};

export type StartOAuthLoginOptions = {
  profile: string;
  signal: AbortSignal;
  now?: () => number;
};

export type OAuthLoginDeps<TTokens extends BaseTokens> = {
  startCallbackServer: (expectedState: string) => Promise<CallbackServer>;
  buildAuthorizeUrl: (pkce: Pkce, state: string) => string;
  exchangeCode: (
    code: string,
    verifier: string,
    now: number,
  ) => Promise<TTokens>;
  saveProfile: (profile: {
    name: string;
    tokens: TTokens;
    createdAt: number;
  }) => Promise<void>;
  openInBrowser?: (url: string) => void;
};

/**
 * Drive the loopback PKCE login: start the callback server, build the
 * authorize URL, and return a handle. `completed` is lazy — the wait and
 * exchange start when the caller first observes it, so a rejection cannot
 * land as unhandled before anyone is listening. The server is closed when
 * that work finishes, fails, or is aborted.
 */
export async function startOAuthLogin<TTokens extends BaseTokens>(
  opts: StartOAuthLoginOptions,
  deps: OAuthLoginDeps<TTokens>,
): Promise<OAuthLoginHandle<TTokens>> {
  const now = opts.now ?? Date.now;
  const open = deps.openInBrowser ?? openInBrowser;
  const pkce = generatePkce();
  const state = generateState();
  const server = await deps.startCallbackServer(state);
  const authorizeUrl = deps.buildAuthorizeUrl(pkce, state);

  async function completeLogin(): Promise<StagedOAuthProfile<TTokens>> {
    try {
      const code = await server.waitForCode(opts.signal);
      const tokens = await deps.exchangeCode(code, pkce.verifier, now());
      const profile = { name: opts.profile, tokens, createdAt: now() };
      let committed: Promise<void> | undefined;
      return {
        profile,
        commit: () => {
          if (committed !== undefined) return committed;
          const attempt = deps.saveProfile(profile);
          committed = attempt;
          attempt.then(
            () => undefined,
            () => {
              if (committed === attempt) committed = undefined;
            },
          );
          return attempt;
        },
      };
    } finally {
      server.close();
    }
  }

  let completed: Promise<StagedOAuthProfile<TTokens>> | undefined;
  open(authorizeUrl);

  return {
    authorizeUrl,
    get completed(): Promise<StagedOAuthProfile<TTokens>> {
      completed ??= completeLogin();
      return completed;
    },
    cancel: () => server.close(),
  };
}
