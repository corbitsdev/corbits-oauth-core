import type { OAuthLoginHandle } from "./login";
import type { BaseTokens } from "./tokens";

/**
 * One live login per key, so a second attempt resumes the first.
 *
 * A loopback login is not a fresh resource each time it is asked for: the
 * authorization server only accepts one registered redirect_uri per client,
 * so every attempt for a provider contends for the same fixed port. Starting
 * over therefore costs more than it looks — the earlier attempt's authorize
 * page is already open in the operator's browser, bound to the state and
 * PKCE verifier that attempt generated, and a restart leaves that page
 * pointing at a listener that either no longer exists or no longer
 * recognises it. Resuming hands back the attempt already in flight, which is
 * what the page in front of them belongs to.
 *
 * An entry lives until its login settles — completed, failed, or aborted —
 * so nothing here needs sweeping; `completed` settling is the signal.
 */
export type LoginRegistry<TTokens extends BaseTokens = BaseTokens> = {
  /**
   * The live login for `key`, or a new one from `begin`. `resumed` says
   * which, so a caller can report the login it already knows about rather
   * than announcing a second one.
   *
   * `tag` identifies who the login belongs to. An entry is resumed only for
   * the same tag; a different one falls through to `begin`, which contends
   * for the port and fails the way it does today. One person's authorization
   * is not another's to continue.
   */
  startOrResume: (
    key: string,
    begin: () => Promise<OAuthLoginHandle<TTokens>>,
    opts?: { readonly tag?: string },
  ) => Promise<{
    readonly handle: OAuthLoginHandle<TTokens>;
    readonly resumed: boolean;
  }>;
  /** Whether a login is live under `key`. */
  has: (key: string) => boolean;
  /** Cancel the live login under `key`; false when there is none. */
  cancel: (key: string) => boolean;
};

export function createLoginRegistry<
  TTokens extends BaseTokens = BaseTokens,
>(): LoginRegistry<TTokens> {
  type Entry = {
    readonly handle: OAuthLoginHandle<TTokens>;
    readonly tag: string | undefined;
  };
  const live = new Map<string, Entry>();

  const drop = (key: string, entry: Entry): void => {
    if (live.get(key) === entry) live.delete(key);
  };

  return {
    async startOrResume(key, begin, opts) {
      const tag = opts?.tag;
      const existing = live.get(key);
      if (existing !== undefined && existing.tag === tag) {
        return { handle: existing.handle, resumed: true };
      }

      const handle = await begin();
      const entry: Entry = { handle, tag };
      live.set(key, entry);
      // Observing `completed` here is also what keeps a rejection from
      // landing unhandled when the caller only ever reads `authorizeUrl`.
      void handle.completed.then(
        () => {
          drop(key, entry);
        },
        () => {
          drop(key, entry);
        },
      );
      return { handle, resumed: false };
    },
    has(key) {
      return live.has(key);
    },
    cancel(key) {
      const entry = live.get(key);
      if (entry === undefined) return false;
      entry.handle.cancel();
      drop(key, entry);
      return true;
    },
  };
}
