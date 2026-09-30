import { OAuthCallbackError, type CallbackServer } from "../index.js";
import { signedInHtml, signInFailedHtml } from "../provider.js";

type Outcome = { code: string } | { error: Error };

export type CallbackParams = {
  state: string | undefined;
  code: string | undefined;
  error: string | undefined;
  errorDescription?: string | undefined;
  /** RFC 9207 issuer identifier, when the authorization server sends one. */
  iss?: string | undefined;
};

export type CallbackResponse = { status: 200 | 400; html: string };

export type RouteCallbackOptions = {
  /**
   * The issuer every redirect for this login must carry as `iss` (RFC 9207).
   * Set only when the server's metadata promises the parameter; a redirect
   * missing or mismatching it is then refused as a mix-up attack.
   */
  expectedIssuer?: string;
};

/**
 * Receives OAuth redirects on an HTTP route instead of a loopback listener.
 * Each login registers its state; the route hands the redirect to the login
 * that owns that state, so concurrent logins never share a port.
 */
export type RouteCallbacks = {
  start: (
    expectedState: string,
    options?: RouteCallbackOptions,
  ) => Promise<CallbackServer>;
  handle: (params: CallbackParams) => CallbackResponse;
};

type Pending = {
  finish: (outcome: Outcome) => void;
  expectedIssuer: string | undefined;
};

export function createRouteCallbacks(): RouteCallbacks {
  const pending = new Map<string, Pending>();

  return {
    start(expectedState, options) {
      let outcome: Outcome | undefined;
      let waiter:
        | { resolve: (code: string) => void; reject: (e: Error) => void }
        | undefined;
      let wait: Promise<string> | undefined;
      const finish = (next: Outcome): void => {
        if (outcome !== undefined) return;
        outcome = next;
        pending.delete(expectedState);
        if (waiter === undefined) return;
        if ("error" in next) waiter.reject(next.error);
        else waiter.resolve(next.code);
      };
      pending.set(expectedState, {
        finish,
        expectedIssuer: options?.expectedIssuer,
      });
      return Promise.resolve({
        // Served by the hub's own listener; there is no loopback port.
        port: 0,
        waitForCode(signal) {
          const aborted = () =>
            finish({ error: new OAuthCallbackError("aborted") });
          if (signal.aborted) aborted();
          else signal.addEventListener("abort", aborted, { once: true });
          wait ??= new Promise<string>((resolve, reject) => {
            if (outcome !== undefined) {
              if ("error" in outcome) reject(outcome.error);
              else resolve(outcome.code);
              return;
            }
            waiter = { resolve, reject };
          });
          return wait;
        },
        close: () => pending.delete(expectedState),
      });
    },
    handle({ state, code, error, errorDescription, iss }) {
      const entry = state === undefined ? undefined : pending.get(state);
      // Not a login in flight (or a stale one): refuse without touching any.
      if (entry === undefined)
        return { status: 400, html: signInFailedHtml("state mismatch") };
      const failed = (reason: string): CallbackResponse => {
        entry.finish({
          error: new OAuthCallbackError(`Authorization failed: ${reason}`),
        });
        return { status: 400, html: signInFailedHtml(reason) };
      };
      // RFC 9207 §2.4: a client that knows the server sends `iss` must
      // reject a response whose `iss` is absent or names another issuer.
      if (entry.expectedIssuer !== undefined && iss !== entry.expectedIssuer)
        return failed("issuer mismatch");
      if (error !== undefined)
        return failed(
          errorDescription === undefined
            ? error
            : `${error}: ${errorDescription}`,
        );
      if (code === undefined || code === "") return failed("no code returned");
      entry.finish({ code });
      return { status: 200, html: signedInHtml };
    },
  };
}
