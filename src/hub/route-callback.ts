import { OAuthCallbackError, type CallbackServer } from "../index.js";
import { signedInHtml, signInFailedHtml } from "../provider.js";

type Outcome = { code: string } | { error: Error };

export type CallbackParams = {
  state: string | undefined;
  code: string | undefined;
  error: string | undefined;
};

export type CallbackResponse = { status: 200 | 400; html: string };

/**
 * Receives OAuth redirects on an HTTP route instead of a loopback listener.
 * Each login registers its state; the route hands the redirect to the login
 * that owns that state, so concurrent logins never share a port.
 */
export type RouteCallbacks = {
  start: (expectedState: string) => Promise<CallbackServer>;
  handle: (params: CallbackParams) => CallbackResponse;
};

export function createRouteCallbacks(): RouteCallbacks {
  const pending = new Map<string, (outcome: Outcome) => void>();

  return {
    start(expectedState) {
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
      pending.set(expectedState, finish);
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
    handle({ state, code, error }) {
      const finish = state === undefined ? undefined : pending.get(state);
      // Not a login in flight (or a stale one): refuse without touching any.
      if (finish === undefined)
        return { status: 400, html: signInFailedHtml("state mismatch") };
      const reason =
        error ??
        (code === undefined || code === "" ? "no code returned" : undefined);
      if (reason !== undefined || code === undefined) {
        finish({
          error: new OAuthCallbackError(
            `Authorization failed: ${reason ?? "no code returned"}`,
          ),
        });
        return {
          status: 400,
          html: signInFailedHtml(reason ?? "no code returned"),
        };
      }
      finish({ code });
      return { status: 200, html: signedInHtml };
    },
  };
}
