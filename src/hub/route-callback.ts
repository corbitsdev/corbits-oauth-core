import {
  OAuthCallbackError,
  type CallbackFailure,
  type CallbackServer,
} from "../index.js";
import { signedInHtml, signInFailedHtml } from "../provider.js";

type Outcome = { code: string } | { error: Error };

export type CallbackParams = {
  state: string | undefined;
  code: string | undefined;
  error: string | undefined;
  errorDescription?: string | undefined;
  /** RFC 9207 issuer identifier, when the authorization server sends one. */
  iss?: string | undefined;
  /** Repeated query parameter. Refused before `code` or `error` is used. */
  repeatedParameter?: boolean;
};

export type CallbackResponse = { status: 200 | 400; html: string };

export type RouteCallbackOptions = {
  /**
   * Issuer recorded with this login's state (RFC 9207). A present `iss` must
   * match it exactly, whether or not the server advertised support. A missing
   * `iss` is refused only when `requireIssuer` is set.
   */
  expectedIssuer?: string;
  /** Set when metadata says `authorization_response_iss_parameter_supported`. */
  requireIssuer?: boolean;
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
  requireIssuer: boolean;
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
        requireIssuer: options?.requireIssuer === true,
      });
      return Promise.resolve({
        // Served by the hub's own listener; there is no loopback port.
        port: 0,
        waitForCode(signal) {
          const aborted = () =>
            finish({ error: new OAuthCallbackError("aborted", "aborted") });
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
    handle({ state, code, error, errorDescription, iss, repeatedParameter }) {
      const entry = state === undefined ? undefined : pending.get(state);
      // Not a login in flight (or a stale one): refuse without touching any.
      if (entry === undefined)
        return {
          status: 400,
          html: signInFailedHtml({ code: "state_mismatch" }),
        };
      const failed = (failure: CallbackFailure): CallbackResponse => {
        entry.finish({
          error: new OAuthCallbackError(
            failure.code,
            `Authorization failed: ${failure.providerError ?? failure.code}`,
          ),
        });
        return { status: 400, html: signInFailedHtml(failure) };
      };
      // RFC 9207: a present `iss` must be the issuer stored with this state.
      // A missing `iss` fails only when the server advertised the parameter.
      if (repeatedParameter === true) return failed({ code: "state_mismatch" });
      if (entry.expectedIssuer !== undefined) {
        if (iss === undefined) {
          if (entry.requireIssuer) return failed({ code: "state_mismatch" });
        } else if (iss !== entry.expectedIssuer) {
          return failed({ code: "state_mismatch" });
        }
      }
      if (error !== undefined)
        return failed(
          errorDescription === undefined
            ? { code: "provider_error", providerError: error }
            : {
                code: "provider_error",
                providerError: `${error}: ${errorDescription}`,
              },
        );
      if (code === undefined || code === "") return failed({ code: "no_code" });
      entry.finish({ code });
      return { status: 200, html: signedInHtml };
    },
  };
}
