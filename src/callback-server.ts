import { lookup } from "node:dns/promises";
import { createServer, type Server } from "node:http";
import { isIP } from "node:net";

function isLoopbackAddress(address: string): boolean {
  if (address === "::1") return true;
  if (isIP(address) !== 4) return false;
  return address.split(".")[0] === "127";
}

async function resolveLoopbackHost(host: string): Promise<string> {
  let addresses: string[];
  try {
    addresses =
      isIP(host) !== 0
        ? [host]
        : (await lookup(host, { all: true, verbatim: true })).map(
            ({ address }) => address,
          );
  } catch (cause) {
    throw new Error(
      `OAuth callback host could not be resolved; received ${host}.`,
      { cause },
    );
  }
  if (
    addresses.length === 0 ||
    addresses.some((address) => !isLoopbackAddress(address))
  ) {
    throw new Error(
      `OAuth callback host must resolve to loopback-only addresses; received ${host}.`,
    );
  }

  // Prefer IPv4 when both loopback families are available so localhost
  // callers use the same address family as the default callback host.
  const ipv4 = addresses.find((address) => isIP(address) === 4);
  if (ipv4 !== undefined) return ipv4;
  const first = addresses[0];
  if (first === undefined) {
    throw new Error(
      `OAuth callback host must resolve to loopback-only addresses; received ${host}.`,
    );
  }
  return first;
}

function isNonEmptyCode(value: string | null): value is string {
  return typeof value === "string" && value.length > 0;
}

export type CallbackServer = {
  /** The bound port; omitted by older callback server implementations. */
  port?: number;
  waitForCode: (signal: AbortSignal) => Promise<string>;
  close: () => void;
};

/**
 * Why a redirect was refused, as a code rather than prose.
 *
 * What a person should be told differs by product and by brand, and none of
 * it is this module's to decide; what the redirect actually was is. Callers
 * map these onto their own copy.
 *
 * - `state_mismatch`: the redirect carried a state this listener did not
 *   issue, so the authorization it belongs to is not the one being waited on.
 * - `provider_error`: the authorization server itself reported a failure;
 *   `providerError` carries its `error` parameter verbatim.
 * - `no_code`: the redirect arrived with neither an authorization code nor
 *   an error to explain its absence.
 */
export type CallbackFailureCode =
  | "state_mismatch"
  | "provider_error"
  | "no_code";

export type CallbackFailure = {
  readonly code: CallbackFailureCode;
  /** The authorization server's own `error` parameter, when it sent one. */
  readonly providerError?: string;
};

export type CallbackServerConfig = {
  port: number;
  host?: string;
  path: string;
  doneHtml: string;
  failedHtml: (failure: CallbackFailure) => string;
};

/** Why the wait for a code ended: a refused redirect, or the caller aborting. */
export type CallbackErrorCode = CallbackFailureCode | "aborted";

export class OAuthCallbackError extends Error {
  readonly code: CallbackErrorCode;

  constructor(code: CallbackErrorCode, message: string) {
    super(message);
    this.name = "OAuthCallbackError";
    this.code = code;
  }
}

export class OAuthCallbackPortInUseError extends Error {
  readonly port: number;
  readonly host?: string;

  constructor(port: number, host?: string) {
    super(
      host === undefined
        ? `Port ${String(port)} is already in use by another process.`
        : `Port ${String(port)} on ${host} is already in use by another process.`,
    );
    this.name = "OAuthCallbackPortInUseError";
    this.port = port;
    if (host !== undefined) this.host = host;
  }
}

export class OAuthCallbackAddressUnavailableError extends Error {
  readonly port: number;
  readonly host: string;

  constructor(port: number, host: string) {
    super(
      `Address ${host}:${String(port)} is not available on this machine; the callback server cannot bind it.`,
    );
    this.name = "OAuthCallbackAddressUnavailableError";
    this.port = port;
    this.host = host;
  }
}

/**
 * Start a fixed-port loopback-only server that receives an OAuth redirect.
 * The optional host may select a loopback hostname or address; routable and
 * wildcard hosts are rejected. The port is fixed because authorization
 * servers only accept the registered redirect_uri for the client. Loopback-only
 * enforcement is a cleartext safeguard: the redirect carrying the authorization
 * code travels as plain HTTP, so a routable or wildcard bind would expose it on
 * the network where passive capture defeats the state check. A bind
 * failure means the port is already in use (e.g. a concurrent login), not a
 * cue to pick another port.
 *
 * `expectedState` is bound before listen so a redirect that arrives the
 * instant the socket opens is CSRF-checked. The outcome is buffered: no
 * Promise is created until `waitForCode`, so an early failed redirect
 * cannot become an unhandled rejection.
 */
export async function startCallbackServer(
  expectedState: string,
  config: CallbackServerConfig,
): Promise<CallbackServer> {
  const host = config.host ?? "127.0.0.1";
  const bindHost = await resolveLoopbackHost(host);

  let outcome: { code: string } | { error: Error } | undefined;
  let waiter:
    | { resolve: (code: string) => void; reject: (err: Error) => void }
    | undefined;
  let wait: Promise<string> | undefined;
  let settled = false;

  const finish = (next: { code: string } | { error: Error }): void => {
    if (settled) return;
    settled = true;
    outcome = next;
    if (waiter === undefined) return;
    if ("error" in next) waiter.reject(next.error);
    else waiter.resolve(next.code);
  };

  const server: Server = createServer((req, res) => {
    const url = new URL(
      req.url ?? "/",
      `http://127.0.0.1:${String(config.port)}`,
    );
    if (url.pathname !== config.path) {
      res.statusCode = 404;
      res.end("Not found");
      return;
    }
    const code = url.searchParams.get("code");
    const error = url.searchParams.get("error");
    const state = url.searchParams.get("state");

    // Refused, but the wait goes on. The listener is on a fixed loopback
    // port anything on the machine can reach, and a redirect that is not
    // this login's -- a stale tab, or a page firing a crafted link -- says
    // nothing about the one being waited on. Ending the login here would let
    // any such request cancel a legitimate sign-in.
    if (state !== expectedState) {
      res.statusCode = 400;
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.end(config.failedHtml({ code: "state_mismatch" }));
      return;
    }

    const failure: CallbackFailure | undefined =
      error !== null
        ? { code: "provider_error", providerError: error }
        : isNonEmptyCode(code)
          ? undefined
          : { code: "no_code" };
    res.statusCode = failure === undefined ? 200 : 400;
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.end(
      failure === undefined ? config.doneHtml : config.failedHtml(failure),
    );

    if (failure !== undefined || !isNonEmptyCode(code)) {
      finish({
        error: new OAuthCallbackError(
          failure?.code ?? "no_code",
          `Authorization failed: ${failure?.providerError ?? "no code returned"}`,
        ),
      });
    } else {
      finish({ code });
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE")
        reject(new OAuthCallbackPortInUseError(config.port, host));
      else if (err.code === "EADDRNOTAVAIL")
        reject(new OAuthCallbackAddressUnavailableError(config.port, host));
      else reject(err);
    });
    server.listen(config.port, bindHost, resolve);
  });

  const address = server.address();
  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("OAuth callback server did not expose a bound port.");
  }

  return {
    port: address.port,
    waitForCode: (signal: AbortSignal) => {
      if (signal.aborted)
        finish({ error: new OAuthCallbackError("aborted", "aborted") });
      else
        signal.addEventListener(
          "abort",
          () => finish({ error: new OAuthCallbackError("aborted", "aborted") }),
          { once: true },
        );
      if (wait !== undefined) return wait;
      wait = new Promise<string>((resolve, reject) => {
        if (outcome !== undefined) {
          if ("error" in outcome) reject(outcome.error);
          else resolve(outcome.code);
          return;
        }
        waiter = { resolve, reject };
      });
      return wait;
    },
    // Closing the listener ends the wait: a caller that closes before a code
    // arrives has given up on it, and anything awaiting `waitForCode` must
    // hear that rather than wait for a redirect that can no longer land.
    // A no-op once a code (or a refusal) has already settled the outcome.
    close: () => {
      server.close();
      finish({
        error: new OAuthCallbackError(
          "aborted",
          "The callback server was closed before an authorization arrived.",
        ),
      });
    },
  };
}
