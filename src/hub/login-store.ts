import { randomUUID } from "node:crypto";

/** What a caller polling a login sees. Tokens never appear here. */
export type LoginState =
  | { readonly status: "pending" }
  | { readonly status: "completed"; readonly credentialId: string }
  | { readonly status: "failed"; readonly message: string }
  | { readonly status: "cancelled" };

type LoginEntry = {
  /** Who started it; only that principal may poll or cancel it. */
  readonly tenantId: string;
  readonly principalId: string;
  readonly expiresAt: number;
  readonly abort: AbortController;
  readonly cancel: () => void;
  state: LoginState;
};

export type LoginStore = {
  create: (entry: {
    tenantId: string;
    principalId: string;
    expiresAt: number;
    abort: AbortController;
    cancel: () => void;
  }) => string;
  settle: (id: string, state: LoginState) => void;
  read: (
    id: string,
    owner: { tenantId: string; principalId: string },
    now?: number,
  ) => LoginState | undefined;
  cancel: (
    id: string,
    owner: { tenantId: string; principalId: string },
  ) => boolean;
};

/**
 * In-process registry of logins in flight. It lives in the hub process
 * because the PKCE verifier and the loopback listener do too — a login is
 * not durable state and must not outlive the process that can complete it.
 * Entries expire so an abandoned login releases its fixed callback port
 * instead of blocking the next attempt forever.
 */
export function createLoginStore(): LoginStore {
  const logins = new Map<string, LoginEntry>();

  const sweep = (now: number): void => {
    for (const [id, entry] of logins) {
      if (now < entry.expiresAt) continue;
      if (entry.state.status === "pending") {
        entry.cancel();
        entry.abort.abort();
        entry.state = { status: "failed", message: "login expired" };
      }
      logins.delete(id);
    }
  };

  const owned = (
    id: string,
    owner: { tenantId: string; principalId: string },
  ): LoginEntry | undefined => {
    const entry = logins.get(id);
    if (entry === undefined) return undefined;
    return entry.tenantId === owner.tenantId &&
      entry.principalId === owner.principalId
      ? entry
      : undefined;
  };

  return {
    create(entry) {
      sweep(Date.now());
      const id = randomUUID();
      logins.set(id, { ...entry, state: { status: "pending" } });
      return id;
    },
    settle(id, state) {
      const entry = logins.get(id);
      if (entry === undefined || entry.state.status !== "pending") return;
      entry.state = state;
    },
    read(id, owner, now = Date.now()) {
      sweep(now);
      return owned(id, owner)?.state;
    },
    cancel(id, owner) {
      const entry = owned(id, owner);
      if (entry === undefined) return false;
      if (entry.state.status === "pending") {
        entry.cancel();
        entry.abort.abort();
        entry.state = { status: "cancelled" };
      }
      return true;
    },
  };
}
