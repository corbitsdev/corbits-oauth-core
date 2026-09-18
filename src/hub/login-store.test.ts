import { describe, expect, it } from "bun:test";

import { createLoginStore } from "./login-store";

const alice = { tenantId: "tenant_1", principalId: "principal_alice" };
const bob = { tenantId: "tenant_1", principalId: "principal_bob" };

function entry(expiresAt: number) {
  let cancelled = false;
  const abort = new AbortController();
  return {
    args: {
      ...alice,
      expiresAt,
      abort,
      cancel: () => {
        cancelled = true;
      },
    },
    abort,
    wasCancelled: () => cancelled,
  };
}

describe("createLoginStore", () => {
  it("releases an abandoned login's callback port once it expires", () => {
    const store = createLoginStore();
    const pending = entry(Date.now() + 1_000);
    const id = store.create(pending.args);

    expect(store.read(id, alice)?.status).toBe("pending");

    const afterExpiry = pending.args.expiresAt + 1;
    expect(store.read(id, alice, afterExpiry)).toBeUndefined();
    expect(pending.wasCancelled()).toBe(true);
    expect(pending.abort.signal.aborted).toBe(true);
  });

  it("hides a login from every principal but the one that started it", () => {
    const store = createLoginStore();
    const id = store.create(entry(Date.now() + 60_000).args);

    expect(store.read(id, bob)).toBeUndefined();
    expect(store.cancel(id, bob)).toBe(false);
    expect(store.read(id, alice)?.status).toBe("pending");
  });

  it("keeps the first terminal outcome when a cancel races a completion", () => {
    const store = createLoginStore();
    const id = store.create(entry(Date.now() + 60_000).args);

    store.settle(id, { status: "completed", credentialId: "credential_1" });
    expect(store.cancel(id, alice)).toBe(true);

    expect(store.read(id, alice)).toEqual({
      status: "completed",
      credentialId: "credential_1",
    });
  });
});
