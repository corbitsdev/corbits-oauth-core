import { describe, expect, test } from "bun:test";
import type { CredentialCipher } from "@intx/types";

import { writeOAuthTokens, type OAuthCredentialWriter } from "./credentials.js";

const cipher: CredentialCipher = {
  encrypt: (plaintext) => Promise.resolve(`sealed:${plaintext}`),
  decrypt: () => Promise.reject(new Error("unused")),
};

describe("writeOAuthTokens", () => {
  test("stores an access token without a refresh secret when none was issued", async () => {
    // Load-bearing: encrypting tokens.refresh unconditionally throws on a
    // valid access-token-only grant, so the login cannot be stored.
    const written: { refreshSecret: string | null; secret: string }[] = [];
    const db = {
      update: () => ({
        set: (values: { refreshSecret: string | null; secret: string }) => ({
          where: () => {
            written.push({
              refreshSecret: values.refreshSecret,
              secret: values.secret,
            });
            return Promise.resolve();
          },
        }),
      }),
    };
    await writeOAuthTokens({
      db: db as unknown as OAuthCredentialWriter,
      cipher,
      credentialId: "cred_1",
      tokens: { access: "access-only" },
      metadata: {},
    });
    expect(written).toEqual([
      { secret: "sealed:access-only", refreshSecret: null },
    ]);
  });
});
