import { createHash } from "node:crypto";
import { describe, expect, test } from "bun:test";

import { generatePkce } from "./index";

function base64urlDecode(value: string): Buffer {
  return Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

describe("PKCE generatePkce — challenge derivation", () => {
  test("the challenge is the base64url SHA-256 digest of the verifier", () => {
    // Load-bearing: an authorization server recomputes this exact transform
    // to check the verifier at token exchange. A wrong encoding (padding,
    // charset) is rejected by every real provider, not just this package.
    const { verifier, challenge, method } = generatePkce();
    expect(method).toBe("S256");
    expect(challenge).not.toMatch(/[+/=]/);
    const expected = createHash("sha256").update(verifier).digest();
    expect(base64urlDecode(challenge)).toEqual(expected);
  });
});
