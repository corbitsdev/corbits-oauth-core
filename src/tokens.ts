// Token shape the exchange returns. Persistence is the host's job
// (Interchange `oauth_token` credential, OS vault, or otherwise).
//
// `refresh` is optional because an authorization server may issue an access
// token and no refresh token (RFC 6749 §5.1). A blank value is the same
// absence: it is not a credential and must not be stored or redeemed.
//
// `expiresAt` is optional because RFC 6749 §5.1 makes `expires_in` RECOMMENDED,
// not required — a token endpoint may omit it, and this package refuses to
// guess a lifetime on the caller's behalf (see `client.ts`). `undefined`
// means "the server did not say"; `session.ts`'s `isTokenExpired` treats such
// a token as not expired until the server rejects it (see there for why).
export type BaseTokens = {
  access: string;
  refresh?: string;
  expiresAt?: number;
};

export type AuthProfile<TTokens extends BaseTokens> = {
  name: string;
  tokens: TTokens;
  createdAt: number;
};

/**
 * A refresh token the caller can redeem. Missing, null, and whitespace-only
 * values are absent — `""` and `" "` must not be stored or sent as if they
 * were a credential.
 */
export function presentRefreshToken(
  token: string | null | undefined,
): string | undefined {
  if (token == null) return undefined;
  if (token.trim().length === 0) return undefined;
  return token;
}
