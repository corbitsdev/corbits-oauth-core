// Token shape the exchange returns. Persistence is the host's job
// (Interchange `oauth_token` credential, OS vault, or otherwise).
//
// `expiresAt` is optional because RFC 6749 §5.1 makes `expires_in` RECOMMENDED,
// not required — a token endpoint may omit it, and this package refuses to
// guess a lifetime on the caller's behalf (see `client.ts`). `undefined`
// means "the server did not say"; `session.ts`'s `isTokenExpired` treats such
// a token as not expired until the server rejects it (see there for why).
export type BaseTokens = {
  access: string;
  refresh: string;
  expiresAt?: number;
};

export type AuthProfile<TTokens extends BaseTokens> = {
  name: string;
  tokens: TTokens;
  createdAt: number;
};
