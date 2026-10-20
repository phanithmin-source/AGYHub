export interface JwtClaims {
  iss?: string;
  sub?: string;
  aud?: string;
  exp?: number;
  iat?: number;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
  given_name?: string;
  family_name?: string;
  hd?: string;
  [key: string]: unknown;
}

/**
 * Decodes the JSON payload from a JWT without external libraries.
 * Handles URL-safe base64 and standard base64 padding.
 */
export function parseJwtPayload(jwt: string): JwtClaims | null {
  if (!jwt || typeof jwt !== 'string') return null;
  const parts = jwt.split('.');
  const p1 = parts[1];
  if (!p1) return null;
  try {
    let payload = p1.replace(/-/g, '+').replace(/_/g, '/');
    while (payload.length % 4 !== 0) payload += '=';
    const json = Buffer.from(payload, 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return null;
  }
}
