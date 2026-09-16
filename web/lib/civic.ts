// Civic Auth configuration shared by next.config.js, the server bridge and
// the sign-in UI. The client id is a public OAuth identifier, so it is safe
// to expose through NEXT_PUBLIC_. When it is unset the Civic button is hidden
// and the bridge provider refuses every sign-in.
export const CIVIC_CLIENT_ID = process.env.NEXT_PUBLIC_CIVIC_CLIENT_ID ?? ''
export const CIVIC_ENABLED = CIVIC_CLIENT_ID.length > 0

export const CIVIC_ROUTES = {
  loginInitUrl: '/api/civic/login',
  challengeUrl: '/api/civic/challenge',
  callbackUrl: '/api/civic/callback',
  refreshUrl: '/api/civic/refresh',
  userUrl: '/api/civic/user',
  logoutUrl: '/api/civic/logout',
  clearSessionUrl: '/api/civic/clearsession',
  logoutCallbackUrl: '/',
} as const
