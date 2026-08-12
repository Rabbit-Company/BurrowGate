# Single Sign-On (OpenID Connect)

BurrowGate supports OpenID Connect (OIDC) single sign-on for two independent account systems. Each has its own configuration, its own identities, and its own on/off switch.

|                           | Dashboard accounts                          | Access list accounts                                        |
| ------------------------- | ------------------------------------------- | ----------------------------------------------------------- |
| Who signs in              | BurrowGate administrators/members           | End users of one protected site                             |
| Scope                     | One instance-wide identity provider         | One identity provider per site                              |
| Settings location         | Dashboard header → key icon                 | Site → Access List tab                                      |
| Settings API              | `GET/PUT /_burrowgate/api/admin/sso`        | `GET/PUT /_burrowgate/api/admin/access-list/sso?siteId=...` |
| Login route               | `/_burrowgate/admin/login/sso`              | `/_burrowgate/access/login/sso`                             |
| Callback route            | `/_burrowgate/admin/sso/callback`           | `/_burrowgate/access/sso/callback`                          |
| Back-channel logout route | `/_burrowgate/admin/sso/backchannel-logout` | `/_burrowgate/access/sso/backchannel-logout`                |

SAML is not supported. Configure a generic OIDC application at the identity provider (Authentik, Keycloak, Authelia, Microsoft ADFS, Azure/Entra ID, Okta, Duo, ...) and use its issuer URL, client ID, and client secret.

## How it works

1. BurrowGate fetches `<issuer>/.well-known/openid-configuration` to discover the authorization, token, and JWKS endpoints.
2. The login button starts an authorization-code flow with PKCE (S256), a random `state`, and a random `nonce`.
3. On callback, BurrowGate exchanges the code for an ID token, verifies its signature against the provider's published JWKS, and checks the issuer, audience, and nonce.
4. The verified `sub` (subject) claim is the durable identity key. On first login, BurrowGate looks for an existing local account with a matching email and links it; otherwise it provisions a new account using the ID token's `email` claim as the username.
5. A normal BurrowGate session is issued exactly as it would be after a password + two-factor login. SSO only replaces the credential-verification step.

The provider must return an `email` claim; BurrowGate has no other stable identifier to name new accounts.

## Provisioning

- New dashboard accounts are created with the **Member** role and no site or stream permissions. An administrator must grant access from the Users panel before the account can see anything.
- New access-list accounts are created and assigned to the site the user signed in through, the same as if an administrator had added them manually.
- SSO-provisioned accounts skip local two-factor enrollment (TOTP or WebAuthn). The identity provider is treated as the second factor.
- BurrowGate does not deprovision accounts automatically. Removing a user at the identity provider does not disable their BurrowGate account (disable it from the dashboard).

## Enforcement

Each scope has an independent **Require single sign-on** toggle. When enabled, the password form is hidden behind a "Use a local account instead" link rather than being removed:

- For the dashboard, this guarantees a break-glass path so a misconfigured identity provider can never lock out every administrator.
- For an access list, it means a user who knows a valid local password can still reach it directly, which is an intentional safety valve rather than a gap. Treat SSO enforcement as UX guidance, not an access-control boundary. Anyone who should not have a path in should not have a local password.

## Logout

Clicking Logout in BurrowGate only ends the local BurrowGate session. It does not sign the user out of the identity provider. This is the standard, expected behavior for SSO-integrated apps: if the identity provider's own browser session is still alive, clicking "Sign in with SSO" again will silently re-authenticate without a credential prompt. BurrowGate does not perform RP-Initiated (browser-redirect) logout.

### Back-channel logout

Both scopes expose a back-channel logout endpoint implementing the [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) specification. Configure it at the identity provider (in Authentik: the OAuth2 provider's **Logout URI** field, with **Logout Method** set to **Back-channel**) and BurrowGate will revoke the matching local session whenever the provider ends its session (on explicit logout, admin-side session revocation, user deactivation, or natural expiry). No browser round-trip is required.

How it's handled:

1. The identity provider `POST`s `application/x-www-form-urlencoded` with a `logout_token` field to the URI above.
2. BurrowGate verifies the token's signature against the provider's JWKS, checks `iss`/`aud`, requires the `http://schemas.openid.net/event/backchannel-logout` event claim, rejects any token carrying a `nonce` claim (a logout token must never look like an ID token), and requires a `jti` used at most once within a 5-minute freshness window (`iat` is also checked directly, so replay is bounded even after the `jti` cache entry expires).
3. If the token carries a `sid` (session ID) claim, BurrowGate revokes only the session that was created with that `sid` (captured from the original ID token at login time). This means signing out one device at the identity provider only signs out that device's BurrowGate session, not every session the account has.
4. If no session matches the `sid` (or the token has no `sid`), BurrowGate falls back to revoking every local session for that `sub`.

Front-channel logout (a hidden iframe loaded in the user's browser) is not supported, since it cannot fire for non-interactive triggers like session expiry or admin-side revocation (the exact case this feature exists for).

## Secrets and storage

- The client secret is encrypted at rest with the same AES-GCM key (`BG_MASTER_KEY` / `BG_MASTER_KEY_FILE`) used for TOTP secrets and TLS private keys.
- Settings are stored in the database (`admin_sso_settings`, `site_sso_settings`), not environment variables, so they can be changed from the dashboard without a restart.
