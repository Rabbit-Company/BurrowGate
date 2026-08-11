# Single Sign-On (OpenID Connect)

BurrowGate supports OpenID Connect (OIDC) single sign-on for two independent account systems. Each has its own configuration, its own identities, and its own on/off switch.

|                   | Dashboard accounts                   | Access list accounts                                        |
| ----------------- | ------------------------------------ | ----------------------------------------------------------- |
| Who signs in      | BurrowGate administrators/members    | End users of one protected site                             |
| Scope             | One instance-wide identity provider  | One identity provider per site                              |
| Settings location | Dashboard header → key icon          | Site → Access List tab                                      |
| Settings API      | `GET/PUT /_burrowgate/api/admin/sso` | `GET/PUT /_burrowgate/api/admin/access-list/sso?siteId=...` |
| Login route       | `/_burrowgate/admin/login/sso`       | `/_burrowgate/access/login/sso`                             |
| Callback route    | `/_burrowgate/admin/sso/callback`    | `/_burrowgate/access/sso/callback`                          |

SAML is not supported. Configure a generic OIDC application at the identity provider (Authentik, Keycloak, Authelia, Microsoft ADFS, Azure/Entra ID, Okta, Duo, ...) and use its issuer URL, client ID, and client secret.

## How it works

1. BurrowGate fetches `<issuer>/.well-known/openid-configuration` to discover the authorization, token, and JWKS endpoints.
2. The login button starts an authorization-code flow with PKCE (S256), a random `state`, and a random `nonce`.
3. On callback, BurrowGate exchanges the code for an ID token, verifies its signature against the provider's published JWKS, and checks the issuer, audience, and nonce.
4. The verified `sub` (subject) claim is the durable identity key. On first login, BurrowGate looks for an existing local account with a matching email and links it; otherwise it provisions a new account using the ID token's `email` claim as the username.
5. A normal BurrowGate session is issued exactly as it would be after a password + TOTP login. SSO only replaces the credential-verification step.

The provider must return an `email` claim; BurrowGate has no other stable identifier to name new accounts.

## Provisioning

- New dashboard accounts are created with the **Member** role and no site or stream permissions. An administrator must grant access from the Users panel before the account can see anything.
- New access-list accounts are created and assigned to the site the user signed in through, the same as if an administrator had added them manually.
- SSO-provisioned accounts skip local TOTP enrollment; the identity provider is treated as the second factor.
- BurrowGate does not deprovision accounts automatically. Removing a user at the identity provider does not disable their BurrowGate account — disable it from the dashboard.

## Enforcement

Each scope has an independent **Require single sign-on** toggle. When enabled, the password form is hidden behind a "Use a local account instead" link rather than being removed:

- For the dashboard, this guarantees a break-glass path so a misconfigured identity provider can never lock out every administrator.
- For an access list, it means a user who knows a valid local password can still reach it directly, which is an intentional safety valve rather than a gap — treat SSO enforcement as UX guidance, not an access-control boundary. Anyone who should not have a path in should not have a local password.

## Secrets and storage

- The client secret is encrypted at rest with the same AES-GCM key (`BG_MASTER_KEY` / `BG_MASTER_KEY_FILE`) used for TOTP secrets and TLS private keys.
- Settings are stored in the database (`admin_sso_settings`, `site_sso_settings`), not environment variables, so they can be changed from the dashboard without a restart.
