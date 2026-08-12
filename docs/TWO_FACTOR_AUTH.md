# Two-Factor Authentication (TOTP & WebAuthn)

BurrowGate supports two second-factor methods, additively, on both of its independent account systems:

- **TOTP** - a 6-digit code from an authenticator app (Ente Auth, Aegis, Google Authenticator, ...).
- **WebAuthn** - a hardware security key (YubiKey, ...) or a platform authenticator (Touch ID, Windows Hello).

|                         | Dashboard accounts                                               | Access list accounts                                             |
| ----------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------- |
| Who signs in            | BurrowGate administrators/members                                | End users of one protected site                                  |
| Enrollment trigger      | Bootstrap administrator always requires it (per-user thereafter) | The site's **Require 2FA** toggle, per user                      |
| Enroll/verify route     | `/_burrowgate/admin/login/enroll` \| `.../login/verify`          | `/_burrowgate/access/login/enroll` \| `.../login/verify`         |
| Self-service management | Dashboard header -> account panel                                | Not available. re-enrollment happens inline at next login        |
| Admin reset action      | Users panel -> **Reset 2FA**                                     | Site -> Access List tab -> **Reset 2FA** (per site, see below)   |
| Recovery codes          | Yes, generated on first enrollment of either method              | Not issued (access-list accounts have no recovery-code fallback) |

## How it works

1. After a correct password, BurrowGate checks whether the account has a TOTP secret or any WebAuthn credential. If it has neither, the user is sent to the **enroll** flow and can set up either method to satisfy the requirement. If it has at least one, the user is sent to the **verify** flow and offered whichever method(s) are already enrolled.
2. WebAuthn registration and authentication both use a server-generated, single-use challenge stored server-side against the in-progress login (the same pending-login/pending-session state TOTP already used) - never trusted from the client, and it cannot be replayed.
3. A successful verification (either method) completes the login and issues a normal BurrowGate session.

## WebAuthn credential scoping

A WebAuthn credential is cryptographically bound to the origin (hostname) it was registered on - this is part of the WebAuthn specification, not a BurrowGate limitation.

- **Dashboard**: the relying-party ID is derived from the hostname used to reach `/_burrowgate/admin` on each request. An administrator who reaches the dashboard through more than one hostname needs to register a key separately per hostname; TOTP has no such restriction and remains a hostname-independent fallback.
- **Access lists**: credentials are stored per `(user, site)`. A user assigned to multiple sites with different domains registers a security key separately on each site's login page - a key registered on `orders.example.com` will not be offered when signing in to `support.example.com`, even for the same underlying user. This is the correct, secure default. TOTP remains shared across every site the user is assigned to, unaffected.

Resetting 2FA for an access-list user only clears that site's WebAuthn credentials and the (site-independent) TOTP secret. Credentials registered for the user's other sites are untouched.

## Managing security keys

Dashboard administrators and members can register, rename, and remove their own security keys from the account panel (header -> account icon) at any time, independent of a login attempt. Access-list end users cannot manage keys outside of login. A key is registered inline during the enroll step and removed only by an administrator's **Reset 2FA** action.

## Secrets and storage

- TOTP secrets are encrypted at rest with the same AES-GCM key (`BG_MASTER_KEY` / `BG_MASTER_KEY_FILE`) used for SSO client secrets and TLS private keys.
- WebAuthn credentials store the authenticator's public key and a signature counter, not a shared secret (there is nothing sensitive to encrypt). The signature counter is checked on every authentication and rejected if it does not advance, which is the standard signal that a credential has been cloned.
- WebAuthn requires a secure context (HTTPS, or `localhost` for local testing).
