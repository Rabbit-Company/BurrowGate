# mTLS and origin certificates

BurrowGate can secure the connection to an origin two independent ways, each
configured per origin (not per site) from the same **Load balancing** tab
used to add and edit origins:

- **Client certificate (mTLS)**: BurrowGate presents a certificate _to_ the
  origin, so the origin can verify BurrowGate's identity.
- **Origin server certificate trust**: BurrowGate validates the _origin's_
  TLS certificate against a specific certificate instead of the public CA
  store - useful for an origin with a self-signed or internally-issued
  certificate.

Both are disabled by default, and **you can use either one alone or both
together.** An origin whose software can't verify client certificates (many
self-hosted apps - fall into this category) still benefits from origin
certificate trust on its own, without needing mTLS enabled at all.

## Client certificate (mTLS)

- **Client certificate + private key**: presented during the TLS handshake
  when connecting to that origin, so the origin can verify BurrowGate's
  identity (the other half of "mutual" TLS).
- Only takes effect while **Enable mTLS** is checked for that origin.

### Generating a client certificate

You don't need your own PKI or OpenSSL knowledge to use this. On an
already-saved origin, click **Generate certificate** (in the mTLS section)
and BurrowGate creates a keypair and a self-signed, 15-year certificate for
you, enables mTLS, and stores it - **the private key never leaves
BurrowGate, not even temporarily.** Only the certificate downloads to your
browser; install that file as a trusted client certificate on your origin
server (how depends on the origin's own software - e.g. nginx's
`ssl_client_certificate`, Apache's `SSLCACertificateFile`). Clicking
**Generate certificate** again replaces the credential immediately - confirm
first, and update the origin's trust store with the newly downloaded
certificate afterward, since the old one stops being presented right away.

If you already manage your own certificates, pasting a cert and key you
generated yourself works exactly the same as before - both paths store the
result identically, and either one can be re-downloaded later with
**Download certificate**, available whenever a certificate is configured
(the certificate itself isn't secret; only the private key is protected).

## Origin server certificate trust

Paste a certificate bundle to trust for validating the origin's server
certificate, in the **Origin server certificate trust** section - instead of
(or in addition to) the public CAs your system already trusts. This applies
regardless of whether mTLS above is enabled, so it works standalone for
origins that only need BurrowGate to trust their certificate, not the other
way around.

### Generating an origin certificate

Click **Generate origin certificate** and BurrowGate creates a self-signed,
15-year certificate covering your site's public hostname, stores the
certificate as the trusted value above, and returns the private key to you
**once, in that response only.**

This is the opposite security model from the client-certificate generator
above: here, the _origin_ needs the private key to serve HTTPS with this
certificate, so BurrowGate hands it over and does not keep a copy anywhere -
not encrypted, not plaintext. Save it immediately (copy or download) when
the "Save this private key" panel appears; if you lose it, generate a new
certificate and install both files on the origin again. The certificate
itself is downloadable again later like any other trusted CA, since it
carries no secrecy on its own.

Install the downloaded certificate and key as the origin's own HTTPS
certificate/key pair (e.g. `ssl_certificate`/`ssl_certificate_key` in
nginx). Regenerating replaces the trusted value immediately, the same as
pasting a new one would.

## Enabling and disabling

Leave the certificate/private-key/CA text fields blank when saving to keep
whatever was previously stored - they are never shown back to you after
saving (matching how the origin signing secret and inbound TLS certificates
work), only whether a value is currently configured. Turning **Enable
mTLS** off just stops presenting the stored client certificate; it does not
delete it, so turning it back on later doesn't require re-uploading. Origin
certificate trust has no separate enable toggle - it's applied whenever a
value is stored, and clearing it means pasting an empty CA is not
supported today; generate or paste a replacement instead.

## Limitations

- Client-certificate mTLS applies to the HTTP(S) proxy path only. WebSocket
  connections to an origin use a separate connection mechanism that does not
  currently support a client certificate override - the existing outbound
  protocol setting (HTTP/1.1, HTTP/2, HTTP/3) has this same limitation
  today.
- Certificate hostname verification for the _origin's_ server certificate is
  checked against the outgoing `Host` header BurrowGate sends to the origin
  (its site's public hostname), not the origin's IP or hostname in the
  origin URL. The origin-certificate generator above already accounts for
  this - the certificate it creates covers the site's public hostname. If
  you're pasting your own certificate instead, make sure it (or the CA that
  issued it) covers that hostname too.

## Security note

The client-certificate private key is encrypted at rest with the instance's
master key, the same mechanism used for the origin signing secret, ACME
account keys, and uploaded inbound TLS certificates - it is never stored in
plaintext and never returned by the dashboard API. The origin-certificate
private key, by contrast, is never stored at all, encrypted or otherwise -
it exists only transiently in the generate response before being handed to
you. Anyone with **manage** access to the site can trigger either
generator or configure either credential, but can never read a stored
client-certificate key back out, and the origin-certificate key isn't
stored to read back in the first place.
