# Update notifications

BurrowGate periodically checks GitHub Releases for a newer version and surfaces it in the dashboard - it never downloads or installs anything itself.

## How it works

Once per interval, BurrowGate makes an unauthenticated `GET` request to `https://api.github.com/repos/Rabbit-Company/BurrowGate/releases/latest` and compares the release's tag against the running version. Draft and pre-release releases are ignored, so the check only ever surfaces a published stable release.

When a newer version is found, an **Update available** badge appears next to the version number in the dashboard header - it's part of the shared header, so it shows up on every dashboard page. Clicking the badge opens a modal with the release name, its notes, and a link to the release on GitHub. There is no in-app upgrade action - upgrading is still the manual process described in [Upgrading](../README.md#upgrading).

The check result is cached in memory per BurrowGate process. It is not persisted to the database and resets on restart. The first check runs shortly after startup, then again every `BG_UPDATE_CHECK_INTERVAL_HOURS`.

## Configuration

- `BG_UPDATE_CHECK_ENABLED` (default `true`) - set to `false` to disable the check entirely, e.g. for an air-gapped deployment with no outbound internet access.
- `BG_UPDATE_CHECK_INTERVAL_HOURS` (default `1`, range `1`-`168`) - how often to re-check GitHub Releases.

## Privacy

The request to GitHub's API carries no site data, traffic data, or identifying information - only a generic `User-Agent` header, which is required by GitHub's API. Nothing about the deployment is reported anywhere.
