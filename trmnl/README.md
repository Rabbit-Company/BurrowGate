# BurrowGate for TRMNL

A polling private plugin, ready to import and submit as a recipe. Users provide their BurrowGate instance URL and a read-only monitoring token, then select the data to display. Full screen, half horizontal, half vertical, and quadrant layouts are included.

## Install

1. Run the updated BurrowGate server. Database migrations create the token table automatically at startup.
2. Sign in as an administrator, open **Account -> Read-only API tokens**, and create a token named `TRMNL`. Copy the `bgro_` value shown once.
3. From the repository root, run `python3 trmnl/build.py`. This creates `trmnl/burrowgate.zip` with a flat `settings.yml` and four Liquid layouts.
4. In TRMNL, open **Private Plugins -> Import new** and select that ZIP. This follows TRMNL's [plugin import format](https://help.trmnl.com/en/articles/10542599-importing-and-exporting-private-plugins).
5. Enter your instance's HTTPS base URL (for example, `https://gate.example.com`, without `/_burrowgate/admin`) and paste the token into **Read-only API token**. Select **View** and **Time range**; optionally supply a **Site ID**. Save and force a refresh.

TRMNL's polling service must be able to reach the URL with a valid HTTPS certificate. A private LAN URL or a dashboard protected by an additional interactive login will need suitable network access for polling. The token is stored in your TRMNL plugin settings and sent only in the polling Authorization header, never in the polling URL or screen markup. The password field masks it in the settings form.

## Choose a view

| View                               | Display                                                    |
| ---------------------------------- | ---------------------------------------------------------- |
| Traffic overview / Request traffic | Request counts, blocks, server errors, and a traffic chart |
| Blocked requests                   | Blocked-request chart and traffic totals                   |
| Client bandwidth                   | Combined client transfer chart with download/upload totals |
| Cache hit ratio                    | Hit-ratio chart, hits, and misses                          |
| Managed protection                 | WAF blocks, inspected requests, and monitored matches      |
| Request latency                    | Average response latency and interval chart                |
| Top countries                      | Most active countries by recorded requests                 |
| CPU / Memory / Storage             | Average usage over time                                    |
| Network throughput                 | Download-rate chart with average download/upload rates     |

Choose the last hour, 6 hours, 24 hours, or 7 days. The default refresh interval is 15 minutes. Half and quadrant layouts show fewer summary fields or country rows to fit the available space. All timestamps are UTC; all views show the fetch timestamp so an old screen remains identifiable.

The view selector lives in the plugin settings. To rotate several views on the device, import multiple instances with different views and add them to a playlist. Use a mashup to show views side by side. Each instance can use a separate token for independent revocation.

**Site ID** is optional. Find it in the dashboard's selected-site URL or through `GET /_burrowgate/api/v1/sites` with the token. Leave it empty for all sites, and always leave it empty for system views. This is a display filter: the credential has instance-wide monitoring access.

## Development and troubleshooting

Edit `screen.liquid` and run `python3 trmnl/build.py` to regenerate the four standalone layouts and ZIP. `settings.yml` defines the connection fields, dropdowns, and polling request. Layouts use Liquid and static CSS bars without third-party chart scripts. The archive contains no example credentials or user data.

The API is documented in [API_TOKENS.md](../docs/API_TOKENS.md). Missing samples show an empty state; zero request counts remain zero. Data is limited by BurrowGate retention and background metric flushes. System metrics must be enabled and collected on the node being polled.

For 401 errors, replace an expired or revoked token and verify its owner is still an enabled administrator. For 400 errors, check the site ID and clear it for system views. For connectivity errors, verify that TRMNL can reach the supplied URL. A failed poll may leave the last successful screen displayed; inspect its update time and TRMNL's plugin logs.

After importing and testing with your instance, use **Publish as a Recipe** in TRMNL if you want a public listing. This repository provides the recipe files; it does not publish a listing automatically.
