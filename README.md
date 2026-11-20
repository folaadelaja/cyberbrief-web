# CyberBrief Web

A public, no-login cybersecurity dashboard for GitHub Pages and any static web host. Built for fola with plain HTML, CSS, and JavaScript.

## Open or download

- App: https://folaadelaja.github.io/cyberbrief-web/
- Ready-to-host ZIP: https://folaadelaja.github.io/cyberbrief-web/downloads/cyberbrief-static.zip
- Source: https://github.com/folaadelaja/cyberbrief-web/archive/refs/heads/main.zip

## Automatic updates

GitHub Actions checks RSS, NVD, CISA KEV, and DShield every hour at minute 17, builds public JSON snapshots, and publishes GitHub Pages. The app does not need your Proxmox server or an open browser. Provider failures retain cached source content when a prior cache is available. A build with no data fails rather than replacing the site with an empty feed.

Schedules can be delayed by GitHub. Public-repository schedules can be disabled after 60 days without repository activity; monitor Actions and re-enable the workflow if GitHub disables it. The app shows publication and source-success timestamps. Check for updates loads the newest published snapshot; it does not trigger a collection.

## Saved articles

The Pages edition stores saved snapshots in the current browser. It has no server-side user storage and does not automatically sync reading lists between devices. Use Saved > Export / Import to transfer the list. Export before clearing browser storage. The separate Python server edition retains shared cross-device bookmarks. Existing private reading lists are never included in public builds.

## Host the download

Extract the ZIP and upload its contents to any static web host. For a local preview:

```sh
python3 -m http.server 8080
```

Open http://localhost:8080. Opening index.html directly from disk can block JSON loading. The ZIP contains the snapshot current when it was built; automatic updates require this repository's GitHub Actions workflow or another scheduled builder.

## Build your own

Requires Python 3.11+ and outbound HTTPS, with no pip packages.

```sh
python3 scripts/build_static.py
python3 scripts/check_static.py dist
```

Publish the dist directory. Its downloads folder includes the portable ZIP. The SQLite collection cache stays in data and is excluded from the output. Fork this repository, enable Pages with GitHub Actions as the source, and run Publish CyberBrief to host it on your account.

## Data

The map shows the latest provider daily scanning sample, not every live attack worldwide. Pulses represent report volume. Sources: [SANS ISC / DShield](https://isc.sans.edu/api/), [ipwho.is](https://ipwhois.io/documentation), [Natural Earth](https://www.naturalearthdata.com/about/terms-of-use/), [NVD](https://nvd.nist.gov/developers/vulnerabilities), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and credited publishers. Open article links for original reporting. Provider terms, quotas, and availability apply.
