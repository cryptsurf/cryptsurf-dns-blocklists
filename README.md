# CryptSurf DNS Blocklists

CryptSurf-maintained DNS blocklist pipeline for DNS profile combinations.

This repository does not mirror another provider's generated output. It fetches
public upstream lists, normalizes them, applies CryptSurf allow/deny rules, and
generates resolver-ready files.

## Output

- `output/domains/<category>.txt`: plain domain lists
- `output/unbound/<category>.conf`: Unbound `local-zone` rules
- `output/rpz/<category>.zone`: RPZ zone files
- `output/profiles.json`: 64 DNS profile combinations and selected categories
- `output/manifest.json`: profile manifest
- `output/metadata.json`: build metadata and counts

Large Unbound outputs may be split into chunk files. In that case,
`output/unbound/<category>.conf` contains `include` directives for
`output/unbound/<category>-001.conf`, `<category>-002.conf`, and so on.

Categories:

- `ads`
- `trackers`
- `malware`
- `adult`
- `gambling`
- `social`

Profile names follow this key format:

```text
all-0_ads-1_trackers-1_malware-0_gambling-0_adult-0_social-0
```

The build creates a lightweight `profiles.json` with 64 category combinations.
The `all` flag is set to `1` only when every category is enabled.

## Build

```bash
python3 scripts/build_cryptsurf_lists.py
```

The script uses only Python standard library modules.

## Local Overrides

- `cryptsurf/allowlist.txt`: domains that must never be blocked
- `cryptsurf/denylist_<category>.txt`: CryptSurf-specific additions

## Sync

GitHub Actions runs every 6 hours and can also be triggered manually.

## Source Notes

Third-party source projects have their own licenses and terms. See
`THIRD_PARTY_NOTICES.md`.
