# Third-Party Notices

This repository generates CryptSurf-specific DNS outputs from public upstream
blocklists and local CryptSurf overrides.

Upstream sources are configured in `config/sources.json`.

Current upstream source projects:

- AdGuard DNS filter: https://github.com/AdguardTeam/AdGuardSDNSFilter
- HaGeZi DNS blocklists: https://github.com/hagezi/dns-blocklists
- URLHaus hostfile: https://urlhaus.abuse.ch/

The generated CryptSurf output is normalized, filtered, deduplicated, and
combined by this repository's build pipeline. Review each upstream source's
license and usage terms before redistributing generated outputs.
