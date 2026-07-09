#!/usr/bin/env python3
import hashlib
import itertools
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATEGORIES = ("ads", "trackers", "malware", "gambling", "adult", "social")
DEFAULT_RAW_OUTPUT_BASE_URL = (
    "https://raw.githubusercontent.com/cryptsurf/"
    "cryptsurf-dns-blocklists/main/output/domains"
)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
BAD_TOKENS = ("$", "/", "\\", "[", "]", "(", ")", "{", "}", ",", ";", ":", "!", "?")
FETCH_ATTEMPTS = max(1, int(os.environ.get("FETCH_ATTEMPTS", "4")))
FETCH_TIMEOUT_SECONDS = max(1, int(os.environ.get("FETCH_TIMEOUT_SECONDS", "60")))
FETCH_RETRY_DELAY_SECONDS = max(0, float(os.environ.get("FETCH_RETRY_DELAY_SECONDS", "5")))
UNBOUND_CHUNK_BYTES = max(
    1024 * 1024,
    int(os.environ.get("UNBOUND_CHUNK_BYTES", str(90 * 1024 * 1024))),
)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_domain_file(path):
    if not path.exists():
        return set()

    domains = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        domain = normalize_domain(raw)
        if domain:
            domains.add(domain)
    return domains


def warn(message):
    print(f"::warning::{message}", file=sys.stderr)


def fetch_text(url):
    last_error = None

    for attempt in range(1, FETCH_ATTEMPTS + 1):
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "CryptSurf-DNS-Blocklists/1.0",
                "Accept": "text/plain,*/*",
            },
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=FETCH_TIMEOUT_SECONDS,
            ) as response:
                return response.read().decode("utf-8", errors="ignore")
        except (TimeoutError, OSError, urllib.error.URLError) as error:
            last_error = error
            if attempt == FETCH_ATTEMPTS:
                break

            wait_seconds = FETCH_RETRY_DELAY_SECONDS * attempt
            warn(
                f"Fetch failed for {url} "
                f"(attempt {attempt}/{FETCH_ATTEMPTS}): {error}; "
                f"retrying in {wait_seconds:g}s"
            )
            time.sleep(wait_seconds)

    raise RuntimeError(
        f"failed to fetch {url} after {FETCH_ATTEMPTS} attempts: {last_error}"
    ) from last_error


def category_output_path(category):
    return ROOT / "output" / "domains" / f"{category}.txt"


def read_cached_category(category):
    cached_domains = read_domain_file(category_output_path(category))
    if not cached_domains:
        path = category_output_path(category)
        raise RuntimeError(
            f"cannot fall back for {category}; {path} is empty or missing"
        )
    return cached_domains


def fetch_category_domains(category, category_sources):
    domains = set()
    failures = []

    for source in category_sources:
        name = source.get("name", source["url"])
        url = source["url"]
        print(f"Fetching {category}/{name}: {url}", file=sys.stderr)
        try:
            domains.update(parse_source(fetch_text(url)))
        except RuntimeError as error:
            failures.append(f"{name} ({url}): {error}")

    if not failures:
        return domains

    for failure in failures:
        warn(failure)
    warn(
        f"Using cached {category_output_path(category)} because "
        f"{len(failures)} upstream source(s) failed"
    )
    return read_cached_category(category)


def normalize_domain(raw):
    line = raw.strip().lower()
    if not line or line.startswith(("#", "!", ";", "[")):
        return None

    if " #" in line:
        line = line.split(" #", 1)[0].strip()
    if "\t#" in line:
        line = line.split("\t#", 1)[0].strip()

    if line.startswith("@@"):
        return None

    if line.startswith("||"):
        line = line[2:]
    if line.startswith("|"):
        line = line[1:]
    if line.startswith("*."):
        line = line[2:]
    if line.startswith("."):
        line = line[1:]

    if "^" in line:
        line = line.split("^", 1)[0]

    parts = line.split()
    if len(parts) >= 2 and is_ip_like(parts[0]):
        line = parts[1]
    elif len(parts) == 1:
        line = parts[0]
    else:
        return None

    line = line.removeprefix("http://").removeprefix("https://")
    line = line.split("/", 1)[0]
    line = line.split(":", 1)[0]
    line = line.strip(" .")

    if any(token in line for token in BAD_TOKENS):
        return None
    if is_ip_like(line):
        return None
    if not DOMAIN_RE.match(line):
        return None

    return line


def is_ip_like(value):
    return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", value))


def parse_source(text):
    domains = set()
    for line in text.splitlines():
        domain = normalize_domain(line)
        if domain:
            domains.add(domain)
    return domains


def ensure_dirs():
    for path in (
        ROOT / "output" / "domains",
        ROOT / "output" / "unbound",
        ROOT / "output" / "rpz",
    ):
        path.mkdir(parents=True, exist_ok=True)


def write_domains(path, domains, header):
    body = "\n".join(sorted(domains))
    content = f"# {header}\n# Generated by CryptSurf DNS pipeline\n{body}\n"
    path.write_text(content, encoding="utf-8")


def write_unbound(path, domains, header):
    header_lines = [
        f"# {header}",
        "# Generated by CryptSurf DNS pipeline",
    ]
    rule_lines = [
        f'local-zone: "{domain}" always_nxdomain'
        for domain in sorted(domains)
    ]
    content = "\n".join(header_lines + rule_lines) + "\n"
    cleanup_unbound_chunks(path)

    if len(content.encode("utf-8")) <= UNBOUND_CHUNK_BYTES:
        path.write_text(content, encoding="utf-8")
        return

    chunk_paths = write_unbound_chunks(path, header_lines, rule_lines)
    index_lines = header_lines + [
        "# Split into chunk files to stay below GitHub's single-file size limit.",
    ]
    index_lines.extend(f'include: "{chunk_path.name}"' for chunk_path in chunk_paths)
    path.write_text("\n".join(index_lines) + "\n", encoding="utf-8")


def cleanup_unbound_chunks(path):
    for chunk_path in path.parent.glob(f"{path.stem}-[0-9][0-9][0-9]{path.suffix}"):
        chunk_path.unlink()


def write_unbound_chunks(path, header_lines, rule_lines):
    chunk_paths = []
    current_lines = []
    current_size = 0
    chunk_header = header_lines + [
        "# Chunked from a generated Unbound config.",
    ]
    chunk_header_size = len(("\n".join(chunk_header) + "\n").encode("utf-8"))

    for line in rule_lines:
        line_size = len((line + "\n").encode("utf-8"))
        if current_lines and current_size + line_size > UNBOUND_CHUNK_BYTES:
            chunk_paths.append(
                write_unbound_chunk(path, len(chunk_paths) + 1, chunk_header, current_lines)
            )
            current_lines = []
            current_size = chunk_header_size

        if not current_lines:
            current_size = chunk_header_size
        current_lines.append(line)
        current_size += line_size

    if current_lines:
        chunk_paths.append(
            write_unbound_chunk(path, len(chunk_paths) + 1, chunk_header, current_lines)
        )

    return chunk_paths


def write_unbound_chunk(path, index, header_lines, rule_lines):
    chunk_path = path.with_name(f"{path.stem}-{index:03d}{path.suffix}")
    chunk_path.write_text(
        "\n".join(header_lines + rule_lines) + "\n",
        encoding="utf-8",
    )
    return chunk_path


def write_rpz(path, domains, zone_name):
    serial = time.strftime("%Y%m%d%H")
    lines = [
        "$TTL 300",
        f"@ SOA localhost. admin.cryptsurf.net. ({serial} 300 300 300 300)",
        "@ NS localhost.",
    ]
    lines.extend(f"{domain} CNAME ." for domain in sorted(domains))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def profile_name(flags):
    all_enabled = all(flags[category] for category in CATEGORIES)
    return (
        f"all-{int(all_enabled)}_"
        f"ads-{int(flags['ads'])}_"
        f"trackers-{int(flags['trackers'])}_"
        f"malware-{int(flags['malware'])}_"
        f"gambling-{int(flags['gambling'])}_"
        f"adult-{int(flags['adult'])}_"
        f"social-{int(flags['social'])}"
    )


def profile_bits(flags):
    return "".join(str(int(flags[category])) for category in CATEGORIES)


def profile_id(flags):
    bits = profile_bits(flags)
    if bits == "000000":
        return "default"
    if bits == "100000":
        return "ads"
    if bits == "111111":
        return "all"
    return f"dns-{bits}"


def flags_from_bits(bits):
    return {
        category: bits[index] == "1"
        for index, category in enumerate(CATEGORIES)
    }


def iter_profile_flags():
    yielded = set()
    for bits in ("000000", "100000", "111111"):
        yielded.add(bits)
        yield flags_from_bits(bits)

    for values in itertools.product((False, True), repeat=len(CATEGORIES)):
        flags = dict(zip(CATEGORIES, values))
        bits = profile_bits(flags)
        if bits in yielded:
            continue
        yielded.add(bits)
        yield flags


def profile_dns_ip(index):
    return f"10.10.0.{index + 2}"


def profile_blocklists(selected_categories, raw_output_base_url):
    return [
        {
            "category": category,
            "format": "domains",
            "url": f"{raw_output_base_url}/{category}.txt",
        }
        for category in selected_categories
    ]


def sha256_domains(domains):
    digest = hashlib.sha256()
    for domain in sorted(domains):
        digest.update(domain.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def build():
    ensure_dirs()

    sources = read_json(ROOT / "config" / "sources.json")
    raw_output_base_url = os.environ.get(
        "RAW_OUTPUT_BASE_URL",
        DEFAULT_RAW_OUTPUT_BASE_URL,
    ).rstrip("/")
    allowlist = read_domain_file(ROOT / "cryptsurf" / "allowlist.txt")
    categories = {}
    metadata = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "categories": {},
        "profiles": {},
        "sources": sources,
    }
    manifest = {
        "version": metadata["generated_at"],
        "updated_at": metadata["generated_at"],
        "source": "cryptsurf-dns-blocklists",
        "profiles": [],
    }

    for category in CATEGORIES:
        domains = fetch_category_domains(category, sources.get(category, []))
        denylist = read_domain_file(ROOT / "cryptsurf" / f"denylist_{category}.txt")
        domains.update(denylist)
        domains.difference_update(allowlist)
        categories[category] = domains

        write_domains(
            ROOT / "output" / "domains" / f"{category}.txt",
            domains,
            f"CryptSurf {category} domains",
        )
        write_unbound(
            ROOT / "output" / "unbound" / f"{category}.conf",
            domains,
            f"CryptSurf {category} Unbound rules",
        )
        write_rpz(
            ROOT / "output" / "rpz" / f"{category}.zone",
            domains,
            f"cryptsurf-{category}",
        )
        metadata["categories"][category] = {
            "count": len(domains),
            "sha256": sha256_domains(domains),
        }

    all_domains = set().union(*categories.values())
    write_domains(ROOT / "output" / "domains" / "all.txt", all_domains, "CryptSurf all domains")
    write_unbound(ROOT / "output" / "unbound" / "all.conf", all_domains, "CryptSurf all Unbound rules")
    write_rpz(ROOT / "output" / "rpz" / "all.zone", all_domains, "cryptsurf-all")

    for index, flags in enumerate(iter_profile_flags()):
        name = profile_name(flags)
        selected_categories = [
            category for category, enabled in flags.items() if enabled
        ]
        profile_domains = set()
        for category in selected_categories:
            profile_domains.update(categories[category])

        metadata["profiles"][name] = {
            "categories": selected_categories,
            "count": len(profile_domains),
            "sha256": sha256_domains(profile_domains),
        }
        manifest["profiles"].append(
            {
                "id": profile_id(flags),
                "profile": name,
                "dns": profile_dns_ip(index),
                "upstream": ["1.1.1.1", "8.8.8.8"],
                "categories": selected_categories,
                "blocklists": profile_blocklists(
                    selected_categories,
                    raw_output_base_url,
                ),
            }
        )

    metadata["categories"]["all"] = {
        "count": len(all_domains),
        "sha256": sha256_domains(all_domains),
    }
    (ROOT / "output" / "metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (ROOT / "output" / "profiles.json").write_text(
        json.dumps(metadata["profiles"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (ROOT / "output" / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    build()
