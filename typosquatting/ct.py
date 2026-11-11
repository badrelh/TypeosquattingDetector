"""Find look-alikes that got a TLS certificate, using the public crt.sh search.

Permutations only reach names dnstwist can guess. Certificate logs also reveal names
that merely contain the brand (`example-login.com`), which is how most phishing sites
are named. Only names whose registrable domain contains the brand are kept, so a
phishing page hosted as `login.example.evil.com` is not found.

crt.sh is a free service, often slow or unavailable, and it may truncate very large
result sets, so a failure here must never stop a scan.
"""

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable, Optional

from typosquatting.filters import is_allowed
from typosquatting.risk import CT_FUZZER

logger = logging.getLogger(__name__)

CRT_URL = "https://crt.sh/?q={}&output=json&exclude=expired"
USER_AGENT = "typosquatting-detector"
MAX_RESULTS = 500
# A DNS name: dot-separated labels of letters, digits and inner hyphens (IDNs in punycode).
HOSTNAME = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
# Second-level labels that are part of the suffix, as in example.co.uk.
SUFFIX_LABELS = {"co", "com", "org", "net", "gov", "edu", "ac"}


def brand_keyword(domain: str) -> str:
    """The brand part of a domain: `example` for example.com and for example.co.uk."""
    labels = domain.lower().strip(".").split(".")
    if len(labels) >= 3 and labels[-2] in SUFFIX_LABELS:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else labels[0]


def registrable_part(name: str) -> str:
    """The last labels of a name, as in `example-login.com` for `www.example-login.com`.

    This is a heuristic without the public suffix list, good enough to tell the owner's
    own domain from a mere subdomain.
    """
    labels = name.split(".")
    keep = 3 if len(labels) >= 3 and labels[-2] in SUFFIX_LABELS else 2
    return ".".join(labels[-keep:])


def fetch(keyword: str, timeout: float) -> list[dict]:
    url = CRT_URL.format(urllib.parse.quote(f"%{keyword}%", safe=""))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def search(domain: str, allowed: Iterable[str] = (), timeout: float = 30) -> Optional[list[dict]]:
    """Domains with a certificate whose name contains the brand, or None when crt.sh fails."""
    keyword = brand_keyword(domain)
    try:
        rows = fetch(keyword, timeout)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        logger.warning("Certificate log search failed for %s: %s", domain, exc)
        return None

    own = [domain.lower(), *allowed]
    first_seen: dict[str, str] = {}
    for row in rows:
        for name in row.get("name_value", "").lower().splitlines():
            name = name.removeprefix("*.")
            # Certificates also list e-mail addresses and organisation names; keep hostnames only.
            if not HOSTNAME.match(name):
                continue
            # A brand that appears only in a subdomain of an unrelated domain (for example a
            # company's CI host) is noise; the registrable part must contain it.
            if keyword not in registrable_part(name) or is_allowed(name, own):
                continue
            date = row.get("not_before", "")
            if name not in first_seen or (date and date < first_seen[name]):
                first_seen[name] = date

    names = sorted(first_seen)[:MAX_RESULTS]
    logger.info("%d look-alikes with a certificate found for %s", len(names), domain)
    return [{"domain": name, "fuzzer": CT_FUZZER, "ct_not_before": first_seen[name]} for name in names]
