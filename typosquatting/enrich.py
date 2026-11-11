"""Look up when a look-alike was registered, through the public RDAP service."""

import http.client
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable, Optional

logger = logging.getLogger(__name__)

RDAP_URL = "https://rdap.org/domain/{}"
USER_AGENT = "typosquatting-detector"
# The public RDAP gateway drops connections when queried too fast, so keep the
# parallelism low and retry a refused request after a short pause.
DEFAULT_WORKERS = 4
ATTEMPTS = 3
RETRY_DELAY = 1.0
# Answers where trying again can help; 404 means the registry has no such record.
RETRY_STATUS = {429, 500, 502, 503, 504}


def parse_date(text: str) -> Optional[datetime]:
    """Parse an ISO 8601 date; dates without a time zone are taken as UTC."""
    try:
        date = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return date if date.tzinfo else date.replace(tzinfo=timezone.utc)


def registration_date(domain: str, timeout: float = 5) -> Optional[datetime]:
    """Registration date from RDAP, or None when the registry does not say or is unreachable."""
    request = urllib.request.Request(
        RDAP_URL.format(urllib.parse.quote(domain, safe="")),
        headers={"Accept": "application/rdap+json", "User-Agent": USER_AGENT},
    )
    data = None
    for attempt in range(1, ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.load(response)
            break
        except urllib.error.HTTPError as exc:
            if exc.code not in RETRY_STATUS:
                return None
        except (urllib.error.URLError, http.client.HTTPException, OSError):
            pass
        except ValueError:
            return None
        if attempt < ATTEMPTS:
            time.sleep(RETRY_DELAY * attempt)
    if data is None:
        return None

    for event in data.get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            return parse_date(event["eventDate"])
    return None


def add_ages(
    variants: list[dict],
    lookup: Callable[[str], Optional[datetime]] = registration_date,
    workers: int = DEFAULT_WORKERS,
    now: Optional[datetime] = None,
) -> int:
    """Add `registered` and `age_days` to the variants in place; return how many were dated.

    A look-alike found in certificate logs falls back to its certificate date when RDAP
    has nothing, which is an upper bound of its age rather than its registration date.
    """
    now = now or datetime.now(timezone.utc)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        dates = list(pool.map(lookup, [v["domain"] for v in variants]))

    dated = 0
    for variant, date in zip(variants, dates):
        if date is None and variant.get("ct_not_before"):
            date = parse_date(variant["ct_not_before"])
        if date is None:
            continue
        variant["registered"] = date.date().isoformat()
        variant["age_days"] = max((now - date).days, 0)
        dated += 1
    logger.info("Registration date found for %d/%d look-alikes", dated, len(variants))
    return dated
