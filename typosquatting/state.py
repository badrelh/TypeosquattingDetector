"""Remember which look-alikes were already seen, so only new ones raise an alert."""

import json
import os
from pathlib import Path
from typing import Union

PathLike = Union[str, "os.PathLike[str]"]


def load_state(path: PathLike) -> dict[str, list[str]]:
    """Read the state file; a missing file means nothing was scanned yet."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"State file {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"State file {path} must contain a JSON object")
    return data


def save_state(path: PathLike, state: dict[str, list[str]]) -> None:
    """Write the state through a temporary file so an interrupted run cannot corrupt it."""
    target = Path(path)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, target)


def find_new(domain: str, variants: list[dict], state: dict[str, list[str]]) -> tuple[list[str], bool]:
    """Return the look-alikes not seen before, and whether this is the first scan of the domain.

    The first scan only records a baseline: reporting every existing look-alike as new
    would raise a false alarm. A look-alike that disappears and comes back is not reported
    again, because the state keeps every name ever seen.
    """
    if domain not in state:
        return [], True
    known = set(state[domain])
    return sorted(v["domain"] for v in variants if v["domain"] not in known), False


def update_state(domain: str, variants: list[dict], state: dict[str, list[str]]) -> None:
    """Add the current look-alikes to the state in place."""
    seen = set(state.get(domain, ()))
    seen.update(v["domain"] for v in variants)
    state[domain] = sorted(seen)
