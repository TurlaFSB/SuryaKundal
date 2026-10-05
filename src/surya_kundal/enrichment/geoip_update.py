"""Download and refresh the GeoLite2 databases from MaxMind.

Credentials are sent only to download.maxmind.com (HTTP Basic auth). The download
redirects to a storage host; httpx drops the Authorization header on cross-origin
redirects, so the licence key never leaves MaxMind. Credentials are never logged.
"""

from __future__ import annotations

import logging
import os
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import maxminddb

logger = logging.getLogger(__name__)

DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/{edition}/download"
EDITIONS = {
    "GeoLite2-City": "GeoLite2-City.mmdb",
    "GeoLite2-ASN": "GeoLite2-ASN.mmdb",
}
FRESH_DAYS = 3  # MaxMind publishes twice a week; skip downloads for anything newer
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
MAX_DATABASE_BYTES = 500 * 1024 * 1024


class GeoIPUpdateError(Exception):
    """A database could not be updated. The message is safe to show to the user."""


@dataclass(frozen=True)
class UpdateResult:
    edition: str
    path: Path
    updated: bool
    reason: str


def _age_days(path: Path) -> float | None:
    """Age of an existing database from its build time, or None if unusable."""
    try:
        with maxminddb.open_database(str(path)) as reader:
            return (time.time() - reader.metadata().build_epoch) / 86400
    except (maxminddb.InvalidDatabaseError, OSError, ValueError):
        return None


def _download_archive(client: httpx.Client, edition: str, dest: Path, auth: tuple) -> None:
    url = DOWNLOAD_URL.format(edition=edition)
    try:
        with client.stream(
            "GET", url, params={"suffix": "tar.gz"}, auth=auth, follow_redirects=True
        ) as response:
            if response.status_code == 401:
                raise GeoIPUpdateError(
                    "MaxMind rejected the credentials (401). Check MAXMIND_ACCOUNT_ID "
                    "and MAXMIND_LICENSE_KEY."
                )
            if response.status_code == 429:
                raise GeoIPUpdateError(
                    "MaxMind download limit reached (429): 30 downloads per day. Try tomorrow."
                )
            if response.status_code != 200:
                raise GeoIPUpdateError(
                    f"MaxMind returned HTTP {response.status_code} for {edition}."
                )
            size = 0
            with dest.open("wb") as out:
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_ARCHIVE_BYTES:
                        raise GeoIPUpdateError(
                            f"{edition} archive is unexpectedly large; aborting."
                        )
                    out.write(chunk)
    except httpx.HTTPError as exc:
        raise GeoIPUpdateError(
            f"Network error while downloading {edition}: {type(exc).__name__}"
        ) from exc


def _extract_mmdb(archive: Path, dest: Path) -> None:
    """Copy the first .mmdb member out of the archive. Never uses extractall."""
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if member.isfile() and member.name.endswith(".mmdb"):
                    if member.size > MAX_DATABASE_BYTES:
                        raise GeoIPUpdateError("Database inside the archive is too large.")
                    source = tar.extractfile(member)
                    if source is None:
                        break
                    with source, dest.open("wb") as out:
                        while chunk := source.read(1024 * 1024):
                            out.write(chunk)
                    return
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise GeoIPUpdateError("Downloaded archive is corrupt or not a tar.gz file.") from exc
    raise GeoIPUpdateError("Downloaded archive contains no .mmdb database.")


def _validate(path: Path, edition: str) -> None:
    try:
        with maxminddb.open_database(str(path)) as reader:
            found = reader.metadata().database_type
    except (maxminddb.InvalidDatabaseError, OSError, ValueError) as exc:
        raise GeoIPUpdateError("Downloaded database is not a valid MMDB file.") from exc
    if found != edition:
        raise GeoIPUpdateError(f"Expected a {edition} database but received {found}.")


def update_database(
    edition: str,
    db_dir: Path,
    account_id: str,
    license_key: str,
    *,
    force: bool = False,
    client: httpx.Client | None = None,
) -> UpdateResult:
    """Download one edition into db_dir, replacing the old file only after validation."""
    if edition not in EDITIONS:
        raise GeoIPUpdateError(f"Unknown edition: {edition}")
    if not account_id or not license_key:
        raise GeoIPUpdateError("MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY must both be set.")

    db_dir = Path(db_dir).expanduser()
    db_dir.mkdir(parents=True, exist_ok=True)
    target = db_dir / EDITIONS[edition]

    if not force and target.is_file():
        age = _age_days(target)
        if age is not None and age < FRESH_DAYS:
            return UpdateResult(edition, target, False, f"already fresh ({age:.1f} days old)")

    owns_client = client is None
    client = client or httpx.Client(timeout=httpx.Timeout(60.0, connect=15.0))
    try:
        with tempfile.TemporaryDirectory(dir=db_dir, prefix=".update-") as tmp:
            archive = Path(tmp) / "archive.tar.gz"
            candidate = Path(tmp) / "candidate.mmdb"
            _download_archive(client, edition, archive, (account_id, license_key))
            _extract_mmdb(archive, candidate)
            _validate(candidate, edition)
            os.replace(candidate, target)  # atomic: readers see old or new, never partial
    finally:
        if owns_client:
            client.close()

    logger.info("Updated %s", target)
    return UpdateResult(edition, target, True, "downloaded")


def update_all(
    db_dir: Path,
    account_id: str,
    license_key: str,
    *,
    force: bool = False,
    client: httpx.Client | None = None,
) -> list[UpdateResult]:
    results: list[UpdateResult] = []
    errors: list[str] = []
    for edition in EDITIONS:  # one failing edition must not stop the other
        try:
            results.append(
                update_database(
                    edition, db_dir, account_id, license_key, force=force, client=client
                )
            )
        except GeoIPUpdateError as exc:
            errors.append(f"{edition}: {exc}")
    if errors:
        done = ", ".join(r.edition for r in results) or "none"
        raise GeoIPUpdateError(f"{'; '.join(errors)} (updated: {done})")
    return results
