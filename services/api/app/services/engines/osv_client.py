"""OSV Vulnerability Client for CODEFORT & BARQAI.

Directly interfaces with Google's Open Source Vulnerabilities (OSV) database
at https://api.osv.dev/v1/query to retrieve verified vulnerability records,
including GHSA/CVE identifiers, CVSS severities, affected versions, and fixed releases.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("codefort.osv_client")

OSV_URL = "https://api.osv.dev/v1/query"

# Local processed dataset path for offline fallback/caching
LOCAL_DATASET_PATH = Path(__file__).resolve().parent.parent.parent / "datasets" / "processed" / "vulnerabilities.json"


async def get_vulnerabilities(
    package_name: str,
    ecosystem: str,
    version: str,
    timeout: float = 20.0,
) -> List[Dict[str, Any]]:
    """Queries the official OSV database API for known vulnerability records.

    Example:
        vulnerabilities = await get_vulnerabilities(
            package_name="jinja2", ecosystem="PyPI", version="2.4.1"
        )
    """
    payload = {
        "package": {"name": package_name, "ecosystem": ecosystem},
        "version": version,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(OSV_URL, json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get("vulns", [])
    except Exception as exc:
        logger.warning(f"OSV live API query failed for {ecosystem}:{package_name}@{version}: {exc}")
        # Graceful fallback to local verified dataset if available
        return get_cached_vulnerabilities(package_name, ecosystem, version)


def get_cached_vulnerabilities(
    package_name: str,
    ecosystem: str,
    version: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Loads matching vulnerabilities from local processed dataset."""
    if not LOCAL_DATASET_PATH.exists():
        return []

    try:
        with open(LOCAL_DATASET_PATH, "r", encoding="utf-8") as f:
            records: List[Dict[str, Any]] = json.load(f)

        matches = []
        for r in records:
            pkg_match = r.get("package", "").lower() == package_name.lower()
            eco_match = r.get("ecosystem", "").lower() == ecosystem.lower()
            ver_match = True if not version else (r.get("version") == version)
            if pkg_match and eco_match and ver_match:
                matches.append({
                    "id": r.get("vulnerability_id"),
                    "aliases": r.get("aliases", []),
                    "summary": r.get("description"),
                    "evidence_id": r.get("evidence_id"),
                    "fixed_version": r.get("fixed_version"),
                    "severity": r.get("severity"),
                })
        return matches
    except Exception as exc:
        logger.warning(f"Failed to read local cached OSV dataset: {exc}")
        return []


def format_osv_evidence(
    vulns: List[Dict[str, Any]],
    package_name: str,
    version: str,
    ecosystem: str,
    evidence_start_idx: int = 1,
) -> List[Dict[str, Any]]:
    """Normalizes raw OSV responses into structured evidence records for BARQAI."""
    evidence_list = []
    for idx, v in enumerate(vulns, start=evidence_start_idx):
        v_id = v.get("id", "VULN-UNKNOWN")
        summary = v.get("summary") or (v.get("details", "")[:120] if v.get("details") else "Known security advisory")

        fixed_version = v.get("fixed_version")
        if not fixed_version:
            for aff in v.get("affected", []):
                for rng in aff.get("ranges", []):
                    for ev in rng.get("events", []):
                        if "fixed" in ev:
                            fixed_version = ev["fixed"]
                            break

        evidence_list.append({
            "evidence_id": v.get("evidence_id") or f"OSV-{idx:03d}",
            "source": "OSV",
            "package": package_name,
            "ecosystem": ecosystem,
            "version": version,
            "vulnerability_id": v_id,
            "aliases": v.get("aliases", []),
            "severity": v.get("severity") or "HIGH",
            "description": summary.strip().replace("\n", " "),
            "fixed_version": fixed_version or "Latest patched release",
        })
    return evidence_list
