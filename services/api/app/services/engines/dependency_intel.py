"""Dependency Intelligence Engine: OSV CVE lookups and Typosquatting heuristics."""

import json
import re
from typing import Any, Dict, List, Optional, Tuple
import httpx
from app.schemas.common import Severity
from app.schemas.finding import FindingBase

# High-profile popular packages commonly targeted by typosquatters (>= 5 chars to prevent short-word collisions)
POPULAR_PACKAGES = {
    "npm": [
        "express", "react", "react-dom", "lodash", "axios", "crypto-js",
        "chalk", "moment", "commander", "webpack",
        "cross-env", "dotenv", "typescript", "debug", "tslib", "rxjs",
        "request", "requests",
    ],
    "pypi": [
        "requests", "numpy", "pandas", "flask", "django", "urllib3",
        "cryptography", "boto3", "scipy", "pytest", "pydantic", "pillow",
    ],
}

# Whitelist of legitimate packages that could otherwise trigger false positives
KNOWN_LEGITIMATE_PACKAGES = {
    "nest", "jest", "vite", "nuxt", "koa", "pinia", "redux", "mobx",
    "esbuild", "parcel", "rollup", "turbo", "gulp", "grunt", "zod",
    "yup", "joi", "swr", "fastify", "supertest", "prettier", "eslint",
    "blue", "text", "test", "vue", "next",
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class DependencyIntelligence:
    def __init__(self, osv_base_url: str = "https://api.osv.dev/v1/query"):
        self.osv_base_url = osv_base_url
        self.version = "1.0.0"

    async def scan_file(self, file_path: str, content: str) -> List[FindingBase]:
        findings: List[FindingBase] = []

        if file_path.endswith("package.json"):
            packages = self._extract_npm_packages(content)
            findings.extend(self._check_typosquats(packages, ecosystem="npm", file_path=file_path))
            findings.extend(await self._query_osv_batch(packages, ecosystem="npm", file_path=file_path))

        elif file_path.endswith("requirements.txt"):
            packages = self._extract_pypi_packages(content)
            findings.extend(self._check_typosquats(packages, ecosystem="pypi", file_path=file_path))
            findings.extend(await self._query_osv_batch(packages, ecosystem="PyPI", file_path=file_path))

        return findings

    def _extract_npm_packages(self, content: str) -> List[Tuple[str, Optional[str], int]]:
        """Returns list of (package_name, version, line_number)."""
        packages = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        lines = content.splitlines()
        for dep_type in ["dependencies", "devDependencies"]:
            deps = data.get(dep_type, {})
            if isinstance(deps, dict):
                for name, ver in deps.items():
                    line_no = self._find_package_line(lines, name)
                    clean_ver = str(ver).strip("^~>=<")
                    packages.append((name, clean_ver, line_no))

        return packages

    def _extract_pypi_packages(self, content: str) -> List[Tuple[str, Optional[str], int]]:
        packages = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"[=><~]", line)
            if parts:
                name = parts[0].strip()
                ver = parts[1].strip() if len(parts) > 1 else None
                packages.append((name, ver, idx))
        return packages

    def _check_typosquats(
        self,
        packages: List[Tuple[str, Optional[str], int]],
        ecosystem: str,
        file_path: str,
    ) -> List[FindingBase]:
        findings: List[FindingBase] = []
        targets = POPULAR_PACKAGES.get(ecosystem.lower(), [])

        for name, _ver, line_no in packages:
            name_lower = name.lower()

            # Exact match with official package or known legitimate library is benign
            if name_lower in targets or name_lower in KNOWN_LEGITIMATE_PACKAGES:
                continue

            # Scoped packages (e.g. @types/node, @nestjs/core) are not typosquats of unqualified names
            if name_lower.startswith("@"):
                continue

            # Compare against known targets
            for target in targets:
                if len(target) < 5:
                    continue

                dist = levenshtein_distance(name_lower, target)
                # Check 1 edit distance (or 2 edit distance for longer package names >= 7 chars)
                is_typosquat = (dist == 1 and abs(len(name_lower) - len(target)) <= 1) or \
                               (dist == 2 and len(target) >= 7 and abs(len(name_lower) - len(target)) <= 1)

                if is_typosquat:
                    findings.append(
                        FindingBase(
                            rule_id=f"dep.typosquat.{target}",
                            title=f"Potential typosquat dependency '{name}' targeting '{target}'",
                            description=(
                                f"The introduced package '{name}' closely resembles popular package '{target}' "
                                f"(edit distance: {dist}). Malicious packages often typosquat popular names to trick developers."
                            ),
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            recommendation=f"Verify if you intended to install the official package '{target}' instead of '{name}'.",
                            confidence=0.88,
                        )
                    )
                    break

        return findings

    async def _query_osv_batch(
        self,
        packages: List[Tuple[str, Optional[str], int]],
        ecosystem: str,
        file_path: str,
    ) -> List[FindingBase]:
        findings: List[FindingBase] = []

        async with httpx.AsyncClient(timeout=4.0) as client:
            for name, ver, line_no in packages:
                if not ver:
                    continue
                try:
                    payload = {
                        "version": ver,
                        "package": {"name": name, "ecosystem": ecosystem},
                    }
                    res = await client.post(self.osv_base_url, json=payload)
                    if res.status_code == 200:
                        data = res.json()
                        vulns = data.get("vulns", [])
                        for vuln in vulns[:2]:  # cap at 2 top vulns per package
                            vuln_id = vuln.get("id", "VULN")
                            summary = vuln.get("summary", "Known vulnerability reported in OSV")
                            findings.append(
                                FindingBase(
                                    rule_id=f"dep.cve.{vuln_id}",
                                    title=f"Vulnerability in {name}@{ver}: {vuln_id}",
                                    description=f"{summary} (OSV ID: {vuln_id})",
                                    severity=Severity.HIGH,
                                    file_path=file_path,
                                    line_start=line_no,
                                    line_end=line_no,
                                    recommendation=f"Upgrade package '{name}' to a patched release.",
                                    confidence=0.99,
                                )
                            )
                except Exception:
                    # Fail safely per TRD requirements without halting other checks
                    pass

        return findings

    def _find_package_line(self, lines: List[str], pkg_name: str) -> int:
        for idx, line in enumerate(lines, start=1):
            if f'"{pkg_name}"' in line or f"'{pkg_name}'" in line:
                return idx
        return 1
