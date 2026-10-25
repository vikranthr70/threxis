"""Synthetic evidence copying, hashing, manifests, and ordinary custody notes."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime
from pathlib import Path

from src.common.models import ContractError, EvidenceManifest

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CHUNK = 1024 * 1024


def _validate_timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ContractError("collected_at must be timezone-aware ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContractError("collected_at must include an explicit timezone")


def _path_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def preserve_evidence(source: Path, destination: Path, evidence_id: str, collected_at: str) -> EvidenceManifest:
    """Copy one explicit synthetic artifact without overwriting any vault file.

    The source's parent directory is treated as the designated synthetic
    workspace. Destination and sidecars must remain beneath it. Symlinks and
    non-regular source files are rejected to avoid path redirection.
    """
    if not isinstance(evidence_id, str) or not _ID_RE.fullmatch(evidence_id):
        raise ContractError("evidence_id must be a safe filename token")
    _validate_timestamp(collected_at)
    source = Path(source)
    destination = Path(destination)
    try:
        if source.is_symlink() or not source.is_file():
            if not source.exists():
                raise FileNotFoundError(source)
            raise ContractError("source must be a regular, non-symlink file")
        source_real = source.resolve(strict=True)
        workspace = source_real.parent
        destination_real = destination.resolve(strict=False)
        if not _path_within(destination_real, workspace) or destination_real == source_real:
            raise ContractError("destination must be a different path inside the source synthetic workspace")
        if destination.is_symlink():
            raise ContractError("destination may not be a symlink")
        destination_real.parent.mkdir(parents=True, exist_ok=True)
        if not _path_within(destination_real.parent.resolve(), workspace):
            raise ContractError("destination parent resolves outside the synthetic workspace")
    except OSError:
        raise

    digest = hashlib.sha256()
    try:
        # Exclusive create prevents accidental overwriting, including races.
        with source_real.open("rb") as input_file, destination_real.open("xb") as output_file:
            while chunk := input_file.read(_CHUNK):
                digest.update(chunk)
                output_file.write(chunk)
            output_file.flush()
            os.fsync(output_file.fileno())
    except FileExistsError as exc:
        raise ContractError("evidence destination already exists") from exc
    except OSError:
        try:
            destination_real.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    manifest = EvidenceManifest(
        manifest_id="MAN-" + hashlib.sha256(f"{evidence_id}|{collected_at}|{digest.hexdigest()}".encode()).hexdigest()[:20],
        evidence_id=evidence_id,
        collected_at=collected_at,
        sha256=digest.hexdigest(),
        source_path=str(destination_real),
    )
    manifest_path = destination_real.with_name(destination_real.name + ".manifest.json")
    custody_path = destination_real.parent / "custody.jsonl"
    if manifest_path.is_symlink() or custody_path.is_symlink():
        destination_real.unlink(missing_ok=True)
        raise ContractError("manifest and custody paths may not be symlinks")
    manifest_payload = json.dumps(manifest.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    custody_payload = json.dumps({
        "evidence_id": evidence_id, "collected_at": collected_at,
        "file_path": str(destination_real), "sha256": manifest.sha256,
        "action": "preserved",
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    try:
        with manifest_path.open("x", encoding="utf-8", newline="") as stream:
            stream.write(manifest_payload)
        # Append only during normal operation; this file is not tamper-proof.
        with custody_path.open("a", encoding="utf-8", newline="") as stream:
            stream.write(custody_payload)
    except FileExistsError as exc:
        destination_real.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        raise ContractError("manifest destination already exists") from exc
    except OSError:
        destination_real.unlink(missing_ok=True)
        manifest_path.unlink(missing_ok=True)
        raise
    return manifest


def verify_evidence(path: Path, expected_sha256: str) -> bool:
    """Recalculate SHA-256 from artifact bytes; invalid manifests are errors."""
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise ContractError("expected_sha256 must be 64 hexadecimal characters")
    path = Path(path)
    if path.is_symlink():
        raise ContractError("evidence path may not be a symlink")
    if not path.exists():
        raise FileNotFoundError(path)
    if not path.is_file():
        raise ContractError("evidence path must be a regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest().lower() == expected_sha256.lower()


def load_evidence_manifest(path: Path) -> EvidenceManifest:
    """Load and validate a sidecar manifest, rejecting unknown/missing fields."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        expected = {"manifest_id", "evidence_id", "collected_at", "sha256", "source_path", "schema_version"}
        if not isinstance(raw, dict) or set(raw) != expected:
            raise ContractError("manifest fields do not match EvidenceManifest schema")
        manifest = EvidenceManifest(**raw)
    except json.JSONDecodeError as exc:
        raise ContractError("manifest is not valid JSON") from exc
    if Path(manifest.source_path).resolve() != path.with_name(path.name.removesuffix(".manifest.json")).resolve():
        raise ContractError("manifest source_path does not match its artifact")
    return manifest


def verify_evidence_vault(directory: Path) -> dict[str, object]:
    """Report valid, modified, missing, and invalid-manifest vault entries."""
    directory = Path(directory)
    if not directory.exists():
        raise FileNotFoundError(directory)
    results: list[dict[str, object]] = []
    manifests = sorted(directory.glob("*.manifest.json"), key=lambda p: p.name)
    for manifest_path in manifests:
        artifact = manifest_path.with_name(manifest_path.name.removesuffix(".manifest.json"))
        try:
            manifest = load_evidence_manifest(manifest_path)
            status = "valid" if verify_evidence(artifact, manifest.sha256) else "modified"
            results.append({"evidence_id": manifest.evidence_id, "path": str(artifact), "status": status})
        except FileNotFoundError:
            results.append({"path": str(artifact), "status": "missing"})
        except (ContractError, OSError):
            results.append({"manifest_path": str(manifest_path), "status": "invalid_manifest"})
    manifested = {path.name.removesuffix(".manifest.json") for path in manifests}
    ignored = {"custody.jsonl", "verification-audit.jsonl"}
    for artifact in sorted((path for path in directory.iterdir() if path.is_file() and path.name not in ignored
                            and not path.name.endswith(".manifest.json") and path.name not in manifested), key=lambda path: path.name):
        results.append({"path": str(artifact), "status": "invalid_manifest", "reason": "artifact has no manifest"})
    return {"directory": str(directory.resolve()), "results": results,
            "valid": sum(item["status"] == "valid" for item in results),
            "modified": sum(item["status"] == "modified" for item in results),
            "missing": sum(item["status"] == "missing" for item in results),
            "invalid_manifests": sum(item["status"] == "invalid_manifest" for item in results)}


