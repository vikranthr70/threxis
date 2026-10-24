# Person 2 methodology: synthetic detection and forensic workflow

## Dataset design

The generator produces deterministic `SecurityEvent` records for three user-facing synthetic scenarios: suspicious authentication, suspicious file modification, and potential exfiltration. It uses only RFC 5737 documentation IPv4 ranges and fixed, timezone-aware UTC timestamps. A seed controls the synthetic timing and harmless metadata. SHA-256-derived substreams keep collection-cost draws independent of relevance assignment; IDs are assigned after a seeded shuffle and are random-looking, stable for a given `(scenario_id, seed)` run, and not ordered by generation position. The records are wholly artificial and do not initiate connections, access host telemetry, or perform system changes.

Each event's source type identifies a possible evidence source. `collection_cost` and `evidence_available` are optional synthetic metadata placed in event attributes so integration code can derive candidates and availability without expanding `EvidenceCandidate`'s strict allowlist. Ground truth is returned separately as `GroundTruthLabel` values, keyed by matching event/evidence IDs. Runtime events contain no relevance, maliciousness, or truth labels. Detection does not accept or inspect the label output.

## Detection rules

The deterministic engine applies four heuristic rules to one scenario at a time:

1. Three or more failed SSH passwords from one source within five minutes.
2. Failed SSH attempts followed by a successful login from the same source within fifteen minutes.
3. A burst of at least three file changes by the same host/user within two minutes, with multiple paths, an unusual process, or an explicit unauthorized indicator.
4. At least three outbound events totaling ten megabytes within ten minutes, together with simulated data access, a recognized unusual process indicator, or repeated peer behavior.

Alerts contain only fields in the frozen `DetectionAlert` model. Their reasons describe suspicious patterns and explicitly avoid treating an alert as proof. Normal synthetic records are deliberately sparse to support false-alert checks. Thresholds are demonstration defaults, not calibrated detection performance claims.

## Evidence preservation and integrity

`preserve_evidence` copies a caller-selected synthetic file, hashes the copied bytes with SHA-256, and writes a contract-shaped `EvidenceManifest` sidecar. Evidence IDs should be the source event IDs when artifacts correspond to individual event records. The source file's parent is treated as the designated synthetic workspace; destination paths must resolve below it. Symlinks, non-regular files, unsafe evidence IDs, and existing destinations are rejected. Artifact creation is exclusive to prevent accidental overwrite.

A JSONL custody note records the evidence ID, collection timestamp, output path, digest, and preservation action. The log is append-only during ordinary operation but is not cryptographically tamper-proof and can be modified by a sufficiently privileged local user. SHA-256 verification detects byte changes only when the expected digest is trusted and retained independently. Neither the hash nor the local log establishes legal chain of custody. Vault verification reports valid artifacts, modified artifacts, missing artifacts, and invalid manifests.

The frozen `EvidenceManifest` has no source-event-ID list or custody-history field. The implementation therefore uses the manifest's `evidence_id` for event linkage and keeps custody history in a separate sidecar. This preserves the shared schema.

## Incident correlation and timeline reconstruction

The timeline builder accepts one `InvestigationCase`, its events, and its alerts. It rejects scenario mismatches, duplicate IDs, unknown alert references, and alert references to missing events. It emits event observations, alert hypotheses, and the case-opened entry, then sorts them by timezone-aware timestamp and stable tie-breakers. Every event or alert timeline entry includes supporting shared IDs.

The Markdown report distinguishes observed synthetic event facts from investigative hypotheses. It lists evidence hashes, event references, and event IDs without matching evidence manifests. Since the frozen timeline API receives no evidence manifests, missing-evidence assessment is done by the separate report helper, not by silently changing that interface.

## Testing methodology

Person 2 tests use seeded fixtures and temporary directories. They cover deterministic generation, unique IDs, timestamp validity, all scenarios, truth-label isolation, each detection rule, benign false-alert cases, evidence copy/hash verification, overwrite prevention, tampering, missing files and malformed manifests, chronological timeline ordering, reference validation, and Markdown report links. No real system logs or external services are used.

## Assumptions and limitations

This is a small research demonstration, not an endpoint sensor or production forensic acquisition tool. Event attributes and rules are synthetic conventions. Alert thresholds have not been tuned against real telemetry; no precision, recall, or real-world attack detection claim is made. The report's source facts are limited to supplied synthetic records. The local custody log can be altered, and filesystem behavior and permissions depend on the host. The Architecture Pack v1.2 and adapted `TEAM_CONTRACT.md` were reviewed. This function supplies only the three user-facing detection demo scenarios; the pack's phase-pair experiment instances remain a separate scientific-runner responsibility.
