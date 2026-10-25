## Privacy Policy: academic demonstration draft

Review status: human review pending. This draft describes the application as configured for local development. It must be reviewed against the actual operator, deployment, hosting, and applicable requirements before public use.

### What the application processes

THREXIS generates artificial security events from a scenario, event count, and seed. The dashboard processes those records, your artifact exclusions and budget choices, and optional uploaded research JSONL records. It does not collect endpoint telemetry, credentials, or real incident records.

Do not upload personal information, credentials, confidential evidence, or real security telemetry. Research uploads are limited to 5 MiB and validated against the shared result schema.

### Storage and retention

Dashboard inputs and uploaded research data are processed in the Streamlit server session. Selected synthetic artifacts are copied into a session-specific temporary directory. Changing the workspace removes its prior vault. Temporary files may remain until the session object is released or the process exits; cleanup after a crash is not guaranteed. Exported files remain on the downloading device.

Server and network access logs may be retained by the operating system, a reverse proxy, or a hosting provider. Their location, retention period, and access policy depend on deployment and must be specified before launch.

### Browser and third-party services

IBM Plex fonts are served locally. Streamlit usage statistics are disabled in the supplied configuration. The app does not add advertising, analytics, or tracking cookies. Streamlit uses a session connection and browser storage as part of normal operation. Visiting an external MITRE or GitHub reference is subject to that service's policies.

### Access and security

The development server binds to loopback by default. No authentication, multi-user access control, production retention policy, or public hosting configuration is provided. The application is not ready to receive sensitive data.

### Operator details required before launch

The operator must supply its identity, contact channel, hosting providers, processing location, log retention, request-handling process, and any required disclosures. No operator or legal jurisdiction is assumed in this draft.

### Updates

Review this policy whenever processing, storage, dependencies, or hosting changes. The public policy must carry its real review and effective dates.
