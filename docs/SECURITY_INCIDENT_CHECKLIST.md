# Credential and historical-data response checklist

This runbook intentionally contains no credential values. Complete it with the repository owner and the administrators of each provider. Do not paste secrets into tickets, chat, command output, or Git commits.

## Verified evidence

The 2026-10-10 remediation pass verified a PostgreSQL backup in reachable backend history. Its schema and redacted category scan show user email addresses, password hashes, names/roles/organization data, messages, posts, assignments, submissions, and educational content. The pass did **not** independently verify that a `.env` file or Firebase service-account JSON was committed. Local ignored copies are not proof of historical exposure.

## Owner triage

- [ ] Determine whether the historical dump contains real, staging, or synthetic records.
- [ ] Identify every person, environment, and Git remote that could access the affected commits.
- [ ] Preserve only the minimum incident evidence required by policy; never copy the dump into a ticket.
- [ ] If records are real, involve the privacy/security owner and assess notification obligations.
- [ ] If password hashes are real, force password resets, invalidate all sessions, and review password-hash strength.
- [ ] Review authentication, admin, storage, email, AI, push, database, deployment, and object-storage audit logs for suspicious use.

## Credential inventory and rotation

Rotate a credential only when its presence in the affected data/history or unauthorized use is verified. A local ignored file alone is not evidence that the credential left the machine.

- [ ] Application JWT access-token signing secret; invalidate sessions after rotation.
- [ ] Refresh-token signing secret; invalidate all refresh sessions after rotation.
- [ ] Database users/passwords and connection URLs.
- [ ] Cloudflare R2/S3-compatible access keys and signed-link secrets.
- [ ] Email provider/SMTP credentials.
- [ ] OpenAI, D-ID, ElevenLabs, or other AI/provider API keys.
- [ ] Firebase service-account private keys and push credentials.
- [ ] CI/CD, hosting, container-registry, and deployment tokens.
- [ ] Any secrets embedded in backups, shell history, logs, or copied configuration.

For each verified exposure: create a replacement, deploy it through the approved secret store, confirm the application uses it, revoke the old credential, inspect provider logs, and record timestamps/owners outside Git.

## Closure evidence

- [ ] Current branches and tags pass `python scripts/check_secrets.py`.
- [ ] Provider-side rotation/revocation is independently verified.
- [ ] Required password resets and session invalidation are complete.
- [ ] History cleanup was coordinated and verified on every remote/clone.
- [ ] CI secret scanning and repository-host secret protection are enabled.
- [ ] The incident owner signs off before AUD-001 is closed.
