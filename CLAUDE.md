# intake Guidelines

## Commands (npm, Node 22 per `mise.toml`)

- Lint: `npm run lint` (ESLint)
- Format check: `npm run format:check` (Prettier; write with `npm run format`)
- Test: `npm test` (`node --test`)
- Before a PR: `npm run verify`
- Audit: `npm run audit:check`
- Start: `npm run web` or `npm run writer`; Docker/Portainer deploy: see README
- CI: `.github/workflows/ci.yml`, `docker.yml`, and `security.yml` must be green

## Decision paths

- Tasks and priorities come from Oskar. Do not lock unclear product assumptions; ask Oskar first. In development, Oskar's word counts as Robert's decision; do not ask Robert directly.
- GitHub Flow: feature branch from `main`, PR, review. Never push directly to `main`.
- Merge and deploy only by Oskar (squash with `--match-head-commit`). Never merge yourself.
- Rebase rule: update the branch by rebasing onto `main` (do not merge `main` in), squash related commits, push own branches with `--force-with-lease`. An approval on an old head no longer counts after a force-push.
- Never read, commit, log, or print secrets (tokens, keys, `.env`, mailbox credentials). Non-secret config belongs in the repo as plaintext.
- New channels, mTLS, where processes run: decision by Oskar.
- Visible changes: the PR shows them (screenshot, before/after if needed).
- Closing keywords only as their own line `Closes #NN` when the PR really closes the issue; otherwise `Refs #NN`, never in running text.
- `.github/workflows` is changed only by Oskar (dev apps cannot push them); send workflow changes to Oskar as a patch or proposal.
- A merge-ready notice names the full approved head SHA.

## Claude Code

- Use the `claude-api` skill only for code that uses the Anthropic SDK, not for other APIs.
- Worktree start: `mise install`, then `npm ci`. Worktrees only under `wt-pr<n>`; remove after merge.
- Code, commits, and PR text in English.
- Intake handles user secrets: no plaintext secrets in logs, tests, or fixtures; do not change the security model in the README without agreeing with Oskar.
- When pinning Docker image digests, check the index really contains platform manifests (amd64), not only that the digest matches the tag.
