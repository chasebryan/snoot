# snoot release checklist

Manual steps to ship v0.1.0. Nothing here is automated — run each command
yourself, in order. (The repo's GitHub App lacks Workflows permission, so
workflow files go up through the web UI.)

## 0. Preconditions (already done in week 6)

- `cargo test`, `cargo clippy --all-targets -- -D warnings`,
  `cargo fmt --check` green
- `cargo publish --dry-run` clean, `cargo doc` warning-free
- `snoot scan . --exclude 'tests/fixtures/**' --fail-on medium` clean

## 1. Upload files the app couldn't push (GitHub web UI)

Repo → Add file → Create new file, one at a time:

- `assets/banner.jpg` — the blue balloon-letter banner (local copy at
  `~/workspace/snoot/assets/banner.jpg`)
- `.github/workflows/ci.yml` — local copy at
  `~/workspace/snoot/.github/workflows/ci.yml`
- `.github/workflows/release.yml` — local copy at
  `~/workspace/snoot/.github/workflows/release.yml` (built in week 6)

Commit each directly to `main`.

## 2. Push the week-6 tree

```bash
cd ~/workspace/snoot
git add -A
git commit -m "week 6: release prep (checklist, release workflow, docs)"
git push origin main
```

## 3. Publish to crates.io

Get a token at https://crates.io/me (API tokens → New Token, scope:
publish). Then:

```bash
cargo login
# paste the token when prompted

cargo publish --dry-run   # sanity check, should already be clean
cargo publish
```

Verify: https://crates.io/crates/snoot and https://docs.rs/snoot

Notes:
- License is `AGPL-3.0-only` (your choice). crates.io and docs.rs both
  accept it; some corporate users will filter it out — that's the tradeoff
  you already decided on.
- `tests/fixtures/` (including openssl-generated test keys) ships in the
  crate package. Deliberate: the fixtures are the test suite's ground
  truth. They're clearly test keys, but if you'd rather slim the package,
  add `exclude = ["tests/fixtures/"]` to `[package]` in Cargo.toml before
  publishing.

## 4. Tag and cut the GitHub release

```bash
git tag -a v0.1.0 -m "snoot v0.1.0 — first release"
git push origin v0.1.0
```

Pushing the tag triggers `.github/workflows/release.yml`, which builds
prebuilt binaries and opens a **draft** release with the archives
attached:

- `snoot-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`
- `snoot-v0.1.0-aarch64-unknown-linux-gnu.tar.gz`
- `snoot-v0.1.0-aarch64-apple-darwin.tar.gz`
- `snoot-v0.1.0-x86_64-apple-darwin.tar.gz`
- `snoot-v0.1.0-x86_64-pc-windows-msvc.zip`

Then: GitHub → Releases → open the draft, sanity-check the archive list,
write release notes (or keep the generated ones), and hit Publish.

## 5. Smoke-test the install

```bash
cargo install snoot --locked
snoot --version
snoot scan --help
```

## 6. Announce (optional)

Draft in `docs/ANNOUNCEMENT_DRAFT.md`. Post wherever you want — it's
yours, not wired to anything.
