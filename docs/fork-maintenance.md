# Maintain the fork

This fork adds manual website sign-in, optional original-image export, and correct boolean
defaults in tool forms. Keep those changes in focused commits so an equivalent upstream feature
can replace them later.

## Merge upstream updates

`main` is the maintained app. `sync/upstream-main` mirrors `storytold/craft-anything` main.
The **Sync upstream** workflow checks daily and can also be run manually. It opens one update PR
and explicitly dispatches **Fork verification** against the PR's merge with this fork's main.
The dispatch is necessary because a PR created with `GITHUB_TOKEN` does not trigger ordinary PR CI.
Verification runs the upstream quality gates on Linux and the authenticated browser fixture on
macOS. For bot-created PRs, inspect the dispatched run in Actions; its results may not appear in
the PR's ordinary checks list.

Enable Actions on the fork and allow GitHub Actions to create pull requests in repository Actions
settings. An update workflow with insufficient permissions fails visibly. It never resets main,
force-pushes, merges a PR, or publishes an app. An upstream history rewrite also fails for manual review.

Before merging an update:

1. Read the update diff and resolve any conflicts with the fork's feature commits.
2. Confirm the dispatched **Fork verification** run tested the PR merge, not upstream alone.
3. Run the authenticated browser integration check below on a machine with Chromium.
4. Build and try the desktop app's sign-in and Continue flow before distributing it.
5. Merge upstream-update PRs with **Create a merge commit**. Squashing or rebasing loses upstream
   ancestry and causes later syncs to propose the same changes again. Feature PRs may be squashed.

If upstream ships equivalent behavior, remove the corresponding fork patch after verifying parity.
Avoid repository-wide formatting, branding changes, and edits to upstream release scripts.

## Build the maintained app

Upstream downloads do not contain this fork's changes. Build the fork's main or its feature PR:

```sh
cargo build --locked --release -p craft-anything -p craft-anything-cli
```

For a macOS fork app alongside the official app:

```sh
bash packaging/macos/package-fork.sh --arch aarch64
```

Use `--arch x86_64` for Intel, or `--arch universal` for both. Unsigned builds are not notarized.
The wrapper reuses upstream app-only packaging, bundles the CLI, and ad-hoc signs **Craft Anything Fork**
with bundle identifier `ai.cgove.craft-anything`. Install that app from `dist/release/` into
`/Applications/`. The official **Craft Anything** can stay installed; its updates do not replace
the fork app. Both apps use the existing Craft Anything settings and project locations.
The app-only path does not create or mount a disk image. Use `--skip-build` to repackage binaries
already built for the chosen architecture.
Upstream's Apple and Windows signing credentials do not transfer to a fork. Keep publication a
separate deliberate step after validation. Scheduled upstream checks do not update an installed app.

## Check authenticated capture

Ordinary tests use synthetic data and do not launch browsers. The explicit integration check starts
a fresh headless Chromium and a loopback fixture. It proves that sign-in state allows capture of
protected content and that exported image bytes match the original protected PNG:

```sh
cargo test --locked -p craft-anything-engine authenticated_images_are_exported_through_the_private_browser -- --ignored --nocapture
```

The fixture uses no real accounts, target websites, credentials, or normal browser profiles.
The app handoff itself is covered by tests requiring explicit Continue, Cancel, timeout and stop.

## Use authenticated capture

Choose **A website**, enter the protected URL, enable **Sign in before capture**, then Start.
Sign in in the new private browser, including any MFA. Leave it open and choose
**I'm signed in, continue** in the project. Capture starts only after that answer.

For original image files, choose Deep mode and enable **Save original images** only when you own
the images or have permission to reuse them. Each capture saves `images/` and lists files, hashes,
and skipped images under `exported_images` in `capture.json`. Export uses the browser cache, with
limits of 100 images, 10 MiB per image, and 50 MiB per page. It does not fetch unseen images, iframe
images, or every lazy-loaded image. PNG, JPEG, GIF, WebP, AVIF, SVG, and ICO are supported.

CLI and MCP use the same workflow:

```sh
craft-anything-cli --deep rebuild https://example.com/private "Recreate this website" --sign-in --export-images
```

`rebuild_start` accepts `website_sign_in` and `website_export_images` for new projects. Answer its
login card through `project_inbox_answer`. Sign-in cannot run unattended. Browser sessions are
private to a build, expire when it ends, and must be signed in again if Study is retried. Closing
the browser before continuing stops capture rather than starting a signed-out replacement.

## Refresh a partially built project

Open the website project and choose **Recapture original** beside **Open folder**. If it is
building or queued, pause it first. Enable **Sign in before capture**, optionally choose permitted
original-image export in Deep mode, then choose **Recapture and continue**. Sign in in the private
browser and answer **I'm signed in, continue** in the project.

The new reference is prepared separately. Only a successful capture replaces `capture/`;
cancellation or a failed capture keeps the old reference. Existing `app/` files, builder session
and API conversation history stay in place. The builder receives the refreshed reference and
continues improving the existing app. It may change app files as part of that improvement.

The CLI equivalent uses the existing project folder:

```sh
craft-anything-cli --deep rebuild - "Improve the existing app using the signed-in original" --continue-in /path/to/project --recapture --sign-in --export-images
```

Omitted sign-in and export flags keep the project's choices. Pass `--sign-in=false` or
`--export-images=false` to turn either off. MCP uses `rebuild_start` with `project`, `recapture: true`
and optional `website_sign_in` and `website_export_images` booleans. No recapture occurs during an
ordinary Continue or follow-up.
