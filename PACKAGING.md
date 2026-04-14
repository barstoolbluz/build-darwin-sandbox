# Darwin packaging plan for `syumai/sbx`

> **To the future Claude reading this:** this file is a self-contained brief. The user handed it to you at the start of a fresh session on a Darwin host. Execute the plan below. Do not improvise beyond it. Ask the user before deviating.

## 1. Goal

Package upstream [`syumai/sbx`](https://github.com/syumai/sbx) — a Go CLI that wraps macOS `sandbox-exec` — as a Flox **Nix expression build** in the working directory (`/Users/<user>/.../sbx` or wherever this file lives). Track `main`. Darwin-only.

The user's FloxHub publishing namespace is `flox`, but **you must not publish**. Publishing is the user's responsibility alone — do not run `flox publish` under any circumstances, even if the build succeeds and looks ready.

## 2. Ground rules

- **Nix expression build only.** Do not author a `[build.*]` manifest build section. The package definition lives in `.flox/pkgs/sbx.nix`.
- **Track `main`.** Resolve `main` to a concrete commit SHA at packaging time and pin it in the Nix expression (Nix still needs determinism). Document how to re-pin later.
- **Darwin-only.** Constrain `options.systems` and `meta.platforms` accordingly. `sbx` calls the system `sandbox-exec` binary, which only exists on macOS.
- **Flox MCP tool usage:** once `.flox/` exists in the working directory, *all* subsequent commands in that directory MUST go through the `mcp__flox__run_command` tool, not the `Bash` tool. The initial `flox init` may run via `Bash` because `.flox/` does not yet exist. Use absolute paths for every `environment_dir` / `working_dir` argument.
- **Read `FLOX.md` in the working directory before you start.** It is the authoritative reference for Flox manifest structure, Nix expression builds (§10), and common pitfalls. Sections most relevant here: §0 (working style), §2 (basics), §5 ([install]), §9.8 (cross-platform), §10 (Nix expression builds), §16 (quick tips).
- **No publishing.** No `flox publish`, no `flox push`, no `git push`. No FloxHub auth setup. If the user asks for publishing later, that is a separate, explicit request.

## 3. Preconditions to verify first

Run these checks at the start of the session and report results to the user before doing anything that writes files:

1. `uname -sm` → confirm Darwin (arm64 or x86_64).
2. `flox --version` → confirm Flox CLI is installed and on PATH.
3. `git --version` → confirm git is available (needed because Flox Nix expression builds require files to be git-tracked — see FLOX.md §10).
4. `pwd` matches the directory containing this `PACKAGING.md`.
5. `ls -la` → confirm no pre-existing `.flox/` directory. If one exists, **stop and ask the user** how to proceed (they may have partial state from a previous attempt).
6. Network reachability to `github.com` (the build will `fetchFromGitHub`).

## 4. Step-by-step plan

### Step 4.1 — Resolve current `main` SHA

Before writing any files, resolve the current tip of `syumai/sbx` `main` so we can pin it:

```bash
git ls-remote https://github.com/syumai/sbx.git refs/heads/main
```

Record the 40-char SHA. Also record today's date in `YYYY-MM-DD` form — it will go into the version string as `unstable-<date>` per nixpkgs convention for untagged main-tracking packages.

### Step 4.2 — `flox init` (via `Bash`, since `.flox/` does not exist yet)

```bash
flox init
```

This creates `.flox/env/manifest.toml` and `.flox/env.json`. From this point forward, all `flox` commands in this directory MUST use `mcp__flox__run_command` with an absolute `working_dir`.

### Step 4.3 — Edit the manifest

Read `.flox/env/manifest.toml` first. Then rewrite it to match this shape (preserve any `version` field that `flox init` placed at the top):

```toml
version = 1

[install]
# Minimal [install]. buildGoModule supplies its own Go toolchain from nixpkgs,
# so we do not need `go` here for the build itself. `git` is convenient for
# the author/dev workflow in the activated env.
git.pkg-path = "git"

[options]
systems = ["aarch64-darwin", "x86_64-darwin"]
```

Apply via `flox edit -f <tmpfile>` (see FLOX.md §7) or by writing the file directly and running `flox list -c` afterward to confirm the manifest parses. If `flox edit` rejects the file, surface the exact error to the user — do not silently retry with a different shape.

### Step 4.4 — Write the Nix expression

Create `.flox/pkgs/sbx.nix` with the following content. Substitute `REPLACE_WITH_MAIN_SHA` and `REPLACE_WITH_DATE` with the values from Step 4.1. Leave both hashes as empty strings on the first pass — Flox will report the real hashes on build failure, per FLOX.md §10.

```nix
{ lib
, buildGoModule
, fetchFromGitHub
}:

buildGoModule {
  pname = "sbx";
  version = "unstable-REPLACE_WITH_DATE";

  src = fetchFromGitHub {
    owner = "syumai";
    repo = "sbx";
    rev = "REPLACE_WITH_MAIN_SHA";
    hash = "";
  };

  vendorHash = "";

  # sbx's main package lives at cmd/sbx. Limiting subPackages keeps the
  # closure small and avoids building any example/test binaries.
  subPackages = [ "cmd/sbx" ];

  meta = with lib; {
    description = "CLI wrapper for macOS sandbox-exec with a flag-based interface";
    homepage = "https://github.com/syumai/sbx";
    license = licenses.mit;
    platforms = platforms.darwin;
    mainProgram = "sbx";
  };
}
```

Notes for you while authoring:

- File name `sbx.nix` → package name `sbx` (FLOX.md §10 file naming rule).
- `subPackages = [ "cmd/sbx" ]` is important — without it `buildGoModule` builds every main package in the module.
- Do **not** add `doCheck = false;` preemptively. Let tests run by default; only disable if the upstream test suite actually breaks the build and the user approves.
- Do **not** add runtime wrappers, PATH fixups, or `postInstall` steps unless a real build failure forces you to. `sbx` is a self-contained static Go binary that execs the system `sandbox-exec`.

### Step 4.5 — Git-track the new files

Flox Nix expression builds require files to be tracked by git (FLOX.md §10). If there is no git repo in the working directory yet, initialize one:

```bash
git init
git add FLOX.md PACKAGING.md .flox/env/manifest.toml .flox/env.json .flox/pkgs/sbx.nix
```

Do **not** commit on the user's behalf unless they ask. `git add` alone is enough for `flox build` to see the files.

Do **not** run `git push` or configure any remote. This repo stays local.

### Step 4.6 — First build (expect two hash failures)

Run the build via the Flox MCP tool:

```
mcp__flox__run_command with:
  working_dir: <absolute path to the sbx directory>
  command: flox build sbx
```

The first attempt will fail with a hash mismatch on `src` (the `fetchFromGitHub` output). The error will print the expected `sha256-...` value. Copy it into `.flox/pkgs/sbx.nix` as the `src.hash` value. Re-`git add` the file.

Run `flox build sbx` again. The second attempt will fail with a hash mismatch on `vendorHash` (Go module cache). Copy that value into `vendorHash`. Re-`git add` the file.

Run `flox build sbx` a third time. It should now succeed and produce a `./result-sbx` symlink pointing into `/nix/store/...-sbx-unstable-<date>/`.

If a build fails for a reason *other* than a hash mismatch (compile error, missing dependency, test failure), **stop and report the full error to the user.** Do not start patching the upstream source, disabling tests, or adding build flags without explicit direction.

### Step 4.7 — Smoke test

```
./result-sbx/bin/sbx --help
```

Expected: `sbx` prints its usage text. If it segfaults, crashes, or prints nothing, surface the output to the user — do not try to "fix" it.

Optionally, run a trivial sandbox invocation to prove the binary actually works against `sandbox-exec`:

```
./result-sbx/bin/sbx --allow-file-read='.' -- ls -l .
```

Expected: directory listing succeeds. Report results.

### Step 4.8 — Report back

Summarise to the user:

- Pinned commit SHA and date
- Final `src.hash` and `vendorHash` values
- Build result path (`./result-sbx`)
- Smoke test output
- Nothing else. Do not suggest next steps involving publishing.

## 5. Re-pinning to a newer `main` later

Document this for the user in your summary so they can do it themselves (or ask you to):

1. `git ls-remote https://github.com/syumai/sbx.git refs/heads/main` to get the new SHA.
2. Update `rev` and `version` (date) in `.flox/pkgs/sbx.nix`.
3. Blank out `src.hash` and `vendorHash` (set both to `""`).
4. `git add .flox/pkgs/sbx.nix` and re-run `flox build sbx`. Copy the new hashes from the two failures. Done.

## 6. Hard "do not" list

- Do not run `flox publish` (anywhere, any namespace, for any reason).
- Do not run `flox push`, `flox auth login`, or touch FloxHub at all.
- Do not run `git push` or add a git remote.
- Do not modify `FLOX.md`.
- Do not add a `[build.*]` manifest build section. Nix expression only.
- Do not pin to a release tag — the user explicitly chose to track `main`.
- Do not add Linux systems to `options.systems` or `meta.platforms`. Darwin only.
- Do not amend the upstream source (no patches, no `postPatch`) unless the user asks.
- Do not bypass the Flox MCP rule: once `.flox/` exists, use `mcp__flox__run_command`, not `Bash`, for `flox` invocations in this directory.
