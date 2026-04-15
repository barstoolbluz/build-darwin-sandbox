{ lib
, coreutils
, writeShellApplication
, symlinkJoin
}:

# These helpers generate SBPL (Sandbox Profile Language) policies and
# call macOS's /usr/bin/sandbox-exec directly. They do NOT wrap the
# syumai/sbx CLI — we used to, but sbx has no way to allow the
# `process-fork` operation except via its `--allow-all` flag, which
# removes all the tightening we want. Generating SBPL ourselves gives
# us full control and matches what macOS uses internally for its own
# App Sandbox.
#
# Policy shape (common to all three helpers):
#
#   (version 1)
#   (allow default)                               ; fork/exec/mach/etc.
#   (deny file-write*)                            ; strip writes globally
#   (allow file-write* (subpath "/dev"))          ; restore tty/null/urandom
#   [per-helper scoped file-write allowances]
#   [per-helper network rules]
#
# We start from (allow default) rather than (deny default) because we
# want "prevent data exfiltration and unauthorised writes" semantics,
# not "enumerate every mach operation a shell needs." A paranoid mode
# would require enumerating allows for mach-lookup, sysctl, signal,
# iokit, etc. — not worth it for this use case.
#
# Write paths are canonicalised via GNU `realpath -m` before being
# embedded in the policy. This handles macOS's /tmp → /private/tmp and
# /var → /private/var symlinks. `-m` tolerates non-existent paths so
# profile wrappers can allow state dirs that haven't been created yet.
#
# sandbox-exec prints a deprecation warning to stderr on every invocation
# ("sandbox-exec: ... is deprecated"). This has been the case since ~2017
# and the mechanism still powers macOS's own App Sandbox. Not hidden.
#
# ------------------------------------------------------------------
# Alternative implementation path: phylum-dev/birdcage (Rust crate)
# ------------------------------------------------------------------
#
# Birdcage (https://github.com/phylum-dev/birdcage) is a Rust library
# that wraps sandbox_init() on macOS (same kernel mechanism we use)
# and Landlock+seccomp on Linux. We adopted its SBPL preamble for our
# --strict-reads mode below, but the helpers are still plain bash
# scripts calling /usr/bin/sandbox-exec, not a Birdcage binding.
#
# If you ever outgrow the bash-script approach, the path forward is:
#
#   1. Write a small Rust `sbx-agent-rs` binary that links `birdcage`
#      from crates.io, parses the same flags we have today (--net,
#      --write, --read, --strict-reads, --no-tmpdir), and maps them to
#      Birdcage's `Sandbox::new()` + `add_exception()` + `lock()` API.
#   2. Add it to .flox/pkgs/ as a Nix expression build using
#      `rustPlatform.buildRustPackage`. Cargo.toml + src/main.rs in a
#      new subdir tracked by git.
#   3. Swap the runtime env's sbx-helpers store-path reference.
#
# What you'd gain: battle-tested SBPL generation (Phylum uses it in
# production for malware-analysis sandboxing), automatic Linux support
# if you ever port, and fewer sharp edges around shell quoting in the
# generated policy.
#
# What you'd lose: ~15 seconds of iteration speed per policy change
# (cargo build vs. bash edit), a Rust dependency in the build chain,
# and the ability to read the entire sandbox implementation in ~300
# lines of one file.
#
# Birdcage does NOT solve the gaps we have: no host-level network
# allowlisting (same platform limit), no env scrubbing, no resource
# limits, no audit logging. For those, you write your own wrapper on
# top of Birdcage exactly as you would on top of this bash helper.

let
  # sbx-run: no writes, no network. Baseline sandbox for "read and exec,
  # nothing else". Useful for running a command you want to observe
  # without letting it touch anything.
  sbxRun = writeShellApplication {
    name = "sbx-run";
    text = ''
      policy_lines=(
        '(version 1)'
        '(allow default)'
        # Deny access to the pasteboard Mach services. macOS registers
        # two relevant names via /usr/libexec/pboard:
        #   com.apple.pasteboard.1  (classic, used by pbcopy/pbpaste)
        #   com.apple.coreservices.uauseractivitypasteboardclient.xpc
        # We deny by prefix so future variants are also covered.
        '(deny mach-lookup (global-name-prefix "com.apple.pasteboard"))'
        '(deny mach-lookup (global-name-prefix "com.apple.coreservices.uauseractivitypasteboard"))'
        '(deny file-write*)'
        '(allow file-write* (subpath "/dev"))'
        '(deny network*)'
        '(allow network* (local unix-socket))'
      )
      policy=$(printf '%s\n' "''${policy_lines[@]}")
      exec /usr/bin/sandbox-exec -p "$policy" "$@"
    '';
  };

  # sbx-cwd: writes restricted to $PWD and $TMPDIR; no network. Useful
  # for running a tool that needs scratch space but must not touch files
  # outside the current project.
  sbxCwd = writeShellApplication {
    name = "sbx-cwd";
    runtimeInputs = [ coreutils ];
    text = ''
      check_path_safe() {
        local p="$1"
        case "$p" in
          *$'\n'*|*'"'*|*\\*)
            echo "sbx-cwd: path contains unsupported character (quote/backslash/newline): $p" >&2
            exit 2
            ;;
        esac
      }

      pwd_canon=$(realpath -m "$PWD")
      check_path_safe "$pwd_canon"

      tmp_canon=""
      if [[ -n "''${TMPDIR:-}" ]]; then
        tmp_canon=$(realpath -m "$TMPDIR")
        check_path_safe "$tmp_canon"
      fi

      policy_lines=(
        '(version 1)'
        '(allow default)'
        # Deny pasteboard Mach services (see sbx-run for rationale).
        '(deny mach-lookup (global-name-prefix "com.apple.pasteboard"))'
        '(deny mach-lookup (global-name-prefix "com.apple.coreservices.uauseractivitypasteboard"))'
        '(deny file-write*)'
        '(allow file-write* (subpath "/dev"))'
        "(allow file-write* (subpath \"''${pwd_canon}\"))"
      )
      if [[ -n "$tmp_canon" ]]; then
        policy_lines+=("(allow file-write* (subpath \"''${tmp_canon}\"))")
      fi
      policy_lines+=(
        '(deny network*)'
        '(allow network* (local unix-socket))'
      )
      policy=$(printf '%s\n' "''${policy_lines[@]}")
      exec /usr/bin/sandbox-exec -p "$policy" "$@"
    '';
  };

  # sbx-agent: full-featured sandbox for interactive AI coding agents.
  # Writes scoped to $PWD + $TMPDIR + user-specified extras; network
  # configurable (block / allow / IP:port list).
  sbxAgent = writeShellApplication {
    name = "sbx-agent";
    runtimeInputs = [ coreutils ];
    text = ''
      usage() {
        cat <<'USAGE'
      Usage: sbx-agent [options] -- <command> [args...]

      Sandbox options:
        --net <mode>     Network mode:
                           block             deny all (default)
                           allow             allow all
                           host:port[,...]   allow listed endpoints
                                             (only * and localhost)
        --net-allow-host HOST  Route HTTPS through sbx-proxy and allow
                         only HOST. Repeatable. Mutually exclusive with
                         --net. The proxy is auto-started, auto-killed,
                         uses an ephemeral local port, and injects
                         HTTPS_PROXY into the child's environment.
                         HOST may be a plain hostname (:443 implied), a
                         host:port pair, or a *.subdomain wildcard.
                         Numeric IPs and CIDRs are rejected at proxy
                         startup — hostnames only.
        --write <path>   Additional writable path. Repeatable. In
                         --strict-reads mode this also grants read.
        --read <path>    Additional read-only path. Repeatable. Only
                         meaningful in --strict-reads mode.
        --no-tmpdir      Do not allow $TMPDIR writes.
        --strict-reads   Deny-default read scoping. Only paths that are
                         explicitly allowed (--write, --read, $PWD,
                         $TMPDIR, $FLOX_ENV, and a hard-coded set of
                         system dylib/framework dirs) can be read. This
                         closes the "agent greps ~/.ssh and exfils"
                         gap at the cost of requiring the caller to
                         enumerate every config file a tool needs.
                         Preamble borrowed from phylum-dev/birdcage.

      Environment options:
        --passenv KEY    Pass KEY from the outer environment into the
                         sandbox. Repeatable. By default, only a safe
                         whitelist (PATH, HOME, USER, SHELL, TERM,
                         TMPDIR, PWD, LANG, TZ, LC_*, COLUMNS, LINES,
                         FLOX_ENV, FLOX_ENV_PROJECT, FLOX_ENV_CACHE,
                         SSL_CERT_FILE, SSL_CERT_DIR, CURL_CA_BUNDLE)
                         is passed. Use --passenv to reinject secrets
                         like ANTHROPIC_API_KEY explicitly.
        --passenv-all    Disable scrubbing entirely; pass the full
                         parent environment. Escape hatch. Defeats the
                         protection against SSH_AUTH_SOCK and token
                         leakage — use only when you know you need it.

      Resource limits:
        --timeout <dur>  Wall-clock timeout via `timeout -k 5 <dur>`.
                         Accepts GNU duration strings: 30s, 5m, 2h.
                         On expiry, sends SIGTERM; 5s later, SIGKILL.
        --max-cpu <s>    RLIMIT_CPU in seconds (ulimit -t). Accounts
                         user+system CPU; a 10s wall-clock sleep
                         consumes ~0s CPU.
        --max-procs <n>  RLIMIT_NPROC (ulimit -u). NOTE: this counts
                         ALL the user's processes, not just this
                         invocation's — set high enough not to trip
                         other processes you're already running.
        --max-files <n>  RLIMIT_NOFILE (ulimit -n).

        (There is intentionally no --max-mem flag. macOS's kernel does
        not implement settable RLIMIT_AS / RLIMIT_DATA / RLIMIT_RSS —
        any attempt returns EINVAL. Shipping a non-enforcing flag would
        give a false sense of protection. If you need memory caps,
        run the agent in a Lima/Orbstack VM and limit at the VM layer.)

      Observability:
        --audit-log <p>  Write audit records to <p> instead of the
                         default location.
        --no-audit-log   Suppress audit logging for this invocation.
        --log-max-size <n>
                         Rotation cap for the agent audit log AND the
                         sbx-proxy event log. Accepts raw bytes or a
                         NUMBER with a K/M/G suffix (case-insensitive).
                         Default: 10485760 (10 MiB). 0 disables rotation
                         on both sides. Runtime manifest surfaces this
                         as SBX_LOG_MAX_SIZE.
        --dump-policy    Build and print the SBPL policy that WOULD be
                         passed to sandbox-exec, then exit 0 without
                         running anything. Dry-run / debugging aid.
                         Compatible with every other flag. When used
                         with --net-allow-host the proxy is NOT
                         started; the policy shows a literal
                         "localhost:<PROXY_PORT>" placeholder so you
                         can still see its structure. No audit record
                         is written. No command is required after --
                         (you can invoke as "sbx-agent --dump-policy"
                         with nothing else).

      Help:
        -h, --help       Show this help.

      Default mode (without --strict-reads):
          Base:           (allow default) — fork/exec/mach/file-read all
                          permitted, only file-write is scoped.
          Reads:          globally allowed. This is fast and works with
                          any tool but does not prevent secret reads.
          Writes:         denied except $PWD, $TMPDIR (unless
                          --no-tmpdir), each --write, and /dev.

      Strict mode (--strict-reads):
          Base:           (deny default) with Birdcage's allow set —
                          mach/ipc/sysctl/system/process-fork/
                          process-exec/file-read-metadata/
                          signal(target others)/system-network.
          Reads:          denied by default. Allowed: /usr/lib,
                          /usr/local/lib, /System, /Library,
                          /private/etc, /private/var/db/dyld,
                          /nix/store, $FLOX_ENV (if set), /dev, $PWD,
                          $TMPDIR (unless --no-tmpdir), each --write
                          path, each --read path.
          Writes:         same scoping as default mode.
          Caveat:         many tools assume they can read $HOME config
                          files (e.g. git reads ~/.gitconfig). In strict
                          mode, you must add --read for each such path,
                          or the tool errors with "Operation not
                          permitted". Test before committing to strict
                          mode for a given workflow.

      Host form for --net: sandbox-exec's network filter only accepts
      '*' (any) or 'localhost' (loopback) as the host part. Numeric IP
      addresses, DNS names, and CIDR/subnets are all rejected by the
      SBPL parser. Supported forms:
          *:*           any host, any port
          *:<port>      any host, specific port    e.g. *:443
          localhost:*   loopback, any port
          localhost:<p> loopback, specific port    e.g. localhost:8080
      To allow multiple ports, pass a comma-separated list:
          --net '*:443,*:80,localhost:5432'

      Audit log: by default, one record per invocation is appended to
      $FLOX_ENV_CACHE/sbx-agent.log (if FLOX_ENV_CACHE is set). Each
      record contains timestamp, pid, cwd, policy mode, write/read
      paths, passenv list, timeout, and argv. Disable with
      --no-audit-log or redirect with --audit-log <path>. For
      kernel-level denial events, tail macOS's unified log:
          log stream --predicate 'subsystem == "com.apple.sandbox"' \\
              --style compact

      sandbox-exec prints a deprecation warning to stderr on some macOS
      versions. That is normal and has been the case since 2017.
      USAGE
      }

      check_path_safe() {
        local p="$1"
        case "$p" in
          *$'\n'*|*'"'*|*\\*)
            echo "sbx-agent: path contains unsupported character (quote/backslash/newline): $p" >&2
            exit 2
            ;;
        esac
      }

      # parse_bytes converts a size value with an optional case-insensitive
      # K/M/G suffix into raw bytes. Used by --log-max-size so users can
      # write "50M" instead of "52428800". 0 is legal and means "disable
      # rotation". Non-matching input exits 2 with a clear error.
      parse_bytes() {
        local val="$1"
        # Digit-count cap {1,18}: max input is 10^18 - 1, comfortably
        # below INT64_MAX (~9.22 * 10^18). Guarantees the subsequent
        # 10#$num normalization cannot silently wrap. A 19-digit or
        # 20-digit input is rejected at this regex step instead of
        # making it to $((...)) where bash would silently emit a
        # wrapped int64 value.
        [[ "$val" =~ ^([0-9]{1,18})([KkMmGg]?)$ ]] || {
          # Distinguish two failure modes so the error message is
          # targeted at the actual problem:
          #   - shape is right but too many digits → "too long"
          #   - shape is wrong (bad chars, empty, etc.)  → "invalid"
          # Without this split, a short-but-malformed input like
          # "0x10" would be rejected with a confusing "max 18 digits"
          # message.
          if [[ "$val" =~ ^[0-9]+[KkMmGg]?$ ]]; then
            echo "sbx-agent: size value too long: $val (max 18 digits + optional K/M/G suffix)" >&2
          else
            echo "sbx-agent: invalid size value: $val (expected a decimal integer with optional K/M/G suffix, e.g. 10M, 2G)" >&2
          fi
          exit 2
        }
        local num="''${BASH_REMATCH[1]}"
        # Force base-10. Bash arithmetic treats 010 as octal 8 and
        # 08/09 as invalid octal → rc=1 under set -e. The 10# prefix
        # normalizes once and for all branches.
        num=$((10#$num))
        local unit="''${BASH_REMATCH[2],,}"
        # Per-suffix overflow bound. max_safe is floor((2^63 - 1) /
        # multiplier), so (num * multiplier) cannot exceed INT64_MAX
        # for any num <= max_safe. Values derived and verified
        # empirically at boundary. v1 of this fix used a result-
        # based detector which failed on inputs like 999999999999999999M
        # where the multiplication wraps back to a *positive* value
        # larger than num — undetectable by a simple < comparison.
        # Pre-multiplication bound check catches every overflow.
        # Note: the no-unit pattern must be "" (double-quoted empty
        # string); Nix indented strings treat two adjacent single
        # quotes as an escape sequence even inside bash comments.
        local max_safe
        case "$unit" in
          "")  max_safe=999999999999999999 ;;
          k)   max_safe=9007199254740991 ;;
          m)   max_safe=8796093022207 ;;
          g)   max_safe=8589934591 ;;
        esac
        if [[ "$num" -gt "$max_safe" ]]; then
          echo "sbx-agent: --log-max-size value too large: $val (max num for unit '$unit' is $max_safe)" >&2
          exit 2
        fi
        case "$unit" in
          "")  printf '%s\n' "$num" ;;
          k)   printf '%s\n' "$((num * 1024))" ;;
          m)   printf '%s\n' "$((num * 1024 * 1024))" ;;
          g)   printf '%s\n' "$((num * 1024 * 1024 * 1024))" ;;
        esac
      }

      net_mode="block"
      net_mode_user_set=0
      net_mode_orig=""
      net_allow_hosts=()
      extra_writes=()
      extra_reads=()
      allow_tmpdir=1
      strict_reads=0
      passenv=()
      passenv_all=0
      wall_timeout=""
      max_cpu=""
      max_procs=""
      max_files=""
      audit_log_path=""
      no_audit_log=0
      dump_policy=0
      # Default rotation cap for audit log and proxy log: 10 MiB. Override
      # via --log-max-size (accepted formats: bytes, or N with K/M/G suffix).
      # 0 disables rotation on both sides. The runtime manifest surfaces
      # this as SBX_LOG_MAX_SIZE via the _sbx_agent_args helper.
      log_max_size="10485760"

      while [[ $# -gt 0 ]]; do
        case "$1" in
          --net=*)         net_mode="''${1#--net=}"; net_mode_user_set=1; shift ;;
          --net)           [[ $# -ge 2 ]] || { echo "sbx-agent: --net requires an argument" >&2; exit 2; }
                           net_mode="$2"; net_mode_user_set=1; shift 2 ;;
          --net-allow-host=*)
                           net_allow_hosts+=("''${1#--net-allow-host=}"); shift ;;
          --net-allow-host)
                           [[ $# -ge 2 ]] || { echo "sbx-agent: --net-allow-host requires an argument" >&2; exit 2; }
                           net_allow_hosts+=("$2"); shift 2 ;;
          --write=*)       extra_writes+=("''${1#--write=}"); shift ;;
          --write)         [[ $# -ge 2 ]] || { echo "sbx-agent: --write requires an argument" >&2; exit 2; }
                           extra_writes+=("$2"); shift 2 ;;
          --read=*)        extra_reads+=("''${1#--read=}"); shift ;;
          --read)          [[ $# -ge 2 ]] || { echo "sbx-agent: --read requires an argument" >&2; exit 2; }
                           extra_reads+=("$2"); shift 2 ;;
          --no-tmpdir)     allow_tmpdir=0; shift ;;
          --strict-reads)  strict_reads=1; shift ;;
          --passenv=*)     passenv+=("''${1#--passenv=}"); shift ;;
          --passenv)       [[ $# -ge 2 ]] || { echo "sbx-agent: --passenv requires an argument" >&2; exit 2; }
                           passenv+=("$2"); shift 2 ;;
          --passenv-all)   passenv_all=1; shift ;;
          --timeout=*)     wall_timeout="''${1#--timeout=}"; shift ;;
          --timeout)       [[ $# -ge 2 ]] || { echo "sbx-agent: --timeout requires an argument" >&2; exit 2; }
                           wall_timeout="$2"; shift 2 ;;
          --max-cpu=*)     max_cpu="''${1#--max-cpu=}"; shift ;;
          --max-cpu)       [[ $# -ge 2 ]] || { echo "sbx-agent: --max-cpu requires an argument" >&2; exit 2; }
                           max_cpu="$2"; shift 2 ;;
          --max-procs=*)   max_procs="''${1#--max-procs=}"; shift ;;
          --max-procs)     [[ $# -ge 2 ]] || { echo "sbx-agent: --max-procs requires an argument" >&2; exit 2; }
                           max_procs="$2"; shift 2 ;;
          --max-files=*)   max_files="''${1#--max-files=}"; shift ;;
          --max-files)     [[ $# -ge 2 ]] || { echo "sbx-agent: --max-files requires an argument" >&2; exit 2; }
                           max_files="$2"; shift 2 ;;
          --audit-log=*)   audit_log_path="''${1#--audit-log=}"; shift ;;
          --audit-log)     [[ $# -ge 2 ]] || { echo "sbx-agent: --audit-log requires an argument" >&2; exit 2; }
                           audit_log_path="$2"; shift 2 ;;
          --no-audit-log)  no_audit_log=1; shift ;;
          --log-max-size=*)
                           log_max_size=$(parse_bytes "''${1#--log-max-size=}"); shift ;;
          --log-max-size)  [[ $# -ge 2 ]] || { echo "sbx-agent: --log-max-size requires an argument" >&2; exit 2; }
                           log_max_size=$(parse_bytes "$2"); shift 2 ;;
          --dump-policy)   dump_policy=1; shift ;;
          -h|--help)       usage; exit 0 ;;
          --)              shift; break ;;
          -*)              echo "sbx-agent: unknown option: $1" >&2; usage >&2; exit 2 ;;
          *)               echo "sbx-agent: positional argument before '--': $1" >&2; usage >&2; exit 2 ;;
        esac
      done

      if [[ $# -eq 0 && $dump_policy -eq 0 ]]; then
        echo "sbx-agent: no command specified (did you forget '--'?)" >&2
        usage >&2
        exit 2
      fi

      pwd_canon=$(realpath -m "$PWD")
      check_path_safe "$pwd_canon"

      tmp_canon=""
      if [[ ''${allow_tmpdir} -eq 1 && -n "''${TMPDIR:-}" ]]; then
        tmp_canon=$(realpath -m "$TMPDIR")
        check_path_safe "$tmp_canon"
      fi

      canon_extras=()
      for p in "''${extra_writes[@]}"; do
        c=$(realpath -m "$p")
        check_path_safe "$c"
        canon_extras+=("$c")
      done

      canon_reads=()
      for p in "''${extra_reads[@]}"; do
        c=$(realpath -m "$p")
        check_path_safe "$c"
        canon_reads+=("$c")
      done

      # --read is a no-op in non-strict mode (reads are globally
      # allowed by (allow default)). Warn so the user isn't misled.
      if [[ $strict_reads -eq 0 && ''${#canon_reads[@]} -gt 0 ]]; then
        echo "sbx-agent: note: --read has no effect without --strict-reads (reads are globally permitted)." >&2
      fi

      flox_env_canon=""
      if [[ $strict_reads -eq 1 && -n "''${FLOX_ENV:-}" ]]; then
        flox_env_canon=$(realpath -m "$FLOX_ENV")
        check_path_safe "$flox_env_canon"
      fi

      # Validate --net and split into host list if applicable.
      net_hosts=()
      case "$net_mode" in
        block|allow)
          ;;
        *)
          IFS=',' read -ra net_hosts_raw <<< "$net_mode"
          for h in "''${net_hosts_raw[@]}"; do
            [[ -z "$h" ]] && continue
            if [[ "$h" == */* ]]; then
              echo "sbx-agent: CIDR/subnet not supported; use host:port form: $h" >&2
              exit 2
            fi
            if [[ "$h" != *:* ]]; then
              echo "sbx-agent: invalid --net entry (expected host:port): $h" >&2
              exit 2
            fi
            host_part="''${h%:*}"
            port_part="''${h##*:}"
            # sandbox-exec's SBPL network filter accepts only '*' or
            # 'localhost' as the host. Numeric IPs, DNS names, and
            # CIDRs are all rejected by the policy parser.
            if [[ "$host_part" != "*" && "$host_part" != "localhost" ]]; then
              echo "sbx-agent: sandbox-exec only accepts '*' or 'localhost' as the host in network rules." >&2
              echo "sbx-agent: numeric IPs, DNS names, and subnets are not supported by SBPL." >&2
              echo "sbx-agent: hint: --net '*:443' allows all HTTPS. Got host: $host_part" >&2
              exit 2
            fi
            # Port must be '*' or a number.
            if [[ "$port_part" != "*" && ! "$port_part" =~ ^[0-9]+$ ]]; then
              echo "sbx-agent: port must be '*' or a number. Got: $port_part" >&2
              exit 2
            fi
            check_path_safe "$h"
            net_hosts+=("$h")
          done
          if [[ ''${#net_hosts[@]} -eq 0 ]]; then
            echo "sbx-agent: --net had no valid entries" >&2
            exit 2
          fi
          net_mode_orig="$net_mode"
          net_mode="hosts"
          ;;
      esac

      # ---------------------------------------------------------------
      # Proxy mode: --net-allow-host starts sbx-proxy and wires it in.
      # Mutually exclusive with --net (the proxy supplies the network
      # policy). We error loudly if the user specifies both.
      # ---------------------------------------------------------------
      proxy_pid=""
      proxy_port=""
      if [[ ''${#net_allow_hosts[@]} -gt 0 ]]; then
        if [[ $net_mode_user_set -eq 1 ]]; then
          echo "sbx-agent: --net and --net-allow-host are mutually exclusive" >&2
          echo "sbx-agent: --net-allow-host implies a host-list policy via sbx-proxy; omit --net" >&2
          exit 2
        fi

        if [[ $dump_policy -eq 1 ]]; then
          # Dump mode: don't start sbx-proxy. Use a literal
          # "<PROXY_PORT>" placeholder so the dumped policy shows
          # its structure without any side effect. The placeholder
          # intentionally contains a '<' so that copy-pasting the
          # dumped policy into sandbox-exec -p produces a clear
          # parse error rather than silently using port 0 or a
          # stale value.
          net_mode="hosts"
          net_hosts=("localhost:<PROXY_PORT>")
        else
          if ! command -v sbx-proxy >/dev/null 2>&1; then
            echo "sbx-agent: sbx-proxy not found on PATH; install the sbx-proxy package" >&2
            exit 1
          fi

          proxy_port_file=$(mktemp -t sbx-proxy-port.XXXXXX)
          proxy_log_file="''${FLOX_ENV_CACHE:-''${TMPDIR:-/tmp}}/sbx-proxy.log"

          proxy_flags=(--listen "127.0.0.1:0" --port-file "$proxy_port_file" --log "$proxy_log_file" --log-max-size "$log_max_size" --ppid "$$")
          for h in "''${net_allow_hosts[@]}"; do
            proxy_flags+=(--allow-host "$h")
          done

          sbx-proxy "''${proxy_flags[@]}" >/dev/null 2>&1 &
          proxy_pid=$!

          # Poll for the port file (proxy is ready when it writes it).
          deadline=$(( SECONDS + 2 ))
          while (( SECONDS < deadline )); do
            [[ -s "$proxy_port_file" ]] && break
            sleep 0.05
          done
          if [[ ! -s "$proxy_port_file" ]]; then
            echo "sbx-agent: sbx-proxy did not start within 2s" >&2
            kill "$proxy_pid" 2>/dev/null || true
            rm -f "$proxy_port_file"
            exit 1
          fi
          proxy_port=$(tr -d '[:space:]' < "$proxy_port_file")
          rm -f "$proxy_port_file"

          # Override network policy: the sandbox only permits TCP to the
          # proxy's port. Any direct network attempt from the agent is
          # denied by the kernel.
          net_mode="hosts"
          net_hosts=("localhost:$proxy_port")
        fi
      fi

      # Build policy.
      if [[ $strict_reads -eq 1 ]]; then
        # Deny-default preamble derived from phylum-dev/birdcage.
        # Reads are scoped; the caller must enumerate everything their
        # tool actually needs beyond the macOS/Flox baseline below.
        policy_lines=(
          '(version 1)'
          '(import "system.sb")'
          '(deny default)'
          '(allow mach*)'
          # Override (allow mach*) for the pasteboard Mach services so
          # pbcopy/pbpaste cannot read or set the clipboard from inside
          # the sandbox. macOS registers these via /usr/libexec/pboard
          # under com.apple.pasteboard.* and the newer
          # com.apple.coreservices.uauseractivitypasteboard* xpc name.
          '(deny mach-lookup (global-name-prefix "com.apple.pasteboard"))'
          '(deny mach-lookup (global-name-prefix "com.apple.coreservices.uauseractivitypasteboard"))'
          '(allow ipc*)'
          '(allow signal (target others))'
          '(allow process-fork)'
          '(allow process-exec*)'
          '(allow sysctl*)'
          '(allow system*)'
          '(allow file-read-metadata)'
          '(system-network)'
          # macOS baseline reads — dylib loading, framework init,
          # dyld shared cache. Removing any of these typically causes
          # the child process to SIGABRT at startup.
          '(allow file-read* (subpath "/usr/lib"))'
          '(allow file-read* (subpath "/usr/local/lib"))'
          '(allow file-read* (subpath "/System"))'
          '(allow file-read* (subpath "/Library"))'
          '(allow file-read* (subpath "/private/etc"))'
          '(allow file-read* (subpath "/private/var/db/dyld"))'
          # Flox baseline reads — /nix/store for Flox-provided
          # binaries, $FLOX_ENV for the activation's run dir.
          '(allow file-read* (subpath "/nix/store"))'
          # /dev carve-out so /dev/null, /dev/tty, /dev/urandom work.
          '(allow file-read* (subpath "/dev"))'
          '(allow file-write* (subpath "/dev"))'
          # PWD: read + write.
          "(allow file-read* (subpath \"''${pwd_canon}\"))"
          "(allow file-write* (subpath \"''${pwd_canon}\"))"
        )
        if [[ -n "$flox_env_canon" ]]; then
          policy_lines+=("(allow file-read* (subpath \"''${flox_env_canon}\"))")
        fi
        if [[ -n "$tmp_canon" ]]; then
          policy_lines+=(
            "(allow file-read* (subpath \"''${tmp_canon}\"))"
            "(allow file-write* (subpath \"''${tmp_canon}\"))"
          )
        fi
        # --write paths: read + write (write implies read in strict).
        for c in "''${canon_extras[@]}"; do
          policy_lines+=(
            "(allow file-read* (subpath \"''${c}\"))"
            "(allow file-write* (subpath \"''${c}\"))"
          )
        done
        # --read paths: read-only.
        for c in "''${canon_reads[@]}"; do
          policy_lines+=("(allow file-read* (subpath \"''${c}\"))")
        done
      else
        # Permissive base: allow-default with writes stripped back.
        # Also deny the pasteboard Mach services so pbcopy/pbpaste
        # cannot read or set the clipboard from inside the sandbox.
        policy_lines=(
          '(version 1)'
          '(allow default)'
          '(deny mach-lookup (global-name-prefix "com.apple.pasteboard"))'
          '(deny mach-lookup (global-name-prefix "com.apple.coreservices.uauseractivitypasteboard"))'
          '(deny file-write*)'
          '(allow file-write* (subpath "/dev"))'
          "(allow file-write* (subpath \"''${pwd_canon}\"))"
        )
        if [[ -n "$tmp_canon" ]]; then
          policy_lines+=("(allow file-write* (subpath \"''${tmp_canon}\"))")
        fi
        for c in "''${canon_extras[@]}"; do
          policy_lines+=("(allow file-write* (subpath \"''${c}\"))")
        done
      fi

      # Network rules. In strict mode the deny-default base blocks
      # remote network and (system-network) only enables narrow local
      # operations (unix-socket etc., never remote TCP). We layer
      # explicit overrides for --net allow and --net hosts. In
      # permissive mode, (allow default) already covers network — we
      # only need rules when the user asks to tighten.
      case "$net_mode" in
        block)
          policy_lines+=(
            '(deny network*)'
            '(allow network* (local unix-socket))'
          )
          ;;
        allow)
          if [[ $strict_reads -eq 1 ]]; then
            policy_lines+=('(allow network*)')
          fi
          ;;
        hosts)
          policy_lines+=(
            '(deny network*)'
            '(allow network* (local unix-socket))'
          )
          for h in "''${net_hosts[@]}"; do
            policy_lines+=("(allow network* (remote ip \"''${h}\"))")
          done
          ;;
      esac

      policy=$(printf '%s\n' "''${policy_lines[@]}")

      # ---------------------------------------------------------------
      # --dump-policy: print the built SBPL policy and exit. Pure
      # dry-run — no env_args, no audit log, no ulimits, no proxy
      # started (a placeholder was used above), no exec. The dump
      # goes to stdout so it is pipe/grep/redirect-friendly.
      # ---------------------------------------------------------------
      if [[ $dump_policy -eq 1 ]]; then
        printf '%s\n' "$policy"
        exit 0
      fi

      # ---------------------------------------------------------------
      # Build the env -i whitelist (skipped entirely if --passenv-all).
      # Proxy mode always injects HTTPS_PROXY regardless of scrub mode.
      # ---------------------------------------------------------------
      env_args=()
      if [[ $passenv_all -eq 0 ]]; then
        local_safe=(
          PATH HOME USER LOGNAME SHELL TERM TMPDIR PWD OLDPWD
          LANG TZ COLUMNS LINES TERMCAP
          FLOX_ENV FLOX_ENV_PROJECT FLOX_ENV_CACHE
          SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE
        )
        for v in "''${local_safe[@]}"; do
          if [[ -n "''${!v:-}" ]]; then
            env_args+=("$v=''${!v}")
          fi
        done
        # All LC_* variables (locale category overrides).
        while IFS= read -r lcv; do
          [[ -n "''${!lcv:-}" ]] && env_args+=("$lcv=''${!lcv}")
        done < <(compgen -v LC_ 2>/dev/null || true)
        # --passenv additions.
        for v in "''${passenv[@]}"; do
          if [[ -n "''${!v:-}" ]]; then
            env_args+=("$v=''${!v}")
          else
            echo "sbx-agent: note: --passenv $v not set in environment, skipping" >&2
          fi
        done
      fi

      # If the proxy is active, inject HTTPS_PROXY into whichever env
      # path we're using. In scrub mode we append to env_args directly;
      # in passenv-all mode we export into the current shell so the
      # exec'd child inherits it.
      if [[ -n "$proxy_port" ]]; then
        proxy_url="http://127.0.0.1:$proxy_port"
        if [[ $passenv_all -eq 0 ]]; then
          env_args+=("HTTPS_PROXY=$proxy_url" "https_proxy=$proxy_url")
        else
          export HTTPS_PROXY="$proxy_url"
          export https_proxy="$proxy_url"
        fi
      fi

      # ---------------------------------------------------------------
      # Audit log — one kv record per invocation. On by default if
      # FLOX_ENV_CACHE is set. Disable with --no-audit-log.
      # ---------------------------------------------------------------
      write_audit_record() {
        if [[ $no_audit_log -eq 1 ]]; then return 0; fi
        local log_file
        if [[ -n "$audit_log_path" ]]; then
          log_file="$audit_log_path"
        elif [[ -n "''${FLOX_ENV_CACHE:-}" ]]; then
          log_file="$FLOX_ENV_CACHE/sbx-agent.log"
        else
          return 0  # no path available, silently skip
        fi
        local log_dir
        log_dir=$(dirname "$log_file")
        [[ -d "$log_dir" ]] || mkdir -p "$log_dir" 2>/dev/null || return 0

        # Crude log rotation: if the existing log exceeds $log_max_size,
        # rename it to .log.1 before appending. Best-effort — concurrent
        # writers can race on the rename, with at most a few lines lost
        # on the losing side. sbx-agent's runtimeInputs is GNU coreutils,
        # so `stat -c%s` is the correct size flag; the fallback to 0
        # handles the "no file yet" case without a separate check.
        # log_max_size=0 disables rotation entirely.
        if [[ "$log_max_size" -gt 0 ]]; then
          local log_size
          log_size=$(stat -c%s "$log_file" 2>/dev/null || echo 0)
          if [[ "$log_size" -gt "$log_max_size" ]]; then
            mv -f "$log_file" "$log_file.1" 2>/dev/null || true
          fi
        fi

        local ts
        ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

        # Join arrays with commas inside brackets. Use a subshell to
        # scope IFS locally without leaking it.
        local writes_str reads_str passenv_str proxy_hosts_str
        writes_str=$( IFS=','; printf '[%s]' "''${canon_extras[*]:-}" )
        reads_str=$(  IFS=','; printf '[%s]' "''${canon_reads[*]:-}" )
        passenv_str=$(IFS=','; printf '[%s]' "''${passenv[*]:-}" )
        proxy_hosts_str=$(IFS=','; printf '[%s]' "''${net_allow_hosts[*]:-}")

        local proxy_state="no"
        [[ -n "$proxy_port" ]] && proxy_state="yes"

        # Argv as a plain space-joined string (readable, not re-escaped).
        # A value containing embedded spaces or quotes makes the line
        # ambiguous — rare enough in practice, and the log is for humans.
        local argv_str="$*"

        # Single printf → atomic append for writes <PIPE_BUF (4KB).
        # net_orig is empty unless --net was given a host list that
        # got rewritten to "hosts"; empty is a valid structured value.
        printf 'ts=%s pid=%d cwd="%s" strict=%d net=%s net_orig="%s" proxy=%s proxy_hosts=%s timeout=%s writes=%s reads=%s passenv=%s argv="%s"\n' \
          "$ts" "$$" "$PWD" "$strict_reads" "$net_mode" "$net_mode_orig" \
          "$proxy_state" "$proxy_hosts_str" \
          "''${wall_timeout:-none}" \
          "$writes_str" "$reads_str" "$passenv_str" \
          "$argv_str" \
          >> "$log_file" 2>/dev/null || true
      }
      write_audit_record "$@"

      # ---------------------------------------------------------------
      # Resource limits — applied to this shell, inherited via exec.
      # ---------------------------------------------------------------
      [[ -n "$max_procs" ]] && ulimit -u "$max_procs"
      [[ -n "$max_files" ]] && ulimit -n "$max_files"
      [[ -n "$max_cpu" ]] && ulimit -t "$max_cpu"

      # ---------------------------------------------------------------
      # Final exec: optional timeout wrapper, optional env -i scrub,
      # sandbox-exec, and the user command.
      # ---------------------------------------------------------------
      if [[ $passenv_all -eq 1 ]]; then
        if [[ -n "$wall_timeout" ]]; then
          exec timeout -k 5 "$wall_timeout" /usr/bin/sandbox-exec -p "$policy" -- "$@"
        else
          exec /usr/bin/sandbox-exec -p "$policy" -- "$@"
        fi
      else
        if [[ -n "$wall_timeout" ]]; then
          exec timeout -k 5 "$wall_timeout" env -i "''${env_args[@]}" /usr/bin/sandbox-exec -p "$policy" -- "$@"
        else
          exec env -i "''${env_args[@]}" /usr/bin/sandbox-exec -p "$policy" -- "$@"
        fi
      fi
    '';
  };
in
symlinkJoin {
  name = "sbx-helpers";
  paths = [ sbxRun sbxCwd sbxAgent ];
  meta = with lib; {
    description = "Policy-generating helpers that call macOS sandbox-exec directly";
    platforms = platforms.darwin;
  };
}
