# Security Policy

## Reporting a Vulnerability

If you discover a security issue in ARC, please report it privately via
GitHub Security Advisories:

https://github.com/a-kaushik2209/ARC/security/advisories/new

Do not file public issues for sensitive findings. For non-sensitive
hardening (linter rules, dependency upgrades, lint of CI workflows, etc.)
feel free to open a normal PR.

We aim to acknowledge reports within seven days.

## Trust Boundary: Checkpoint Files

ARC's checkpoint loading uses `torch.load()`, which deserializes data with
Python's `pickle` protocol. Pickle executes arbitrary code during
deserialization through the `__reduce__` mechanism — a checkpoint file
is effectively executable Python.

**Treat any checkpoint file you did not produce yourself as untrusted
code.** This includes, at minimum:

- Checkpoints downloaded from the internet (including model zoos and
  Hugging Face Hub repos you do not control)
- Checkpoints shared by other users on a multi-tenant system
- Checkpoints sitting in a directory writable by other accounts on the
  same machine (shared GPU servers, CI runners, training clusters)

### What ARC does

As of this release, ARC loads checkpoints with `weights_only=True` first.
This restricts unpickling to a safe subset of types and rejects payloads
that try to execute arbitrary callables via `__reduce__`. If that load
fails — typically because the checkpoint contains optimizer state,
schedulers, or other non-tensor Python objects — ARC falls back to
`weights_only=False` after emitting a `UserWarning` of the form:

``` Loading <path> with weights_only=False. Only do this for checkpoints
you produced yourself. See SECURITY.md for the checkpoint trust boundary.```

The fallback is provided for backward compatibility with existing
checkpoints. **It reintroduces the pickle code-execution risk for the
duration of that specific load.** If you see this warning for a
checkpoint you did not produce, treat it as a refusal-to-load signal,
not a routine notice.

### What ARC does NOT do

ARC does not verify the integrity of checkpoint files. There is no
signature or hash check. If you transfer checkpoints between machines or
download them, verify integrity through your own out-of-band channel.

## Hardening Recommendations

1. **Use per-user checkpoint directories.** ARC's defaults are now under
   `~/.cache/arc/` rather than `/tmp/`. The previous `/tmp/` defaults
   were world-writable on Linux and let any local user plant a malicious
   pickle that ARC's autonomous rollback would later load. If you
   override the default, point it at a directory that other users on
   the system cannot write to.

2. **Audit checkpoint sources.** For checkpoints from external sources
   (other researchers, model hubs, internet downloads), inspect the
   producer and transport before loading. A signed hash from a trusted
   channel is the simplest verification.

3. **Pay attention to fallback warnings.** A `weights_only=False`
   warning means the file contains pickle-deserializable objects
   beyond pure tensors. For checkpoints from untrusted sources,
   refuse to load.

4. **Run on a separate user account for untrusted training data.** If
   you must work with checkpoints from outside your team, sandbox the
   training process in a dedicated low-privilege account so a successful
   exploit has minimal blast radius.