# Change Log

## 1.4.0
- Add per-type sanitization flags: `--sanitize-all`, `--sanitize-<type>s`, `--sanitize-<type>-arrays`, and a
  `--sanitize-<type>-replacement` for each primitive type, plus `--sanitize-all-replacement`. Flags are resolved in
  command-line order, so a later flag overrides an earlier one.
- **Breaking change**: the default sanitization scope is now all primitive fields and arrays (`--sanitize-all=true`).
  Previously only byte and char arrays were sanitized. Pass
  `--sanitize-all=false --sanitize-byte-arrays=true --sanitize-char-arrays=true` for the old scope, plus
  `--sanitize-all-replacement=0` for the old `\0` fill. That reproduces the previous default output byte for byte, apart
  from the `String.coder` byte of strings preserved by `-e`, which `-f` no longer rewrites.
- Replacement values are now typed per primitive rather than tiled text, so an `int[]` sanitized with `0` reads back as
  zeros instead of a repeating byte pattern.
- `-f, --force-string-coder-match` keeps its name and default but is now narrower: it rewrites a `String`'s `coder`
  field only when that string's backing `byte[]` is actually being sanitized. It is therefore a no-op when `byte[]` is
  out of scope, and it is skipped for the individual strings `-e, --exclude-string-fields` preserves, whose original
  coder would otherwise be overwritten and render as garbage.
- Deprecate `-s, --sanitize-byte-char-arrays-only`, `-t, --text` and `-T, --text-charset`. Each prints a warning and is
  still applied at its position on the command line; `-t` now unescapes Java escape sequences and then accepts a single
  ASCII character only (so `-t '\0'` and `-t '\t'` work, `-t abc` does not), and `-T` is ignored.

## 1.1.1
- Upgrade to latest logback through spring-boot bom upgrade.
- Also upgrade various other dependencies.

## 1.1.0
- Add ability to sanitize hs_err Java fatal error logs

## 1.0.0
- Public release of tool for capturing sanitized Java heap dumps
