# Change Log

## 1.4.0
- Add `--target` and `--replacement`, which together control what is sanitized and what is written over it.
  `--target` takes a comma-separated selector list applied left to right — `all`, `none`, `<type>`,
  `<type>-fields`, `<type>-arrays`, `fields`, `arrays`, with `-` to subtract and an optional trailing `s`
  throughout. `--replacement` takes comma-separated `<type>=<value>` entries. Object references are never
  sanitized.
- **Breaking change**: the default sanitization scope is now every primitive field and array (`--target=all`).
  Previously only byte and char arrays were sanitized. Pass `--target=byte-arrays,char-arrays
  --replacement=all=0` for the old scope and fill. That reproduces the previous default output byte for byte, apart
  from the `String.coder` byte of strings preserved by `-e`, which `-f` no longer rewrites.
- Replacement values are now typed per primitive rather than tiled text, so an `int[]` sanitized with `0` reads back as
  zeros instead of a repeating byte pattern.
- A replacement value is a number for every type. `--replacement=char=<value>` additionally accepts a character
  literal: a single non-digit character (`*`, `a`), or a backslash escape denoting one character. `\` followed only by
  digits is a decimal code point, so `\0` is NUL and `\97` is `a`; the other Java escapes (`\t`, `\n`, `\\`, `\uXXXX`)
  work as written. The quoted form is not part of the grammar: a value that reaches the tool as the three characters
  `'*'` is a usage error, not a synonym for `*`. The numeric per-type entries (`byte`, `int`, `float`, …) take a number
  only, so `--replacement=int=*` is a usage error; write the code point (`42`). `--replacement=all=<value>`
  still accepts a character literal and applies it as its code point across every type.
- `-f, --force-string-coder-match` keeps its name and default but is now narrower: it rewrites a `String`'s `coder`
  field only when that string's backing `byte[]` is actually being sanitized. It is therefore a no-op when `byte[]` is
  out of scope, and it is skipped for the individual strings `-e, --exclude-string-fields` preserves, whose original
  coder would otherwise be overwritten and render as garbage.
- **Breaking change**: option abbreviations are no longer accepted. `--targ` previously resolved to `--target`;
  it is now an unknown option, and the error lists the options it could have meant. Spell options out in full.
- Options are now listed in a logical order rather than alphabetically: what to sanitize (`--target`,
  `--replacement`) first, then what to spare, then input/output, with the deprecated flags last.
- Fix command-line usage errors being reported as a Java stack trace and exit code 1. An unknown option or a malformed
  option value now prints the explanation plus usage help and exits 2.
- Deprecate `-s, --sanitize-byte-char-arrays-only`, `-t, --text` and `-T, --text-charset`. Each prints a warning and is
  still applied at its position on the command line; `-t` now unescapes Java escape sequences and then accepts a single
  ASCII character only (so `-t '\0'` and `-t '\t'` work, `-t abc` does not), and `-T` is ignored.
- Reduce allocation on the streaming path by roughly 90% (96 GB to 8.6 GB on a 1.19 GB dump) and wall clock by about
  35%, with byte-for-byte identical output.

## 1.1.1
- Upgrade to latest logback through spring-boot bom upgrade.
- Also upgrade various other dependencies.

## 1.1.0
- Add ability to sanitize hs_err Java fatal error logs

## 1.0.0
- Public release of tool for capturing sanitized Java heap dumps
