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

## 1.3.4
- When `--sanitize-byte-char-arrays-only=false` is set, retain refs to objects.
- Remove obsolete `--sanitize-arrays-only` flag.

## 1.3.3
- Support running sanitize commands in docker.

## 1.3.2
- New docker base image with fewer vulnerabilities.
- Add support for multi-platform images.
- Bump commons-lang3 from 3.17.0 to 3.18.0.

## 1.3.1
- Make it easier to skip docker pull.

## 1.3.0
- Fix wrong charset of sanitized strings in Java 8 heap dumps.
- **Breaking change**: boolean cli options must be set with a `true|false` argument.

## 1.2.0
- Add ability to exclude certain string fields from sanitization.
- Force `coder` field value in string instances to match sanitizationText's coder value.
- Improve docker memory usage configuration.

## 1.1.8
- Remove logback.

## 1.1.7
- Add ability to customize jcmd cmd and options to create heap dump and thread dump.

## 1.1.6
- Upgrade logback from 1.2.13 to 1.3.14.

## 1.1.5
- Bump commons-compress from 1.21 to 1.26.0.
- Upgrade commons-io, commons-lang3, commons-text, junit-pioneer, picocli to latest versions.

## 1.1.4
- Document more cli options.
- Fix logback and guava vulnerabilities.
- Bump guava from 30.1.1-jre to 32.0.0-jre.

## 1.1.3
- Allow sanitizing arrays of all types while preserving primitive values.

## 1.1.2
- Upgrade commons-text from 1.9 to 1.10.0.
- Bump xercesImpl from 2.12.1 to 2.12.2.
- Update LICENSE.

## 1.1.1
- Upgrade to latest logback through spring-boot bom upgrade.
- Also upgrade various other dependencies.

## 1.1.0
- Add ability to sanitize hs_err Java fatal error logs

## 1.0.0
- Public release of tool for capturing sanitized Java heap dumps
