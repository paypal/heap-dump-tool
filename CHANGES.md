# Change Log

## 1.4.0
- Add `--target` and `--replacement`, which together control what data is sanitized and what is written over it.
  `--target` takes a comma-separated selector list applied left to right — `all`, `none`, `<type>`,
  `<type>-fields`, `<type>-arrays`, `fields`, `arrays`, with `-` to subtract and an optional trailing `s`
  throughout. `--replacement` takes comma-separated `<type>=<value>` entries. Object references are never
  sanitized.
- Deprecate `-s, --sanitize-byte-char-arrays-only`, `-t, --text` and `-T, --text-charset`.
- **Breaking change**: the default sanitization target is now every primitive field and array (`--target=all`).
  Previously only byte and char arrays were sanitized by default. Pass `--target=byte-arrays,char-arrays
  --replacement=all=0` for the old target and fill. That reproduces the previous default output byte for byte, apart
  from the `String.coder` byte of strings preserved by `-e`, which `-f` no longer rewrites.
- A replacement value is a number for every type. `--replacement=char=<value>` additionally accepts a character
  literal: a single non-digit character (`*`, `a`), or a backslash escape denoting one character. `\` followed only by
  digits is a decimal code point, so `\0` is NUL and `\97` is `a`; the other Java escapes (`\t`, `\n`, `\\`, `\uXXXX`)
  work as written. The quoted form is not part of the grammar: a value that reaches the tool as the three characters
  `'*'` is a usage error, not a synonym for `*`. The numeric per-type entries (`byte`, `int`, `float`, …) take a number
  only, so `--replacement=int=*` is a usage error; write the code point (`42`). `--replacement=all=<value>`
  still accepts a character literal and applies it as its code point across every type.
- `-f, --force-string-coder-match` has been improved: it rewrites a `String`'s `coder` field only when that string's
  backing `byte[]` is actually being sanitized.
- **Breaking change**: option abbreviations like `--zi` for `--zip-output` are no longer accepted. Spell out in full.
- Options are now listed in a more logical order rather than alphabetically.
- Command-line usage errors now prints the explanation plus usage help and exits 2; stack trace no more.
- Reduce allocation by roughly 90% (about 96 GB down to under 10 GB on a 1.2 GB dump) and wall clock by about 35%.
- Speed up the pre-processing pass that runs. On a 1.2 GB dump the pass drops from 20-22s to 12-14s (~40% faster) and
  the whole run from 43-46s to 35-37s (roughly 20%).
- Progress is now reported roughly every 5 seconds like `Processed 484.32 MB / 1.11 GB (ETA 12s)`
- Support .zip, .tar, .tar.gz, .tgz, or .gz files as input or output files transparently. `-a, --tar-input` and 
  `-z, --zip-output` options are now deprecated.

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
