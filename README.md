# Heap Dump Tool

[![Maven Central](https://maven-badges.sml.io/maven-central/com.paypal/heap-dump-tool/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.paypal/heap-dump-tool)

Heap Dump Tool can capture and, more importantly, sanitize sensitive data from Java heap dumps. Sanitization is accomplished
by replacing primitive field and array values in the heap dump file with a value like `*` for chars and `0` for numbers.
Heap dump can then be more freely shared and analyzed.

A typical scenario is when a heap dump needs to be sanitized before it can be given to another person or moved to a different
environment. For example, an app running in production environment may contain sensitive data (passwords, credit card
numbers, etc) which should not be viewable when the heap dump is copied to a development environment for analysis with a
graphical program.

**Conceptual illustration of sanitization**:

<img src="https://github.com/paypal/heap-dump-tool/raw/statics/heap-dump-file.png"/>

---

<img src="https://github.com/paypal/heap-dump-tool/raw/statics/sanitized-heap-dump-file.png"/>

&nbsp;
&nbsp;

**Concrete illustration of before-and-after sanitization**:

<img src="https://github.com/paypal/heap-dump-tool/raw/statics/before.png"/>

---

<img src="https://github.com/paypal/heap-dump-tool/raw/statics/after.png"/>


## TOC
  * [Examples](#examples)
  * [CLI Usage](#cli-usage)
  * [Library Usage](#library-usage)
  * [License](#license)

## Examples

The tool can be run in several ways depending on tool's packaging and where the target to-be-captured app is running.

#### [Jar] Capture sanitized heap dump manually

Simplest way to capture sanitized heap dump of an app is to run:

```
# capture plain heap dump of Java process with given pid
$ jcmd {pid} GC.heap_dump /path/to/plain-heap-dump.hprof

# then sanitize the heap dump
$ wget -O heap-dump-tool.jar https://repo1.maven.org/maven2/com/paypal/heap-dump-tool/1.4.0/heap-dump-tool-1.4.0-all.jar
$ java -jar heap-dump-tool.jar sanitize /path/to/plain-dump.hprof /path/to/sanitized-dump.hprof
```

<br/>

#### [Jar] Capture sanitized heap dump of a containerized app

Suppose the tool is a packaged jar on the host, and the target app is running as the only Java process within a container.

Then, to capture sanitized heap dump of a containerized app, run:

```
# list docker containers
$ docker ps
CONTAINER ID        IMAGE                                [...]   NAMES
06e633da3494        registry.example.com/my-app:latest   [...]   my-app

# capture and sanitize
$ wget -O heap-dump-tool.jar https://repo1.maven.org/maven2/com/paypal/heap-dump-tool/1.4.0/heap-dump-tool-1.4.0-all.jar
$ java -jar heap-dump-tool.jar capture my-app
```

Note that a plain stack dump is also captured.

<br/>

#### [Docker] Capture sanitized heap dump of a containerized app

Suppose the tool is a Docker image, and the target app is running as the only Java process within a container.

Then, to capture sanitized heap dump of another containerized app, run:

```
# list docker containers
$ docker ps
CONTAINER ID        IMAGE                                [...]   NAMES
06e633da3494        registry.example.com/my-app:latest   [...]   my-app

# capture and sanitize
$ docker run heapdumptool/heapdumptool capture my-app | bash
```

If the container runs multiple Java processes, pid can be specified:
```
# list docker containers
$ docker ps
CONTAINER ID        IMAGE                                [...]   NAMES
06e633da3494        registry.example.com/my-app:latest   [...]   my-app

# find pid
$ jps
$ ps aux

# capture and sanitize
$ docker run heapdumptool/heapdumptool capture my-app -p {pid} | bash
```

<br/>

#### Sanitize hs_err* Java fatal error logs

To sanitize environment variables in hs_err* files, you can run:

```
# with java -jar
$ wget -O heap-dump-tool.jar https://repo1.maven.org/maven2/com/paypal/heap-dump-tool/1.4.0/heap-dump-tool-1.4.0-all.jar
$ java -jar heap-dump-tool.jar sanitize-hserr input-hs_err.log outout-hs_err.log

# Or, with docker
$ docker run heapdumptool/heapdumptool sanitize-hserr input-hs_err.log outout-hs_err.log | bash
```

<a name="cli-usage"></a>

## CLI Usage

```
$ java -jar heap-dump-tool.jar help
Usage: heap-dump-tool [-hV] [COMMAND]
Tool primarily for capturing or sanitizing heap dumps
  -h, --help      Show this help message and exit.
  -V, --version   Print version information and exit.
Commands:
  capture         Capture sanitized heap dump of a containerized app
  sanitize        Sanitize a heap dump by replacing primitive field and array contents
  sanitize-hserr  Sanitize fatal error log by censoring environment variable values
  help            Display help information about the specified command.
```

Additional usage for sub-commands can be found by running `help {sub-command}`. For example:

```
$ java -jar heap-dump-tool.jar help sanitize
Usage: heap-dump-tool sanitize [OPTIONS] <inputFile> <outputFile>
Sanitize a heap dump by replacing primitive field and array contents
      <inputFile>     Input heap dump .hprof. File or stdin
      <outputFile>    Output heap dump .hprof file
  -a, --tar-input=<true|false>
                      Treat input as tar archive
  -b, --buffer-size=<bufferSize>
                      Buffer size for reading and writing
                        Default: 100MB
  -d, --docker-registry=<dockerRegistry>
                      docker registry hostname for bootstrapping heap-dump-tool docker image
  -e, --exclude-string-fields=<excludeStringFields>
                      String fields to exclude from sanitization. Value in com.example.MyClass#fieldName format
                        Default: java.lang.Thread#name,java.lang.ThreadGroup#name
  -f, --force-string-coder-match=<true|false>
                      Force JEP-254 String.coder field to match their sanitized byte[], so MAT or similar tools render
                        them correctly
                        Default: true
  -s, --sanitize-byte-char-arrays-only=<true|false>
                      Deprecated. Use --sanitize-all, --sanitize-byte-arrays, and --sanitize-char-arrays instead
      --sanitize-all[=<true|false>]
                      Sanitize all primitive fields and arrays. Object references are never sanitized. Default: true
      --sanitize-all-replacement=<value>
                      Value to replace all primitive data with, converted per type. A number, or a single character
                        such as * or \0
      --sanitize-boolean-arrays[=<true|false>]
                      Sanitize boolean[] contents. Default: true, via --sanitize-all
      --sanitize-boolean-replacement=<value>
                      Value to replace boolean data with. Default: false
      --sanitize-booleans[=<true|false>]
                      Sanitize boolean fields. Default: true, via --sanitize-all
      --sanitize-byte-arrays[=<true|false>]
                      Sanitize byte[] contents. Default: true, via --sanitize-all
      --sanitize-byte-replacement=<value>
                      Value to replace byte data with. Default: 42
      --sanitize-bytes[=<true|false>]
                      Sanitize byte fields. Default: true, via --sanitize-all
      --sanitize-char-arrays[=<true|false>]
                      Sanitize char[] contents. Default: true, via --sanitize-all
      --sanitize-char-replacement=<value>
                      Value to replace char data with. Default: *
      --sanitize-chars[=<true|false>]
                      Sanitize char fields. Default: true, via --sanitize-all
      --sanitize-double-arrays[=<true|false>]
                      Sanitize double[] contents. Default: true, via --sanitize-all
      --sanitize-double-replacement=<value>
                      Value to replace double data with. Default: 0.0
      --sanitize-doubles[=<true|false>]
                      Sanitize double fields. Default: true, via --sanitize-all
      --sanitize-float-arrays[=<true|false>]
                      Sanitize float[] contents. Default: true, via --sanitize-all
      --sanitize-float-replacement=<value>
                      Value to replace float data with. Default: 0.0
      --sanitize-floats[=<true|false>]
                      Sanitize float fields. Default: true, via --sanitize-all
      --sanitize-int-arrays[=<true|false>]
                      Sanitize int[] contents. Default: true, via --sanitize-all
      --sanitize-int-replacement=<value>
                      Value to replace int data with. Default: 0
      --sanitize-ints[=<true|false>]
                      Sanitize int fields. Default: true, via --sanitize-all
      --sanitize-long-arrays[=<true|false>]
                      Sanitize long[] contents. Default: true, via --sanitize-all
      --sanitize-long-replacement=<value>
                      Value to replace long data with. Default: 0
      --sanitize-longs[=<true|false>]
                      Sanitize long fields. Default: true, via --sanitize-all
      --sanitize-short-arrays[=<true|false>]
                      Sanitize short[] contents. Default: true, via --sanitize-all
      --sanitize-short-replacement=<value>
                      Value to replace short data with. Default: 0
      --sanitize-shorts[=<true|false>]
                      Sanitize short fields. Default: true, via --sanitize-all
  -t, --text=<text>   Deprecated. Use --sanitize-all-replacement instead. Supports a single ASCII character only
  -T, --text-charset=<charset>
                      Deprecated and ignored. Replacement values are now typed per primitive
  -z, --zip-output    Write zipped output
                        Default: false
```

### Explanation of options

* `-a, --tar-input=<true|false>`
  * Meant for use with `-` or `stdin` as inputFile when piping heap dump from k8s `kubectl cp` command which produces tar
    archive.

* `-b, --buffer-size=<bufferSize>`
  * Higher buffer size should improve performance when reading and writing large heap dump files at the cost of higher
    memory usage.

* `-d, --docker-registry=<dockerRegistry>`
  * Meant for use with private docker-registry setups.

* `-e, --exclude-string-fields=<excludeStringFields>`
  * CSV list of string fields to exclude from sanitization.

* `-f, --force-string-coder-match=<true|false>`
  * Because of [JEP-254](https://openjdk.org/jeps/254), since Java 9, string instances may be encoded differently based on content. 
    This setting forces encoding of sanitized strings in heap dump to match the encoding of the replacement text. 
    If unset, some sanitized string fields may not be displayed correctly in [MAT](https://eclipse.dev/mat/) or similar
    GUI tools.

* `--sanitize-all[=<true|false>]`
  * Sanitize every primitive field and array. Defaults to true. Object references are never sanitized, since
    overwriting them corrupts the object graph.

* `--sanitize-bytes`, `--sanitize-shorts`, `--sanitize-ints`, `--sanitize-longs`, `--sanitize-chars`,
  `--sanitize-floats`, `--sanitize-doubles`, `--sanitize-booleans`
  * Sanitize non-array fields of that primitive type.

* `--sanitize-byte-arrays`, `--sanitize-short-arrays`, `--sanitize-int-arrays`, `--sanitize-long-arrays`,
  `--sanitize-char-arrays`, `--sanitize-float-arrays`, `--sanitize-double-arrays`, `--sanitize-boolean-arrays`
  * Sanitize the contents of arrays of that primitive type.

* `--sanitize-<type>-replacement=<value>`, `--sanitize-all-replacement=<value>`
  * The value to write over sanitized data, interpreted as a value of that type. For `--sanitize-<type>-replacement`:

    | Value | Meaning | Example                                 |
    | --- | --- |-----------------------------------------|
    | a decimal number | that numeric value | `42` is 42 |
    | a lone non-digit character | that character's code point; `--sanitize-char-replacement` only | `*` is 42, `a` is 97                    |
    | a backslash escape | the character it denotes; `--sanitize-char-replacement` only | `\0` is 0, `\98` is 98 (`b`), `\t` is 9 |
    | `true` / `false` | boolean; `--sanitize-boolean-replacement` only | `--sanitize-boolean-replacement=true`   |

  * Character literals like `*` or `x` are accepted only by `--sanitize-char-replacement`. The numeric per-type flags - 
    `byte`, `short`, `int`, `long`, `float`, `double`, `boolean` - take a number only.
  * Fractional values like `0.5` are only accepted by `float` and `double`.
  * Defaults: byte=42 (`*` character), char=*, short/int/long/float/double=0, boolean=false.
  * `--sanitize-all-replacement=<value>` sets every type's replacement from one value, converted per type.
    `--sanitize-all-replacement=*` yields `byte=42`, `short=42`, `int=42`, `long=42`, `char=*`, `float=42.0`,
    `double=42.0`, `boolean=true`.

* `-z, --zip-output` 
  * When set, output heap dump is compressed in zip format.

#### Flags are resolved in command-line order

Overlapping sanitization flags resolve by position: the flag that appears **later** on the command line wins, whichever
flag it is. This matters most when combining `--sanitize-all` with per-type flags:

```
# sanitize short fields only
$ java -jar heap-dump-tool.jar sanitize --sanitize-all=false --sanitize-shorts=true in.hprof out.hprof

# sanitize nothing: --sanitize-all=false comes last and clears the earlier --sanitize-shorts
$ java -jar heap-dump-tool.jar sanitize --sanitize-shorts=true --sanitize-all=false in.hprof out.hprof
```

The same rule applies to replacement values: `--sanitize-all-replacement=0 --sanitize-int-replacement=7` gives ints 7
and everything else 0.

#### Deprecated options

Each deprecated flag prints a warning and is then applied at its position on the command line, exactly as though the
equivalent new flags had been typed there.

| Deprecated flag | Applied as |
| --- | --- |
| `-s, --sanitize-byte-char-arrays-only=true` | `--sanitize-all=false --sanitize-byte-arrays=true --sanitize-char-arrays=true` |
| `-s, --sanitize-byte-char-arrays-only=false` | `--sanitize-all=true` |
| `-t, --text=<char>` | `--sanitize-all-replacement=\<code point>`, so the value is always treated as a character: `-t 4` means the character `'4'` (52), not the number 4. The value is first passed through Java escape unescaping, then must be **a single ASCII character**; anything else is a usage error. So `-t '\0'` (byte `0x00`, the old default) and `-t '\t'` (`0x09`) are accepted even though they are two characters as typed, while `-t ab` and `-t abc` are rejected. This is deliberately narrower than the old contract, which took arbitrary text. |
| `-T, --text-charset=<charset>` | Nothing. Replacement values are typed per primitive, so no charset is involved. The value is ignored. |

`-f, --force-string-coder-match` and `-e, --exclude-string-fields` are **not** deprecated; both keep their names and
defaults. `-e`'s behavior is unchanged. `-f`'s is narrower: previously `-f=true` rewrote the `coder` field of *every*
`String` instance in the dump, whereas it now rewrites it only for strings whose backing `byte[]` is actually being
sanitized - so it is a no-op when `byte[]` is out of scope, and it is skipped for the individual strings `-e` preserves.
See [`-f` above](#explanation-of-options) for why.

#### A note on abbreviated options

The CLI accepts unambiguous option abbreviations (`--z-o` for `--zip-output`). Since 27 options now begin with
`--sanitize-`, many previously-working abbreviations are now ambiguous and rejected, for example:

```
$ java -jar heap-dump-tool.jar sanitize --s-a in.hprof out.hprof
Error: '--s-a' is not unique: it matches '--sanitize-byte-arrays', '--sanitize-short-arrays', ...
Usage: heap-dump-tool sanitize [OPTIONS] <inputFile> <outputFile>
...
```

Spell such options out in full.

### CLI FAQ

**Q: How can I sanitize only char array or byte array fields?**
Set `--sanitize-all=false --sanitize-byte-arrays=true --sanitize-char-arrays=true`. The behavior mimics that of versions
prior to 1.4.0.

**Q: Why are collection sizes, hash codes and timestamps gone from my dump?**
Because `--sanitize-all` defaults to true, every primitive field is overwritten. Opt back in per type, e.g.
`--sanitize-all=true --sanitize-ints=false --sanitize-longs=false`, keeping in mind that a later flag wins.


<a name="library-usage"></a>

## Library Usage

To use the tool as a library and embed it within another app, you can declare it as dependency in your project. For maven:

```xml
<dependency>
  <groupId>com.paypal</groupId>
  <artifactId>heap-dump-tool</artifactId>
  <version>1.4.0</version>
</dependency>
```

Then, use `HeapDumpSanitizer` class to sanitize heap dumps programmatically. Example:

```java
public class Demo {
  public static void main(String[] args) throws Exception {
    SanitizeCommand command = new SanitizeCommand();
    command.setInputFile(Path.of("/path/to/input.hprof"));
    command.setOutputFile(Path.of("/path/to/output.hprof"));

    SanitizeStreamFactory streamFactory = new SanitizeStreamFactory(command);

    try (InputStream inputStream = streamFactory.newInputStream();
         OutputStream outputStream = streamFactory.newOutputStream()) {
      HeapDumpSanitizer sanitizer = new HeapDumpSanitizer();
      sanitizer.setSanitizeCommand(command);
      sanitizer.setInputStream(inputStream);
      sanitizer.setOutputStream(outputStream);
      sanitizer.setProgressMonitor(bytes -> {});
      sanitizer.sanitize();
    }
  }
}
```

### Library FAQ

**Q: I see `java.lang.NoClassDefFoundError: org/apache/commons/lang3/Strings`** error

A: Another dependency in your project is likely pulling in an older version of commons-lang3 library. Try explicitly
adding a newer version of commons-lang3 as dependency:
```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-lang3</artifactId>
    <version>3.18.0</version>
</dependency>
```

<a name="license"></a>

## Whitepaper

See [whitepaper (pdf)](https://github.com/paypal/heap-dump-tool/blob/statics/whitepaper.pdf)

## License

Heap Dump Tool is Open Source software released under the Apache 2.0 license.

