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
      <inputFile>            Input heap dump .hprof. File or stdin
      <outputFile>           Output heap dump .hprof file
      --target=<selectors>   What to sanitize: a comma-separated list applied left to right. Default: all
                             Selectors: all, none, <type>, <type>-fields, <type>-arrays, fields, arrays. <type> alone
                               means type's primitive fields and array fields; 'fields' or 'arrays' means type's
                               primitive fields or array fields only
                             Prefix an entry with '-' to deselect it, e.g. --target=all,-ints
                             <type> is byte, short, int, long, char, float, double or boolean
      --replacement=<type>=<value>
                             Replacement values for sanitization: comma-separated <type>=<value> entries applied left
                               to right.
                             Defaults: all=0,byte=42,char=*,boolean=false
  -e, --exclude-string-fields=<excludeStringFields>
                             String fields to exclude from sanitization. Value in com.example.MyClass#fieldName format
                               Default: java.lang.Thread#name,java.lang.ThreadGroup#name
  -f, --force-string-coder-match=<true|false>
                             Force JEP-254 String.coder field to match their sanitized byte[], so MAT or similar tools
                               render them correctly
                               Default: true
  -a, --tar-input=<true|false>
                             Treat input as tar archive
  -z, --zip-output           Write zipped output
                               Default: false
  -b, --buffer-size=<bufferSize>
                             Buffer size for reading and writing
                               Default: 100MB
  -d, --docker-registry=<dockerRegistry>
                             docker registry hostname for bootstrapping heap-dump-tool docker image
  -s, --sanitize-byte-char-arrays-only=<true|false>
                             Deprecated. Use --target=byte-arrays,char-arrays instead
  -t, --text=<text>          Deprecated. Use --replacement=all=<value> instead. Supports a single ASCII character only
  -T, --text-charset=<charset>
                             Deprecated and ignored. Replacement values are now typed per primitive
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

* `--target=<selectors>`
  * What to sanitize: a comma-separated list applied left to right. Defaults to `all`.
    Prefix an entry with `-` to subtract it.

    | Selector | Also accepted | Means |
    | --- | --- | --- |
    | `all` | — | every primitive field and array |
    | `none` | — | nothing |
    | `byte` | `bytes` | `byte` fields **and** `byte[]` contents |
    | `byte-field` | `byte-fields`, `bytes-field`, `bytes-fields` | `byte` fields only |
    | `byte-array` | `byte-arrays`, `bytes-array`, `bytes-arrays` | `byte[]` contents only |
    | `field` | `fields` | every primitive-typed field, no array contents |
    | `array` | `arrays` | the contents of every primitive array, no fields |

    `<type>` is one of `byte`, `short`, `int`, `long`, `char`, `float`, `double`, `boolean`; a trailing `s` on a type
    name is ignored.

  ```
  --target=all                          # the default
  --target=none                         # copy the dump through, sanitizing nothing
  --target=all,-ints,-longs             # everything except int and long
  --target=byte-arrays,char-arrays      # the target prior to version 1.4.0
  --target=arrays                       # primitive array contents only, skip primitive fields
  --target=all,-char,char-array         # all, but only char's array contents
  ```
  * A deselection cannot start the list. `--target=-int` is a usage error. Write `--target=all,-int`.
  * `--target` cannot be passed multiple times.

* `--replacement=<type>=<value>,...`
  * Replacement values for sanitization, as comma-separated `<type>=<value>` entries applied left to right.
    `<type>` is `all` or a primitive type name; a trailing `s` on a type name is ignored.

    | Value | Meaning | Example                                             |
    | --- | --- |-----------------------------------------------------|
    | a decimal number | that numeric value | `int=42` is 42                                      |
    | a single non-digit character | that character's code point; `char` and `all` only | `char=*`, `char=a`                                  |
    | a backslash escape | the character it denotes; `char` and `all` only | `char=\0` is 0, `char=\98` is `b`, `char=\t` is tab |
    | `true` / `false` | boolean only | `boolean=true`                                      |

  * Character literals like `*` are accepted by `char` and by `all`.
  * Fractional values like `0.5` are only accepted by `float` and `double`.
  * Defaults: `byte=42` (the `*` character), `char=*`, `boolean=false`, everything else `0`.
  * `all=<value>` sets every type from one value, converted per type. e.g. `--replacement=all=*` means `byte=42`,
    `short=42`, `int=42`, `long=42`, `char=*`, `float=42.0`, `double=42.0`, `boolean=true`.
  * Like `--target`, `--replacement` cannot be passed multiple times.

  ```
  --replacement=all=0                   # sanitize with null byte
  --replacement=all=0,char=*            # every type 0, then char back to *
  --replacement=int=42,byte=0
  ```

* `-z, --zip-output` 
  * When set, output heap dump is compressed in zip format.

### CLI FAQ

**Q: How can I sanitize only char array or byte array fields?**
Set `--target=byte-arrays,char-arrays`. The behavior mimics that of versions prior to 1.4.0. Add
`--replacement=all=0` to reproduce the old `\0` fill as well.

**Q: Why are collection sizes, hash codes and timestamps gone from my dump?**
Because `--target` defaults to `all`, every primitive field is overwritten. Subtract the types you want to keep, e.g.
`--target=all,-int-fields,-long-fields`.

**Q: How do I tell what a run actually sanitized?**
Every `sanitize` run logs the resolved scope and replacement values on startup, before it reads the dump:

```
INFO SanitizeCommandProcessor - Sanitization targets: --target=char-arrays,byte-arrays
INFO SanitizeCommandProcessor - Replacement values: --replacement=boolean=false,char=*,float=0.0,[...]
```

Both lines are valid flag values, so pasting them into a later command reproduces the same run. This is the reliable
way to read a policy assembled from the deprecated flags, whose effect depends on where they sit on the command line.


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

