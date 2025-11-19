# Heap Dump Tool

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.paypal/heap-dump-tool/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.paypal/heap-dump-tool)

Heap Dump Tool can capture and, more importantly, sanitize sensitive data from Java heap dumps. Sanitization is accomplished
by replacing field values in the heap dump file with zero values. Heap dump can then be more freely shared freely and analyzed.

A typical scenario is when a heap dump needs to be sanitized before it can be given to another person or moved to a different
environment. For example, an app running in production environment may contain sensitive data (passwords, credit card
numbers, etc) which should not be viewable when the heap dump is copied to a development environment for analysis with a
graphical program.

<img src="https://github.com/paypal/heap-dump-tool/raw/statics/heap-dump-file.png"/>

---

<img src="https://github.com/paypal/heap-dump-tool/raw/statics/sanitized-heap-dump-file.png"/>

## TOC
  * [Examples](#examples)
  * [Usage](#usage)
  * [License](#license)
	
## Examples

The tool can be run in several ways depending on tool's packaging and where the target to-be-captured app is running.

#### [Jar] Capture sanitized heap dump manually

Simplest way to capture sanitized heap dump of an app is to run:

```
# capture plain heap dump of Java process with given pid
$ jcmd {pid} GC.heap_dump /path/to/plain-heap-dump.hprof

# then sanitize the heap dump
$ wget -O heap-dump-tool.jar https://repo1.maven.org/maven2/com/paypal/heap-dump-tool/1.3.3/heap-dump-tool-1.3.3-all.jar
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
$ wget -O heap-dump-tool.jar https://repo1.maven.org/maven2/com/paypal/heap-dump-tool/1.3.3/heap-dump-tool-1.3.3-all.jar
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
$ wget -O heap-dump-tool.jar https://repo1.maven.org/maven2/com/paypal/heap-dump-tool/1.3.3/heap-dump-tool-1.3.3-all.jar
$ java -jar heap-dump-tool.jar sanitize-hserr input-hs_err.log outout-hs_err.log

# Or, with docker
$ docker run heapdumptool/heapdumptool sanitize-hserr input-hs_err.log outout-hs_err.log | bash
```

### [Library] Embed within an app

To use it as a library and embed it within another app, you can declare it as dependency in maven:

```
<dependency>
  <groupId>com.paypal</groupId>
  <artifactId>heap-dump-tool</artifactId>
  <version>1.3.3</version>
</dependency>
```

<a name="usage"></a>

## Usage

```
java -jar heap-dump-tool.jar  help
Usage: heap-dump-tool [-hV] [COMMAND]
Tool for capturing or sanitizing heap dumps
  -h, --help      Show this help message and exit.
  -V, --version   Print version information and exit.
Commands:
  capture   Capture sanitized heap dump of a containerized app
  sanitize  Sanitize a heap dump by replacing byte and char array contents
  sanitize-hserr  Sanitize fatal error log by censoring environment variable values
  help      Displays help information about the specified command
```

Additional usage for sub-commands can be found by running `help {sub-command}`. For example:

```
$ java -jar heap-dump-tool.jar help capture
Usage: heap-dump-tool sanitize [OPTIONS] <inputFile> <outputFile>
Sanitize a heap dump by replacing byte and char array contents
      <inputFile>    Input heap dump .hprof. File or stdin
      <outputFile>   Output heap dump .hprof. File, stdout, or stderr
  -a, --tar-input    Treat input as tar archive
  -b, --buffer-size=<bufferSize>
                     Buffer size for reading and writing
                       Default: 100MB
  -d, --docker-registry=<dockerRegistry>
                     docker registry hostname for bootstrapping heap-dump-tool docker image
  -e, --exclude-string-fields=<excludeStringFields>
                     String fields to exclude from sanitization. Value in com.example.MyClass#fieldName format
                       Default: java.lang.Thread#name,java.lang.ThreadGroup#name
  -f, --force-string-coder-match=<forceMatchStringCoder>
                     Force strings coder values to match sanitizationText.coder value
                       Default: true
  -s, --sanitize-byte-char-arrays-only
                     Sanitize byte/char arrays only
                       Default: true
  -S, --sanitize-arrays-only
                     Sanitize arrays only
                       Default: false
  -t, --text=<sanitizationText>
                     Sanitization text to replace with
                       Default: \0
  -z, --zip-output   Write zipped output
                       Default: false
```

### Explanation of options

* `-a, --tar-input    Treat input as tar archive`
  * Meant for use with `-` or `stdin` as inputFile when piping heap dump from k8s `kubectl cp` command which produces tar archive.

* `-b, --buffer-size=<bufferSize>`
  * Higher buffer size should improve performance when reading and writing large heap dump files at the cost of higher memory usage.

* `-d, --docker-registry=<dockerRegistry>`
  * Meant for use with private docker-registry setups.

* `-e, --exclude-string-fields=<excludeStringFields>`
  * CSV list of string fields to exclude from sanitization.

* `-f, --force-string-coder-match=<forceMatchStringCoder>`
  * Newer Java versions (Java 9+) may encode string instances differently. This setting forces sanitized value in heap dump
    to match the coder of the sanitization text provided via `-t` flag. If unset, some sanitized string fields may not be
    displayed correctly in analysis tools due to coder mismatch.

* `-s, --sanitize-byte-char-arrays-only`
  * When set to true, only byte[] and char[] arrays are sanitized. When false, all fields are sanitized (primitive, 
  non-primitive, array, non-array). Be warned that some tools like VisualVM may not be able to open such
  sanitized heap dumps; Eclipse Memory Analyzer (MAT) is known to work.

* `-S, --sanitize-arrays-only`
  * Deprecated. Use `--sanitize-byte-char-arrays-only` instead.

* `-t, --text=<sanitizationText>`
  * Sanitization text to replace with. Default is null character `\0`.

* `-z, --zip-output   Write zipped output`
  * When set, output heap dump is compressed in .hprof.zip format.

### FAQ

**Q: How can I sanitize non-array primitive fields?**
Set `--sanitize-byte-char-arrays-only=false`.

<a name="license"></a>

## Whitepaper

See [whitepaper (pdf)](https://github.com/paypal/heap-dump-tool/blob/statics/whitepaper.pdf)

## License

Heap Dump Tool is Open Source software released under the Apache 2.0 license.

