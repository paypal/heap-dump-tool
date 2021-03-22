# Heap Dump Tool

Heap Dump Tool can capture and, more importantly, sanitize sensitive data from Java heap dumps. Sanitization is accomplished
by replacing field values in the heap dump file with zero values. Heap dump can then be more freely shared freely and analyzed.

A typical scenario is when a heap dump needs to be sanitized before it can be given to another person or moved to a different
environment. For example, an app running in production environment may contain sensitive data (passwords, credit card
numbers, etc) which should not be viewable when the heap dump is copied to a development environment for analysis with a
graphical program.

---

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
$ docker run paypal/heap-dump-tool capture my-app | bash
```

<br/>

<a name="usage"></a>

## Usage

```
java -jar target/heap-dump-tool.jar  help
Usage: heap-dump-tool [-hV] [COMMAND]
Tool for capturing or sanitizing heap dumps
  -h, --help      Show this help message and exit.
  -V, --version   Print version information and exit.
Commands:
  capture   Capture sanitized heap dump of a containerized app
  sanitize  Sanitize a heap dump by replacing byte and char array contents
  help      Displays help information about the specified command
```

<a name="license"></a>

## License

Spring Boot is Open Source software released under the Apache 2.0 license.

