#!/bin/bash
set -euo pipefail

TMPDIR="${TMPDIR:-/tmp/}"

# don't use JAVA_TOOL_OPTIONS to avoid JVM's "Picked up ..." message messing up piping to bash
exec java -Djava.io.tmpdir=$TMPDIR ${JAVA_OPTS:-} -jar $APP_JAR $*
