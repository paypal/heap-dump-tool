#!/bin/bash
set -euo pipefail

export JAVA_OPTS="${JAVA_OPTS--Xmx512m -Xms512m -XX:-OmitStackTraceInFastThrow}"

java $JAVA_OPTS -jar $APP_JAR $*
