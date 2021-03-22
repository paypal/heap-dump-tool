FROM adoptopenjdk:8 as builder

# build nsenter1 in another stage
FROM adoptopenjdk:8 as nsenter1
RUN apt update \
    && apt install gcc libc6-dev -y
COPY src/main/c/nsenter1.c ./
RUN gcc -Wall -static nsenter1.c -o /usr/bin/nsenter1

# go back to original state and copy nsenter
FROM builder
COPY --from=nsenter1 /usr/bin/nsenter1 /usr/bin/nsenter1

WORKDIR /tmp/

ENV APP_ID heap-dump-tool
ENV APP_JAR /tmp/$APP_ID.jar
COPY src/main/docker/docker-entrypoint.sh /
COPY target/$APP_ID.jar /tmp/

RUN chmod ugo+x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
