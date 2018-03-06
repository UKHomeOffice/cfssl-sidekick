FROM alpine:3.7
MAINTAINER Rohith Jayawardene <gambol99@gmail.com>

RUN apk add curl openssl --update && \
    adduser -D sidekick

ADD bin/cfssl-sidekick /cfssl-sidekick

USER 1000

ENTRYPOINT [ "/cfssl-sidekick" ]
