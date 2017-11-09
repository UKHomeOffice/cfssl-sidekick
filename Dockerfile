FROM alpine:3.6
MAINTAINER Rohith Jayawardene <gambol99@gmail.com>

RUN apk add curl openssl --update && \
    adduser -D sidekick

ADD bin/cfssl-sidekick /cfssl-sidekick

USER sidekick

ENTRYPOINT [ "/cfssl-sidekick" ]
