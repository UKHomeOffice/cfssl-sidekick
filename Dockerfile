FROM alpine:20210212
MAINTAINER Rohith Jayawardene <gambol99@gmail.com>

RUN apk add curl openssl --update && \
    adduser -D sidekick

ADD bin/cfssl-sidekick /cfssl-sidekick
ADD scripts/trigger_nginx_reload.sh /usr/local/scripts/trigger_nginx_reload.sh
RUN chmod +x /usr/local/scripts/trigger_nginx_reload.sh

USER 1000

ENTRYPOINT [ "/cfssl-sidekick" ]
