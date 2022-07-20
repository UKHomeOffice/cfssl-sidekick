FROM alpine:3.16 as standard

RUN apk add --no-cache curl openssl --update && \
    adduser -D sidekick

COPY bin/cfssl-sidekick /cfssl-sidekick
COPY scripts/trigger_nginx_reload.sh /usr/local/scripts/trigger_nginx_reload.sh

RUN chmod +x /usr/local/scripts/trigger_nginx_reload.sh

USER 1000

ENTRYPOINT [ "/cfssl-sidekick" ]


FROM standard as jks

RUN apk add --no-cache openjdk17-jre bash

COPY scripts/create-keystore.sh /usr/bin/create-keystore.sh

RUN mkdir -p /etc/ssl/java && \
    cp -r /etc/ssl/certs/java/cacerts /etc/ssl/java

USER 1000
