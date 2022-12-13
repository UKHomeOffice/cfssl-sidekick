FROM alpine:3.17 as main

RUN apk add curl openssl --update --no-cache && \
    adduser -D sidekick

ADD bin/cfssl-sidekick /cfssl-sidekick
ADD scripts/trigger_nginx_reload.sh /usr/local/scripts/trigger_nginx_reload.sh
RUN chmod +x /usr/local/scripts/trigger_nginx_reload.sh

USER 1000

ENTRYPOINT [ "/cfssl-sidekick" ]

FROM main as jks

USER root
RUN apk add openjdk17-jre bash --update --no-cache

ADD scripts/create-keystore.sh /usr/bin/create-keystore.sh

RUN mkdir -p /etc/ssl/java && \
    cp -r /etc/ssl/certs/java/cacerts /etc/ssl/java

USER 1000
