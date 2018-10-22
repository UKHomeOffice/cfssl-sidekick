FROM golang:onbuild AS base
MAINTAINER Rohith Jayawardene <gambol99@gmail.com>
RUN mkdir /app
ADD . /app/
WORKDIR /app
RUN go get github.com/Masterminds/glide && \
    glide install
RUN go test -v
RUN gofmt -s -w *.go
RUN go tool vet -asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -shift -structtags -unsafeptr *.go
RUN go get -u github.com/golang/lint/golint
RUN golint .
RUN go test -v -bench=.
RUN CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -o /bin/cfssl-sidekick


FROM openjdk:8 AS javac
RUN mkdir /app
ADD ./SSLPoke.java /app
WORKDIR /app
RUN javac SSLPoke.java


FROM alpine:3.8
MAINTAINER Mark Olliver <mark@digitalpatterns.io>
RUN apk add curl openssl openjdk8-jre-base java-cacerts bash --update && \
    adduser -D sidekick
COPY --from=base bin/cfssl-sidekick /usr/bin/cfssl-sidekick
COPY --from=javac app/SSLPoke.class /usr/bin/SSLPoke.class
ADD scripts/trigger_nginx_reload.sh /usr/bin/trigger_nginx_reload.sh
ADD scripts/create.sh /usr/bin/create.sh
RUN chmod +x /usr/bin/trigger_nginx_reload.sh /usr/bin/create.sh /usr/bin/cfssl-sidekick && \
    mkdir -p /etc/ssl/java /etc/keystore /cacerts /certs && \
    cp -r /etc/ssl/certs/java/cacerts /etc/ssl/java && \
    rm /usr/lib/jvm/default-jvm/jre/lib/security/cacerts && \
    ln -s /etc/ssl/java/cacerts /usr/lib/jvm/default-jvm/jre/lib/security/cacerts && \
    chown -R sidekick /etc/ssl/java /etc/keystore /cacerts /certs
USER 1000
VOLUME ["/certs", "/etc/ssl/certs", "/etc/keystore", "/cacerts"]
ENTRYPOINT [ "/usr/bin/cfssl-sidekick", "--certs=/certs", "--expiry=8760h"]
CMD ["--domain=servicename.KUBE_NAMESPACE.svc.cluster.local", "--url=http://ca.kube-tls.svc.cluster.local", "--command=/usr/bin/create.sh"]