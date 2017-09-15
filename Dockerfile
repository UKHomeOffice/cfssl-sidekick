FROM alpine:3.6
MAINTAINER Rohith Jayawardene <gambol99@gmail.com>

ADD bin/cfssl-sidekick /cfssl-sidekick

ENTRYPOINT [ "/cfssl-sidekick" ]
