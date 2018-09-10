#! /bin/sh

NGINX_PORT="${NGINX_PORT:-10443}"

touch /tmp/triggering-nginx-reload
/usr/bin/curl -k https://localhost:${NGINX_PORT}/reload
touch /tmp/triggered-nginx-reload
