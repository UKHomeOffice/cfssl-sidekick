#! /bin/sh

touch /tmp/triggering-nginx-reload
/usr/bin/curl -k https://localhost:10443/reload
touch /tmp/triggered-nginx-reload
