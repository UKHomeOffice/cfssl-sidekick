#!/usr/bin/env bash

[[ -n ${DEBUG} ]] && set -x

# Expected Files
# /certs/tls.pem - Server cert - if missing create
# /certs/tls-key.pem - Server key - if missing create
# /etc/ssl/certs/chain-ca.pem - CA Cert (or intermediate CA)
# /etc/ssl/certs/ca-bundle.crt - CA Bundle

CERTIFICATE_FILE="${CERTIFCATE_FILE:-/certs/tls.pem}"
PRIVATE_KEY_FILE="${PRIVATE_KEY_FILE:-/certs/tls-key.pem}"
CA_CERT_DIR="${CA_CERT_DIR:-/certs}"
IMPORT_SYSTEM_TRUSTSTORE="${IMPORT_SYSTEM_TRUSTSTORE:-true}"
JAVA_CACERTS="${JAVA_CACERTS:-/etc/ssl/java/cacerts}"
KEYSTORE_RUNTIME="${KEYSTORE_RUNTIME:-/etc/keystore}"
KEYSTORE_FILE="${KEYSTORE_FILE:-${KEYSTORE_RUNTIME}/keystore.jks}"
TRUSTSTORE_FILE="${TRUSTSTORE_FILE:-${KEYSTORE_RUNTIME}/truststore.jks}"
RELOAD_NGINX="${RELOAD_NGINX:-false}"
NGINX_PORT="${NGINX_PORT:-10443}"

announce() {
  [ -n "$@" ] && echo "[v] --> $@"
}

failed() {
  echo "[failed] $@" && exit 1
}

create_truststore() {
  announce "Creating a JAVA truststore as ${TRUSTSTORE_FILE}"
  if [[ -d "${CA_CERT_DIR}" ]]
  then
    find ${CA_CERT_DIR} \( -name '*ca*.crt' -o  -name '*ca*.pem' \) -type f | xargs -r basename >> /tmp/certs_list
    for CA in `cat /tmp/certs_list`
    do
      announce "Importing ${CA} into JAVA truststore"
      keytool -import -alias ${CA%%.*} -file ${CA} -keystore ${TRUSTSTORE_FILE} -noprompt -storepass changeit -trustcacerts
    done
  fi

  if [[ ${IMPORT_SYSTEM_TRUSTSTORE} == 'true' ]]; then
    announce "Importing ${JAVA_CACERTS} into ${TRUSTSTORE_FILE}."
    keytool -importkeystore -destkeystore ${TRUSTSTORE_FILE} \
      -srckeystore ${JAVA_CACERTS} -srcstorepass changeit \
      -noprompt -storepass changeit &> /dev/null
  fi
}

create_keystore() {
  announce "Creating a temporary pkcs12 keystore."
  openssl pkcs12 -export -name cert -in ${CERTIFICATE_FILE} -inkey ${PRIVATE_KEY_FILE} -nodes \
    -CAfile ${CA_CERT_FILE} -out ${KEYSTORE_RUNTIME}/keystore.p12 -passout pass: || failed "unable to convert certificates pkcs12 format"

  announce "Creating a JAVA keystore as ${KEYSTORE_FILE}."
  keytool -importkeystore -destkeystore ${KEYSTORE_FILE} \
    -srckeystore ${KEYSTORE_RUNTIME}/keystore.p12 -srcstoretype pkcs12 \
    -alias cert -srcstorepass '' -noprompt -storepass changeit || failed "unanle to import the pkcs12 into keystore"

  keytool -keypasswd -new changeit -keystore ${KEYSTORE_FILE} -storepass changeit -alias cert -keypass ''
}

create_stores() {
    sleep 10
    create_truststore
    create_keystore
}

# step: at the very least we must have cert and private key
if [[ -f "${CERTIFICATE_FILE}" ]] && [[ -f "${PRIVATE_KEY_FILE}" ]]
then
    create_stores
    if [[ "${RELOAD_NGINX}" == "true" ]]
    then
        /usr/bin/trigger_nginx_reload.sh ${NGINX_PORT}
    fi
else
    failed "Certificate or Key missing"
fi
