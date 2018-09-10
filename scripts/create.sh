#!/usr/bin/env bash

[[ -n ${DEBUG} ]] && set -x

# Expected Files
# /certs/tls.pem - Server cert - if missing create
# /certs/tls-key.pem - Server key - if missing create
# /etc/ssl/certs/ca.pem - CA Cert (or intermediate CA)
# /etc/ssl/certs/ca-bundle.crt - CA Bundle

CERTIFICATE_FILE="${CERTIFCATE_FILE:-/certs/tls.pem}"
PRIVATE_KEY_FILE="${PRIVATE_KEY_FILE:-/certs/tls-key.pem}"

IMPORT_SYSTEM_TRUSTSTORE=${IMPORT_SYSTEM_TRUSTSTORE:-"true"}
JAVA_CACERTS=${JAVA_CACERTS:-"/etc/ssl/java/cacerts"}
KEYSTORE_RUNTIME=${KEYSTORE_RUNTIME:-"/etc/keystore"}
KEYSTORE_FILE=${KEYSTORE_FILE:-"${KEYSTORE_RUNTIME}/keystore.jks"}
TRUSTSTORE_FILE=${TRUSTSTORE_FILE:-"${KEYSTORE_RUNTIME}/truststore.jks"}

# step: create the keystore runtime
mkdir -p ${KEYSTORE_RUNTIME}

announce() {
  [ -n "$@" ] && echo "[v] --> $@"
}

failed() {
  echo "[failed] $@" && exit 1
}

create_truststore() {
  announce "Creating a JAVA truststore as ${TRUSTSTORE_FILE}"
  if [ -f "${CA_CERT_FILE}" ]; then
    announce "Importing the CA ${CA_CERT_FILE} into the keystore"
    keytool -import -alias ca -file ${CA_CERT_FILE} -keystore ${TRUSTSTORE_FILE} \
      -noprompt -storepass changeit -trustcacerts
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

create_certs() {
    announce "Create Certificates."
    [ -z "${DOMAIN}" ] || failed "Certificate Domain name not supplied"
    /cfssl-sidekick --certs=/certs --expiry=8760h --domain=${DOMAIN}
}

# step: at the very least we must have cert and private key
if [[ -f "${CERTIFICATE_FILE}" ]] && [[ -f "${PRIVATE_KEY_FILE}" ]]
then
    create_truststore
    create_keystore
else
    create_certs
    create_truststore
    create_keystore
fi
