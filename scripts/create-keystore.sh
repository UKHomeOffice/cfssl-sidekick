#!/bin/bash

[[ -n ${DEBUG} ]] && set -x

IMPORT_SYSTEM_TRUSTSTORE=${IMPORT_SYSTEM_TRUSTSTORE:-"true"}
JAVA_CACERTS=${JAVA_CACERTS:-"/etc/ssl/java/cacerts"}
KEYSTORE_RUNTIME=${KEYSTORE_RUNTIME:-"/etc/keystore"}
KEYSTORE_FILE=${KEYSTORE_FILE:-"${KEYSTORE_RUNTIME}/keystore.jks"}
TRUSTSTORE_FILE=${TRUSTSTORE_FILE:-"${KEYSTORE_RUNTIME}/truststore.jks"}
KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD:-"changeit"}
# step: create the keystore runtime
mkdir -p ${KEYSTORE_RUNTIME}

annonce() {
  [ -n "$@" ] && echo "[v] --> $@"
}

failed() {
  echo "[failed] $@" && exit 1
}

create_truststore() {
  annonce "Creating a JAVA truststore as ${TRUSTSTORE_FILE}"
  if [ -f "${CA_CERT_FILE}" ]; then
    annonce "Importing the CA ${CA_CERT_FILE} into the keystore"
    keytool -import -alias ca -file ${CA_CERT_FILE} -keystore ${TRUSTSTORE_FILE} \
      -noprompt -storepass ${KEYSTORE_PASSWORD} -trustcacerts
  fi

  if [[ ${IMPORT_SYSTEM_TRUSTSTORE} == 'true' ]]; then
    annonce "Importing ${JAVA_CACERTS} into ${TRUSTSTORE_FILE}."
    keytool -importkeystore -destkeystore ${TRUSTSTORE_FILE} \
      -srckeystore ${JAVA_CACERTS} -srcstorepass changeit \
      -noprompt -storepass ${KEYSTORE_PASSWORD} &> /dev/null
  fi
}

create_keystore() {
  annonce 'Creating a temporary pkcs12 keystore.'
  openssl pkcs12 -export -name cert -in ${CERTIFICATE_FILE} -inkey ${PRIVATE_KEY_FILE} -nodes \
    -CAfile ${CA_CERT_FILE} -out ${KEYSTORE_RUNTIME}/keystore.p12 -passout pass: || failed "unable to convert certificates pkcs12 format"

  annonce "Creating a JAVA keystore as ${KEYSTORE_FILE}."
  keytool -importkeystore -destkeystore ${KEYSTORE_FILE} \
    -srckeystore ${KEYSTORE_RUNTIME}/keystore.p12 -srcstoretype pkcs12 \
    -alias cert -srcstorepass '' -noprompt -storepass ${KEYSTORE_PASSWORD} || failed "unanle to import the pkcs12 into keystore"

  keytool -keypasswd -new changeit -keystore ${KEYSTORE_FILE} -storepass ${KEYSTORE_PASSWORD} -alias cert -keypass ''
}

# step: the vault-sidekick will pass the file=<filename> or the name.type, we are ASSUMING the ca, key and cert are in .ca, .key and .crt
CERTIFICATE_FILE=${1}
PRIVATE_KEY_FILE=${2}
CA_CERT_FILE=${1}
[[ -n "${3}" ]] && CA_CERT_FILE="${3}"

# step: at the very least we must have cert and private key
[ -f "${CERTIFICATE_FILE}" ] || failed "cannot find the certificate file: ${CERTIFICATE_FILE}"
[ -f "${PRIVATE_KEY_FILE}" ] || failed "cannot find the private key file: ${PRIVATE_KEY_FILE}"

create_truststore
create_keystore
