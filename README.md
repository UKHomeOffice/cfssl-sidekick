### CFSSL-SIDEKICK

Will provide a server TLS cert on demand from a [cfssl server](https://github.com/cloudflare/cfssl/blob/master/doc/api/intro.txt).

#### Kubernetes example sidekick or init container:

```YAML
- name: certs
 image: quay.io/ukhomeofficedigital/cfssl-sidekick:v0.0.5
 securityContext:
   runAsNonRoot: true
 args:
 - --certs=/certs
 - --domain=servicename.${KUBE_NAMESPACE}.svc.cluster.local
 - --expiry=8760h
 env:
 - name: KUBE_NAMESPACE
   valueFrom:
     fieldRef:
       fieldPath: metadata.namespace
 volumeMounts:
 - name: certs
   mountPath: /certs
 - name: bundle
   mountPath: /etc/ssl/certs
   readOnly: true
```

We always produce a Java version, which includes a create-keystore.sh script used to generate a Java key and trust store.

```YAML
- name: certs
 image: quay.io/ukhomeofficedigital/cfssl-sidekick-jks:v0.0.5
 securityContext:
   runAsNonRoot: true
 args:
 - --certs=/certs
 - --domain=servicename.${KUBE_NAMESPACE}.svc.cluster.local
 - --command=/usr/bin/create-keystore.sh /certs/tls.pem /certs/tls-key.pem /etc/ssl/certs/acp-root.crt
 - --expiry=8760h
 env:
 - name: KUBE_NAMESPACE
   valueFrom:
     fieldRef:
       fieldPath: metadata.namespace
 - name: KEYSTORE_PASSWORD
   value: anythingelse
 volumeMounts:
 - name: certs
   mountPath: /certs
 - name: bundle
   mountPath: /etc/ssl/certs
   readOnly: true
```

