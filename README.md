### CFSSL-SIDEKICK

Will provide a server TLS cert on demand from a [cfssl server](https://github.com/cloudflare/cfssl/blob/master/doc/api/intro.txt).

#### Kubernetes example sidekick or init container:

```
 - name: certs
   image: quay.io/ukhomeofficedigital/cfssl-sidekick:v0.0.2
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
