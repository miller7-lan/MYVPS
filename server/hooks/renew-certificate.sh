#!/bin/sh
set -eu
SERVER_IP="${VPS_SERVER_IP:-192.0.2.10}"
[ "$SERVER_IP" != 192.0.2.10 ] || { echo "Set VPS_SERVER_IP or edit SERVER_IP before installing hook" >&2; exit 1; }
[ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/qqg-ip ] || exit 0
openssl x509 -in "$RENEWED_LINEAGE/fullchain.pem" -noout -checkip "$SERVER_IP" >/dev/null
openssl x509 -in "$RENEWED_LINEAGE/fullchain.pem" -noout -checkend 86400 >/dev/null
cert_public=$(openssl x509 -in "$RENEWED_LINEAGE/fullchain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
key_public=$(openssl pkey -in "$RENEWED_LINEAGE/privkey.pem" -pubout -outform DER | sha256sum)
[ "$cert_public" = "$key_public" ]
/etc/s-box/sing-box check -c /etc/s-box/sb.json
cert_stage=$(mktemp /etc/s-box/.cert.XXXXXX)
key_stage=$(mktemp /etc/s-box/.key.XXXXXX)
trap 'rm -f "$cert_stage" "$key_stage"' EXIT
install -m 644 -o root -g sing-box "$RENEWED_LINEAGE/fullchain.pem" "$cert_stage"
install -m 640 -o root -g sing-box "$RENEWED_LINEAGE/privkey.pem" "$key_stage"
mv -f "$cert_stage" /etc/s-box/cert.pem
mv -f "$key_stage" /etc/s-box/private.key
# sing-box watches the parent directory and atomically adopts a valid TLS pair.
if [ -d /etc/qqg-sub/tls ]; then
 sub_cert=$(mktemp /etc/qqg-sub/tls/.cert.XXXXXX)
 sub_key=$(mktemp /etc/qqg-sub/tls/.key.XXXXXX)
 trap 'rm -f "$cert_stage" "$key_stage" "$sub_cert" "$sub_key"' EXIT
 install -m 644 -o root -g qqg-sub "$RENEWED_LINEAGE/fullchain.pem" "$sub_cert"
 install -m 640 -o root -g qqg-sub "$RENEWED_LINEAGE/privkey.pem" "$sub_key"
 mv -f "$sub_cert" /etc/qqg-sub/tls/cert.pem
 mv -f "$sub_key" /etc/qqg-sub/tls/private.key
 if systemctl is-active --quiet qqg-sub.service; then systemctl restart qqg-sub.service; fi
fi
