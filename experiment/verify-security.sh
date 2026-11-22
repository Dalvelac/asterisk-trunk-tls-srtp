#!/usr/bin/env bash
# Supplemental controls. Run on Linux outside the capture series with idle PBXs.
set -euo pipefail
cd "$(dirname "$0")/.."
cli() { ./lab compose exec -T "$1" asterisk -rx "$2"; }
inside() { ./lab compose exec -T "$@"; }
fresh() { ./lab up secure >/dev/null; }
originate() { cli pbx-a 'channel originate PJSIP/200@peer extension 101@caller-tone'; sleep 2; }
check_rejected() {
    if ./lab compose logs --no-color pbx-b | grep -F 'LAB-MEDIA '; then
        echo 'Unexpected answered media channel' >&2
        return 1
    fi
}
fresh
trial_dir=$(mktemp -d "$PWD/.lab/control.XXXXXX")
cp -R work "$trial_dir/work"
cat > "$trial_dir/compose.yaml" <<'YAML'
services:
  pbx-a:
    volumes:
      - ${LAB_CONTROL_TREE:?}:/lab:ro
YAML
export LAB_CONTROL_TREE="$trial_dir/work"
control_start() {
    ./lab compose -f compose.yaml -f "$trial_dir/compose.yaml" up -d --force-recreate --no-build --pull never --wait >/dev/null
}
# Only A mounts the temporary working copy during rejection tests.
trap './lab down >/dev/null; rm -rf -- "$trial_dir"' EXIT
echo "Verified at $(date -u +%FT%TZ)"
for node in a b; do
    echo "pbx-$node TLS transport and certificate"
    cli "pbx-$node" 'pjsip show transport link' | grep -E '^ (verify_client|verify_server|require_client_cert|method|protocol) '
    crt=".lab/pki/$node/node.crt"
    openssl x509 -in "$crt" -noout -subject -issuer -dates -ext subjectAltName
    openssl x509 -in "$crt" -noout -fingerprint -sha256
    openssl verify -CAfile ".lab/pki/$node/ca.crt" -purpose sslserver -verify_hostname "pbx-$node.lab.test" "$crt"
    openssl verify -CAfile ".lab/pki/$node/ca.crt" -purpose sslclient "$crt"
done
echo 'Live authenticated TLS connection A to B'
client=(openssl s_client -brief -tls1_2 -connect pbx-b.lab.test:5061 -servername pbx-b.lab.test
        -verify_hostname pbx-b.lab.test -verify_return_error -CAfile /identity/ca.crt)
inside pbx-a "${client[@]}" -cert /identity/node.crt -key /identity/node.key </dev/null 2>&1
echo 'B rejects a TLS client without its certificate'
if message=$(inside pbx-a "${client[@]}" </dev/null 2>&1); then
    echo 'Unexpected accepted connection' >&2; exit 1
fi
grep -Ei 'alert.*(handshake failure|certificate required)' <<< "$message"

echo 'Supplemental call with read-only reporting of installed SRTP policy parameters'
cc -O2 -Wall -Wextra -fPIC -shared -o .lab/verify-policy.so experiment/verify-policy.c -ldl
./lab compose -f compose.yaml -f experiment/policy.compose.yaml up -d --force-recreate --no-build --pull never --wait >/dev/null
inside pbx-a dpkg-query -W libsrtp2-1
./lab call
for node in pbx-a pbx-b; do
    echo "$node"
    ./lab compose logs --no-color "$node" | grep -F 'LAB-POLICY RTP' | sort -u
done

echo 'Authenticated TLS with plaintext-only audio offered by A'
sed -i 's/^media_encryption=sdes$/media_encryption=no/' "$trial_dir/work/profiles/secure.conf"
control_start
cli pbx-a 'pjsip show endpoint peer' | grep -Eq '^ media_encryption +: no$'
cli pbx-b 'pjsip show endpoint peer' | grep -Eq '^ media_encryption +: sdes$'
for node in pbx-a pbx-b; do
    echo "$node"
    cli "$node" 'pjsip show endpoint peer' | grep -E '^ media_encryption '
done
originate
./lab compose logs --no-color pbx-b | grep -E "Couldn't negotiate stream|No joint capabilities|incompatible media"
check_rejected

echo 'A dials the correct IP using a DNS name outside B’s certificate'
sed 's/@PEER_NAME@/pbx-b/g' work/profiles/secure.conf > "$trial_dir/work/profiles/secure.conf"
control_start
cli pbx-a 'pjsip show aor peer' | grep -F 'sip:pbx-b:5061'
originate
./lab compose logs --no-color pbx-a | grep -Ei 'identity does not match|identity not match|identity mismatch|name mismatch|certificate.*match|PJSIP_TLS_ECERTVERIF'
check_rejected
