#!/bin/sh
set -eu

options=/data/options.json

required_option() {
  jq -er \
    --arg key "$1" \
    '.[$key] | select(type == "string" and length > 0)' \
    "$options"
}

export EUFY_USERNAME="$(required_option username)"
export EUFY_PASSWORD="$(required_option password)"
export EUFY_COUNTRY="$(required_option country)"

export EUFY_VERIFY_CODE="$(
  jq -r '.verification_code // empty' "$options"
)"

force_reprovision="$(
  jq -r '.force_reprovision // false' "$options"
)"

case "$force_reprovision" in
  true)
    export EUFY_E31_FORCE_REPROVISION=1
    ;;
  *)
    export EUFY_E31_FORCE_REPROVISION=0
    ;;
esac

export EUFY_GATEWAY_DATA_DIR=/data/runtime

echo "======================================================"
echo " Eufy E31 MQTT Transport Probe"
echo " Certificate provisioning + TLS + MQTT CONNECT only"
echo " NO SUBSCRIBE"
echo " NO PUBLISH"
echo " NO LOCK / UNLOCK"
echo "======================================================"

exec node /app/dist/probes/e31-mqtt-probe.js