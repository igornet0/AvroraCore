#!/bin/sh
# AvroraCore container entrypoint: avrora (control+UI) or sql (pgwire).
# Set AVRORA_DEV=1 (+ secrets from docker/env.dev) for auto-provisioned local stack.
set -eu

AVRORA_HOME="${AVRORA_HOME:-/var/lib/avrora}"
AVRORA_DATA="${AVRORA_DATA:-$AVRORA_HOME/avrora.dbs.json}"
AVRORA_CONTROL_DIR="${AVRORA_CONTROL_DIR:-$AVRORA_HOME/control}"
AVRORA_ADDR="${AVRORA_ADDR:-0.0.0.0:18787}"
AVRORA_CONTROL_ADDR="${AVRORA_CONTROL_ADDR:-0.0.0.0:7432}"
INVITE_HOST="${INVITE_HOST:-127.0.0.1}"
INVITE_PORT="${INVITE_PORT:-7432}"
AVRORA_UID="${AVRORA_UID:-10001}"
AVRORA_GID="${AVRORA_GID:-10001}"

SQL_DATA="${SQL_DATA:-$AVRORA_HOME/sql.dbs.json}"
SQL_MASTER_KEY="${SQL_MASTER_KEY:-$AVRORA_HOME/sql.master.key}"
SQL_ADDR="${SQL_ADDR:-0.0.0.0:15432}"

DEV_MASTER_FILE="$AVRORA_HOME/.avrora-dev-master.hex"

export AVRORA_HOME AVRORA_DATA AVRORA_CONTROL_DIR AVRORA_ADDR AVRORA_CONTROL_ADDR

# Named volumes are often root-owned on first mount.
if [ "$(id -u)" = "0" ]; then
  mkdir -p "$AVRORA_HOME" "$AVRORA_CONTROL_DIR" \
    "$(dirname "$AVRORA_DATA")" \
    "$(dirname "$SQL_DATA")" \
    "$(dirname "$SQL_MASTER_KEY")"
  chown -R "${AVRORA_UID}:${AVRORA_GID}" "$AVRORA_HOME"
  exec gosu avrora "$0" "$@"
fi

mkdir -p "$AVRORA_HOME" "$AVRORA_CONTROL_DIR" \
  "$(dirname "$AVRORA_DATA")" \
  "$(dirname "$SQL_DATA")" \
  "$(dirname "$SQL_MASTER_KEY")"

ensure_control() {
  if [ ! -f "$AVRORA_CONTROL_DIR/tls/server.crt" ]; then
    echo "control plane: initializing → $AVRORA_CONTROL_DIR"
    avrora init \
      --data-dir "$AVRORA_CONTROL_DIR" \
      --invite-host "$INVITE_HOST" \
      --invite-port "$INVITE_PORT"
  else
    echo "control plane: already initialized ($AVRORA_CONTROL_DIR)"
  fi
}

write_dev_master_file() {
  hex="${1:-}"
  if [ -z "$hex" ]; then
    return 0
  fi
  printf '%s\n' "$hex" >"$DEV_MASTER_FILE"
  chmod 600 "$DEV_MASTER_FILE" 2>/dev/null || true
}

ensure_dev_vault() {
  # Always keep env.dev master in the auto-unlock file when provided.
  if [ -n "${AVRORA_MASTER_KEY_HEX:-}" ]; then
    write_dev_master_file "$AVRORA_MASTER_KEY_HEX"
  fi

  if [ -f "$AVRORA_DATA" ] || [ -d "${AVRORA_DATA%.dbs.json}" ]; then
    # Vault may already exist; try status / skip if provisioned.
    if avrora status 2>/dev/null | grep -qi 'Unlocked\|Locked\|identity'; then
      :
    fi
  fi

  demo_flag=
  case "${AVRORA_DEVO_DEMO:-0}" in
    1|true|TRUE|yes|YES) demo_flag=--demo ;;
  esac

  set -- devo-init $demo_flag
  if [ -n "${AVRORA_MASTER_KEY_HEX:-}" ]; then
    set -- "$@" --master-hex "$AVRORA_MASTER_KEY_HEX"
  fi
  if [ -n "${AVRORA_UI_ACCESS_KEY:-}" ]; then
    set -- "$@" --ui-access-key "$AVRORA_UI_ACCESS_KEY"
  fi
  if [ -n "${AVRORA_UI_TOTP_SECRET:-}" ]; then
    set -- "$@" --ui-totp-secret "$AVRORA_UI_TOTP_SECRET"
  fi

  echo "dev provisioning: avrora $*"
  if out="$(avrora "$@" 2>&1)"; then
    echo "$out"
  else
    # Already provisioned on a previous boot — expected.
    case "$out" in
      *"already provisioned"*)
        echo "dev provisioning: already done (ok)"
        ;;
      *)
        echo "$out" >&2
        exit 1
        ;;
    esac
  fi

  if [ -n "${AVRORA_MASTER_KEY_HEX:-}" ]; then
    write_dev_master_file "$AVRORA_MASTER_KEY_HEX"
  fi

  echo "── DEV credentials (from env) ──"
  echo "UI access_key=${AVRORA_UI_ACCESS_KEY:-<unset>}"
  echo "UI totp_secret=${AVRORA_UI_TOTP_SECRET:-<unset>}"
  if [ -n "${AVRORA_UI_TOTP_SECRET:-}" ]; then
    echo "otpauth://totp/Avrora:ui?secret=${AVRORA_UI_TOTP_SECRET}&issuer=Avrora"
    echo "TOTP code: oathtool --totp -b ${AVRORA_UI_TOTP_SECRET}"
  fi
  echo "vault master → $DEV_MASTER_FILE"
  echo "───────────────────────────────"
}

run_avrora() {
  ensure_control

  if [ "${AVRORA_DEV:-0}" = "1" ] || [ "${AVRORA_DEV:-}" = "true" ]; then
    ensure_dev_vault
  fi

  if [ -f "$AVRORA_CONTROL_DIR/invite.json" ]; then
    echo "invite: $AVRORA_CONTROL_DIR/invite.json"
  fi
  if [ -f "$AVRORA_CONTROL_DIR/bootstrap.token" ]; then
    echo "bootstrap token present (one-shot enroll)"
  fi

  echo "avrora serve  http=$AVRORA_ADDR  control=$AVRORA_CONTROL_ADDR  dev=${AVRORA_DEV:-0}"
  exec avrora serve
}

run_sql() {
  # Prefer fixed SQL master from env.dev when set.
  if [ -n "${SQL_MASTER_KEY_HEX:-}" ]; then
    (umask 077 && printf '%s' "$SQL_MASTER_KEY_HEX" >"$SQL_MASTER_KEY")
    chmod 600 "$SQL_MASTER_KEY"
  fi

  if [ -f "$SQL_DATA" ] && [ -f "$SQL_MASTER_KEY" ]; then
    echo "sql unlock → $SQL_ADDR  data=$SQL_DATA"
    exec dmc-pgwire --data "$SQL_DATA" --listen "$SQL_ADDR" \
      --unlock-file "$SQL_MASTER_KEY"
  fi

  if [ -f "$SQL_DATA" ]; then
    echo "SQL data exists but master key missing: $SQL_MASTER_KEY" >&2
    exit 1
  fi

  echo "sql create → $SQL_ADDR  data=$SQL_DATA"
  if [ -f "$SQL_MASTER_KEY" ]; then
    # fixed SQL_MASTER_KEY_HEX from env was written to the key file above
    echo "using fixed SQL master key from $SQL_MASTER_KEY"
    exec dmc-pgwire --data "$SQL_DATA" --listen "$SQL_ADDR" \
      --create --master-hex-file "$SQL_MASTER_KEY"
  fi

  # The key is written by dmc-pgwire itself (0600); it is never printed or logged.
  echo "master key will be saved to $SQL_MASTER_KEY"
  exec dmc-pgwire --data "$SQL_DATA" --listen "$SQL_ADDR" \
    --create --master-key-out "$SQL_MASTER_KEY"
}

cmd="${1:-avrora}"
if [ "$#" -gt 0 ]; then
  shift
fi

case "$cmd" in
  avrora|serve|core)
    run_avrora "$@"
    ;;
  sql|pgwire)
    run_sql "$@"
    ;;
  init)
    exec avrora init \
      --data-dir "$AVRORA_CONTROL_DIR" \
      --invite-host "$INVITE_HOST" \
      --invite-port "$INVITE_PORT" \
      "$@"
    ;;
  invite)
    exec avrora invite \
      --data-dir "$AVRORA_CONTROL_DIR" \
      --host "$INVITE_HOST" \
      --port "$INVITE_PORT" \
      --write \
      "$@"
    ;;
  status)
    exec avrora status "$@"
    ;;
  credentials|creds)
    echo "UI access_key=${AVRORA_UI_ACCESS_KEY:-<unset>}"
    echo "UI totp_secret=${AVRORA_UI_TOTP_SECRET:-<unset>}"
    if [ -n "${AVRORA_UI_TOTP_SECRET:-}" ]; then
      echo "otpauth://totp/Avrora:ui?secret=${AVRORA_UI_TOTP_SECRET}&issuer=Avrora"
    fi
    echo "AVRORA_MASTER_KEY_HEX=${AVRORA_MASTER_KEY_HEX:-<unset>}"
    echo "SQL_MASTER_KEY_HEX=${SQL_MASTER_KEY_HEX:-<unset>}"
    ;;
  shell|sh)
    exec /bin/sh "$@"
    ;;
  *)
    exec "$cmd" "$@"
    ;;
esac
