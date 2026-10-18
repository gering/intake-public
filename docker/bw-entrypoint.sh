#!/bin/sh
set -eu
umask 0077

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

: "${BW_SERVER:?BW_SERVER is required}"
: "${BW_CLIENTID_FILE:?BW_CLIENTID_FILE is required}"
: "${BW_CLIENTSECRET_FILE:?BW_CLIENTSECRET_FILE is required}"
: "${BW_PASSWORD_FILE:?BW_PASSWORD_FILE is required}"

check_secret_file() {
    [ -f "$1" ] && [ -r "$1" ] || return 1
    mode=$(stat -c %a -- "$1" 2>/dev/null) || return 1
    case "$mode" in
        ''|*[!0-7]*) return 1 ;;
    esac
    [ "$((0$mode & 077))" -eq 0 ]
}

for file in "$BW_CLIENTID_FILE" "$BW_CLIENTSECRET_FILE" "$BW_PASSWORD_FILE"; do
    check_secret_file "$file" || fail 'Vault secret files are unreadable or unsafe.'
done

unset BW_CLIENTID BW_CLIENTSECRET BW_SESSION BW_RESPONSE BW_RAW BW_QUIET BW_CLEANEXIT
export BW_NOINTERACTION=true

if bw login --check >/dev/null 2>&1; then
    # The CLI refuses even an unchanged server setter while logged in.
    if ! server=$(bw config server 2>/dev/null) || [ "$server" != "$BW_SERVER" ]; then
        fail 'Vault server does not match the existing CLI profile.'
    fi
else
    bw config server "$BW_SERVER" >/dev/null 2>&1 || fail 'Vault server configuration failed.'
    client_id=$(cat "$BW_CLIENTID_FILE" 2>/dev/null) || fail 'Vault API credentials are unreadable.'
    client_secret=$(cat "$BW_CLIENTSECRET_FILE" 2>/dev/null) || fail 'Vault API credentials are unreadable.'
    [ -n "$client_id" ] && [ -n "$client_secret" ] || fail 'Vault API credentials are empty.'
    BW_CLIENTID="$client_id" BW_CLIENTSECRET="$client_secret" bw login --apikey >/dev/null 2>&1 \
        || fail 'Vault API login failed.'
    unset client_id client_secret
fi

if ! BW_SESSION=$(bw unlock --passwordfile "$BW_PASSWORD_FILE" --raw 2>/dev/null); then
    fail 'Vault unlock failed.'
fi
[ -n "$BW_SESSION" ] || fail 'Vault unlock returned no session.'
export BW_SESSION
node /opt/intake/docker/prepare-bw-socket.js
exec bw serve --hostname unix:///run/intake-bw/bw.sock
