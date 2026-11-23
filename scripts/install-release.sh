#!/usr/bin/env bash
set -euo pipefail

workload_user=clawrun
workload_home=/home/clawrun
workload_prefix="$workload_home/.local"

within_workload() (
  node_bin=$(dirname -- "$(command -v node)")
  cd /
  exec sudo -n -u "$workload_user" -- /usr/bin/env -i \
    PATH="$node_bin:$workload_prefix/bin:/usr/bin:/bin" HOME="$workload_home" \
    CI=true NODE_ENV=production "$@"
)

if [[ "$1" == prepare ]]; then
  sudo -n useradd --create-home --home-dir "$workload_home" --shell /usr/sbin/nologin "$workload_user"
  sudo -n chmod 0700 "$workload_home"
  within_workload /bin/sh -eu -c '
    test "$(id -un)" = clawrun
    test "$(node --version)" = v24.22.3
    npm install --global --prefix "$1" --registry=https://registry.npmjs.org --no-audit --no-fund openclaw@2026.11.7
    test "$(node -p "require(process.argv[1]).version" "$1/lib/node_modules/openclaw/package.json")" = 2026.11.7
  ' sh "$workload_prefix"
  exit
fi

if [[ "$1" == first-load ]]; then
  plugin=$(jq -er '.plugin | select(test("^[a-z0-9-]+$"))' "$2")
  within_workload /bin/sh -eu -c '
    openclaw config set gateway.mode local
    openclaw config set plugins.allow "[\"$1\"]" --strict-json
    openclaw plugins enable "$1"
    openclaw gateway run --bind loopback --auth none --port 18789 &
    gateway=$!
    trap "kill -TERM $gateway 2>/dev/null || true; wait $gateway || true" EXIT
    attempts=0
    until node -e "fetch(\"http://127.0.0.1:18789/startupz\", {signal: AbortSignal.timeout(1000)}).then(r => {if (!r.ok) process.exitCode = 1}, () => {process.exitCode = 1})"; do
      kill -0 "$gateway"
      attempts=$((attempts + 1))
      if [ "$attempts" -ge 60 ]; then
        printf "Gateway did not finish startup\\n" >&2
        exit 1
      fi
      sleep 1
    done
    printf "Gateway finished startup; observing for 10 seconds\\n"
    sleep 10
    kill -TERM "$gateway"
    wait "$gateway"
    trap - EXIT
    printf "Gateway stopped cleanly\\n"
  ' sh "$plugin"
  exit
fi

[[ "$1" == install || "$1" == check-scan ]]
case_id=$(basename -- "$2" .json)
[[ "$case_id" =~ ^[a-z0-9-]+$ ]]
package=$(jq -er '.package | select(test("^(@[a-z0-9-]+/)?[a-z0-9-]+$"))' "$2")
version=$(jq -er '.version | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' "$2")
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scan="$root/clawscan/$case_id/$version/scan.json"
if ! expected=$(jq -er --arg package "$package" --arg version "$version" '
    select(.package == $package and .version == $version)
    | .sha256 | select(test("^[a-f0-9]{64}$"))
  ' "$scan"); then
  printf 'Missing or invalid scan digest for %s@%s: %s\n' "$package" "$version" "$scan" >&2
  exit 1
fi
if [[ "$1" == check-scan ]]; then
  printf 'Found archived scan digest for %s@%s: %s\n' "$package" "$version" "$expected"
  exit
fi

within_workload /bin/sh -eu -c '
    openclaw plugins install "$1"
    openclaw plugins list
  ' sh "clawhub:$package@$version"

escaped_package=$(jq -rn --arg package "$package" '$package | @uri')
artifact_url="https://clawhub.ai/api/v1/packages/$escaped_package/versions/$version/artifact/download"
if ! checksum=$(curl --fail --silent --show-error --location --max-time 120 "$artifact_url" | sha256sum); then
  printf 'Could not retrieve ClawHub artifact for %s@%s\n' "$package" "$version" >&2
  exit 1
fi
actual=${checksum%% *}
if [[ "$actual" != "$expected" ]]; then
  printf 'ClawHub artifact SHA-256 mismatch for %s@%s: expected %s, got %s\n' \
    "$package" "$version" "$expected" "$actual" >&2
  exit 1
fi
printf 'Verified ClawHub release artifact SHA-256 for %s@%s: %s\n' "$package" "$version" "$actual"
