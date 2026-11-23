#!/usr/bin/env bash
set -euo pipefail

network=plugin-install
subnet=172.29.47.0/24
bridge=oc-release
container=plugin-release

if [[ "$1" == cleanup ]]; then
  if docker container inspect "$container" >/dev/null 2>&1; then
    docker rm -f "$container" >/dev/null
  fi
  if docker network inspect "$network" >/dev/null 2>&1; then
    docker network rm "$network" >/dev/null
  fi
  exit
fi

within_container() {
  docker exec "$container" /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin \
    HOME=/tmp/openclaw-home CI=true NODE_ENV=production "$@"
}

if [[ "$1" == first-load ]]; then
  plugin=$(jq -er '.plugin | select(test("^[a-z0-9-]+$"))' "$2")
  within_container /bin/sh -eu -c '
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
      if [ "$attempts" -ge 25 ]; then
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

[[ "$1" == install ]]
package=$(jq -er '.package | select(test("^(@[a-z0-9-]+/)?[a-z0-9-]+$"))' "$2")
version=$(jq -er '.version | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))' "$2")
docker network create --opt "com.docker.network.bridge.name=$bridge" \
  --ipv6=false --subnet "$subnet" "$network" >/dev/null

sudo iptables -I INPUT -i "$bridge" -j REJECT
for destination in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
  172.16.0.0/12 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4; do
  sudo iptables -I DOCKER-USER -i "$bridge" -d "$destination" -j REJECT
done

docker run -d --name "$container" --pull never --init --network "$network" \
  --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,mode=1777 --pids-limit 256 \
  --entrypoint /bin/sleep openclaw-runtime:2026.11.7 infinity >/dev/null
within_container /bin/sh -eu -c '
    mkdir "$HOME"
    openclaw plugins install "$1"
    openclaw plugins list
  ' sh "clawhub:$package@$version"
