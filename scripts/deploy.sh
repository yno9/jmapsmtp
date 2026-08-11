#!/usr/bin/env bash
# Build on s2 and install on v1, from the Mac, in one command.
#
# The Mac cannot produce a binary v1 can run: it is arm64 Darwin, v1 is x86_64
# Linux, and cross-compiling is not a flag here — web-push pulls isahc → curl
# (C), and ring wants a C compiler too, so it means a musl cross toolchain.
#
# Building on s2 is also the only place the binary that actually ships gets
# built and tested on the same OS and architecture as production. A test run on
# the Mac exercises a different binary.
#
# Usage: just deploy [--no-restart]
set -euo pipefail

S2=${S2_HOST:-s2}
V1=${V1_HOST:-root@v1}
REMOTE_SRC=${REMOTE_SRC:-jmapsmtp-deploy}
RESTART=1
[ "${1:-}" = "--no-restart" ] && RESTART=0

cd "$(dirname "$0")/.."

# 1. Deploy something that exists in history. Today a build made from an
#    uncommitted tree was installed and then nobody could say what was running.
if [ -n "$(git status --porcelain)" ]; then
    echo "作業ツリーが汚れています。コミットするか stash してください:" >&2
    git status --short >&2
    exit 1
fi
COMMIT=$(git rev-parse --short HEAD)
SUBJECT=$(git log -1 --format=%s)
echo "== 配備するもの: $COMMIT  $SUBJECT"

# 2. Source to the build host. `.git`, `target` and `oracle` stay behind:
#    the first two are large and the third is a build product of the Go repos,
#    which live on this machine.
echo
echo "== 1/4 s2 へ同期"
rsync -a --delete \
    --exclude '.git' --exclude 'target' --exclude 'oracle' --exclude 'node_modules' \
    ./ "$S2:$REMOTE_SRC/"

# 3. Build there.
echo
echo "== 2/4 s2 でビルド（Linux / x86_64）"
ssh "$S2" "cd $REMOTE_SRC && \$HOME/.cargo/bin/cargo build --release -p jmapsmtp 2>&1 | tail -3"

# 4. Install on the relay, from s2 — it is the machine holding the binary.
echo
echo "== 3/4 v1 へ設置"
ssh "$S2" "bash -s" <<EOF
set -euo pipefail
scp -q $REMOTE_SRC/target/release/jmapsmtp $V1:/tmp/jmapsmtp-new
ssh $V1 bash -s <<'REMOTE'
set -euo pipefail
cp -a /root/jmapsmtp/jmapsmtp /root/jmapsmtp-bin-bak-\$(date +%Y%m%d-%H%M%S)
install -m 755 /tmp/jmapsmtp-new /root/jmapsmtp/jmapsmtp
rm -f /tmp/jmapsmtp-new
printf '%s\n' "$COMMIT" > /root/jmapsmtp/DEPLOYED_COMMIT
$([ "$RESTART" = 1 ] && echo "systemctl restart jmapsmtp" || echo "echo '(再起動は省略)'")
REMOTE
EOF

# 5. Say whether it came back, rather than assuming.
echo
echo "== 4/4 確認"
sleep 4
ssh "$S2" "ssh $V1 bash -s" <<'EOF'
set -uo pipefail
echo "  状態      : $(systemctl is-active jmapsmtp)"
echo "  配備コミット: $(cat /root/jmapsmtp/DEPLOYED_COMMIT 2>/dev/null || echo '?')"
echo "  --- 起動ログ ---"
journalctl -u jmapsmtp --since "1 minute ago" --no-pager \
    | grep -E "INFO|ERROR|WARN" | grep -v provision | tail -6 | sed 's/^/  /'
echo "  メッセージ: $(ls /root/jmapsmtp/data/biset.md/y/messages/*.json 2>/dev/null | wc -l) / キュー: $(ls -d /root/jmapsmtp/data/_queue/*/ 2>/dev/null | wc -l)"
EOF
