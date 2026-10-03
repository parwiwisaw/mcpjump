#!/usr/bin/env bash
# Fails if a real implementation is named anywhere in src/ except its home
# files and the composition root, src/main.rs. Everything else takes the seam
# trait, so tests can inject fakes. Add each real implementation here as it
# lands. A factory behind a seam, such as SystemStores, is a second home for
# what it builds.
set -euo pipefail

# "TypeName home.rs[,other-home.rs]"
implementations=(
    "ProcessEnv src/sys/env.rs"
    "HttpConnector src/mcp/connector.rs"
    "StdTerminal src/sys/terminal.rs"
    "SystemStores src/store/system.rs"
    "FileStore src/store/file.rs,src/store/system.rs"
    "KeyringStore src/store/keyring.rs"
    "SystemClock src/sys/clock.rs"
    "WebBrowser src/sys/browser.rs"
)

status=0
for entry in "${implementations[@]}"; do
    read -r name homes <<<"$entry"
    allowed="${homes//,/|}|src/main.rs"
    allowed="${allowed//./\\.}"
    if grep -rnw "$name" src --include='*.rs' | grep -vE "^($allowed):"; then
        echo "composition root: $name may appear only in $homes and src/main.rs" >&2
        status=1
    fi
done
[ "$status" -eq 0 ] && echo "composition root: ok"
exit "$status"
