# browserid-ng — standard targets (same vocabulary in mingo, sbo, browserid-bsky):
#
#   make build            compile the whole workspace
#   make test             run the Rust + SDK test suites
#   make push             push HEAD to origin (triggers the CI image builds)
#   make watch            watch CI runs for HEAD until they all finish
#   make release          release HEAD's images to dokku (all apps)
#   make release-<app>    one app: broker | www | wallet | mcp-demo | python-mcp-demo | guestbook
#   make deploy           push + watch + release
#
# Deploy model: CI builds GHCR images per app (.github/workflows/deploy-*.yml);
# the CI ssh-release step fails on this host (deploy key not authorized — bean
# o7ip), so `release` does the `git:from-image` from here via the mini-ops key.
# `git:from-image` exits 1 on an unchanged image digest ("No changes detected")
# — expected when an app's paths didn't change — so release targets tolerate it.

SHA  := $(shell git rev-parse HEAD)
HOST ?= dokku@browserid.me
SSH  := ssh -i $(HOME)/.ssh/mini-ops -o StrictHostKeyChecking=accept-new
REG  := ghcr.io/vthunder/browserid-ng

.PHONY: build test push watch release deploy \
        release-broker release-www release-wallet release-mcp-demo \
        release-python-mcp-demo release-guestbook

build:
	cargo build --workspace

test:
	cargo test --workspace

push:
	git push origin HEAD

# gh's --commit filter needs the FULL sha — a short sha silently matches nothing.
watch:
	@echo "Watching CI for $(SHA)…"
	@while gh run list --commit $(SHA) --json status -q '.[].status' \
	    | grep -qE 'in_progress|queued|requested|waiting'; do sleep 15; done
	@gh run list --commit $(SHA)

# app-on-dokku ← image-on-ghcr
release-broker:          ; -$(SSH) $(HOST) git:from-image id               $(REG)/broker:$(SHA)
release-www:             ; -$(SSH) $(HOST) git:from-image www              $(REG)/www:$(SHA)
release-wallet:          ; -$(SSH) $(HOST) git:from-image browserid-wallet $(REG)/wallet:$(SHA)
release-mcp-demo:        ; -$(SSH) $(HOST) git:from-image mcp-demo         $(REG)/mcp-demo:$(SHA)
release-python-mcp-demo: ; -$(SSH) $(HOST) git:from-image python-mcp-demo  $(REG)/python-mcp-demo:$(SHA)
release-guestbook:       ; -$(SSH) $(HOST) git:from-image guestbook-mcp    $(REG)/guestbook-mcp:$(SHA)

release: release-broker release-www release-wallet release-mcp-demo release-python-mcp-demo release-guestbook

deploy: push watch release
