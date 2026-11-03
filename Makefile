# browserid-ng — standard targets (same vocabulary in mingo, sbo, browserid-bsky):
#
#   make build            compile the whole workspace
#   make test             run the Rust + SDK test suites
#   make audit            cargo-audit + npm audit + pip-audit + gitleaks (CI: supply-chain.yml)
#   make fuzz-smoke       run every cargo-fuzz target for FUZZ_SECS (default 60) — see fuzz/README.md
#   make fuzz-smoke-install  (dev box) install the weekly launchd agent org.sandmill.fuzz-smoke
#   make push             push HEAD to origin (triggers the CI image builds)
#   make watch            watch CI runs for HEAD until they all finish
#   make release          release HEAD's images to dokku (all apps)
#   make release-<app>    one app: broker | www | wallet | mcp-demo | python-mcp-demo | guestbook
#   make deploy           push + watch (CI releases the images itself)
#
# Deploy model: CI builds GHCR images per app (.github/workflows/deploy-*.yml)
# and releases them itself (browserid-ng-ci dokku key, fixed 2026-08-11 — bean
# o7ip). `release` is the manual fallback via the mini-ops key, e.g. for
# re-releasing an already-built image. `git:from-image` exits 1 on an unchanged
# image digest ("No changes detected") — expected when an app's paths didn't
# change — so release targets tolerate it.

SHA  := $(shell git rev-parse HEAD)
HOST ?= dokku@browserid.me
SSH  := ssh -i $(HOME)/.ssh/mini-ops -o StrictHostKeyChecking=accept-new
REG  := ghcr.io/vthunder/browserid-ng

.PHONY: build test audit fuzz-smoke fuzz-smoke-install push watch release deploy publish-status \
        release-broker release-www release-wallet release-mcp-demo \
        release-python-mcp-demo release-guestbook

build:
	cargo build --workspace

test:
	cargo test --workspace

# Same script and ignore lists as .github/workflows/supply-chain.yml.
audit:
	scripts/supply-chain-audit.sh

# Needs nightly + cargo-fuzz; standalone workspace under fuzz/ (not built by
# `make build`/CI/Docker). On the dev box: ssh localtest 'make fuzz-smoke'.
fuzz-smoke:
	scripts/fuzz-smoke.sh

# Dev-box only (audit 2026-11 Q29): weekly fuzz-smoke via launchd, Sundays
# 13:00, through `ssh localtest`, log /tmp/fuzz-smoke.log. Re-run after
# editing scripts/launchd/org.sandmill.fuzz-smoke.plist. Check with
# `launchctl list | grep fuzz` (from a login/ssh shell; a sandboxed shell
# lists only its own session, use `launchctl print gui/$$(id -u)/...`);
# kick one off now with
# `launchctl kickstart gui/$$(id -u)/org.sandmill.fuzz-smoke`.
FUZZ_PLIST = org.sandmill.fuzz-smoke.plist
fuzz-smoke-install:
	cp scripts/launchd/$(FUZZ_PLIST) $(HOME)/Library/LaunchAgents/$(FUZZ_PLIST)
	-launchctl bootout gui/$$(id -u)/org.sandmill.fuzz-smoke 2>/dev/null
	launchctl bootstrap gui/$$(id -u) $(HOME)/Library/LaunchAgents/$(FUZZ_PLIST)
	launchctl print gui/$$(id -u)/org.sandmill.fuzz-smoke | head -3

# Publish-state oracle for the SDK packages: local vs registry version, plus a
# content diff when versions match (catches "changed code, same version").
publish-status:
	node scripts/publish-status.mjs

push:
	git push origin HEAD

# gh's --commit filter needs the FULL sha — a short sha silently matches nothing.
watch:
	@echo "Watching CI for $(SHA)…"
	@# Runs take a few seconds to register after a push — wait for them to
	@# APPEAR before waiting for them to finish, or this exits instantly.
	@until gh run list --commit $(SHA) --json status -q '.[].status' | grep -q .; do sleep 5; done
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

deploy: push watch
