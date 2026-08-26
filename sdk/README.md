# SDK packages

Each directory here is an independently published package (npm under the
`@browserid-ng` scope; `python-mcp-auth` publishes to PyPI as
`browserid-mcp-auth`). Note two directory names differ from their package
names — `js` publishes as `@browserid-ng/verify`, `python-mcp-auth` as
`browserid-mcp-auth` (bean 2nay tracks renaming them).

## Publishing

Publish state is a derived fact, never remembered:

```sh
make publish-status        # local vs registry version, content diff at equal versions
```

Statuses: `OK` (published, content matches), `NEEDS PUBLISH` (local version
ahead — publish it), `NEEDS BUMP` (content changed at an already-published
version — bump before anything else), `BEHIND` (registry is newer than the
repo).

**The convention: a PR that changes a package's shipped content must bump its
version.** CI enforces this — the drift gate in `sdk-tests.yml` fails on
`NEEDS BUMP`. Once merged to main, `publish.yml` publishes anything whose
version is ahead of the registry via OIDC trusted publishing (npm
`--provenance`; PyPI via `pypa/gh-action-pypi-publish`). So releasing is just:
bump, merge.

Manual fallback (before trusted publishing is configured, or offline):

```sh
cd sdk/<pkg> && npm publish --access public       # npm packages
cd sdk/python-mcp-auth && uv build && uv publish  # PyPI (needs a token)
```
