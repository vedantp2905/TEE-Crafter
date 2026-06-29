# `tee-crafter` CLI (core product)

This package is the TEE-Crafter command-line tool and its core library: it
builds an operator's **Dockerfile / OCI image**, deploys it into hardware TEEs
on ten backends (AWS Nitro, Intel SGX/TDX, AMD SEV-SNP, NVIDIA Confidential
GPU), and produces attestation + compliance evidence.

It is published as the Python package `tee_crafter` (console script
`tee-crafter`) and is also installed verbatim into the hosted-SaaS **worker**
image (`apps/worker/`), which runs the exact same CLI a human would.

## Layout

```
apps/cli/
├── src/tee_crafter/     # the package (cli, core, llm/iac, templates, scripts, resources, certs)
├── tests/               # unit + integration tests
├── byok-sandbox/        # sample BYOK configs used as test fixtures
├── siem-sandbox/        # sample SIEM configs
├── pyproject.toml       # package metadata + console script + [dev] extra
├── requirements.txt     # pinned runtime/dev mirror of pyproject deps
└── Dockerfile           # lean CLI image (build context = this directory)
```

## Develop

From the repository root (a monorepo — see the root `README.md`):

```bash
make install              # creates venv + installs apps/cli with [dev]
make docker-build-cli     # builds the lean CLI image (context apps/cli/)
make test-unit            # runs apps/cli/tests
```

Or directly:

```bash
./venv/bin/pip install -e "apps/cli[dev]"
./venv/bin/python -m pytest apps/cli/tests -q
```

The full user guide, per-platform flow docs, and CLI reference live in the
repository-root [`docs/`](../../docs).
