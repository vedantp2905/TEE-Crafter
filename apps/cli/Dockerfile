# TEE-Crafter CLI image (lean): run the full TEE deploy toolchain
# (Nitro + SGX + SNP + TDX + GPU CC) with only Docker installed on the
# host.  Usage: tee-crafter deploy --source ./examples/docker_flask_api ...
#
# Bundles: Python 3.12, tee-crafter, Terraform, AWS CLI, SSM plugin, Azure CLI,
# Google Cloud CLI, Trivy, Gramine + GSC (amd64-only SGX signing/graminizing),
# Docker CLI + Buildx.
#
# This image intentionally does **not** ship the Node/Go/JDK/.NET
# toolchains.  Under the unified execution model (plan 00) any language
# the user needs ships inside their own Dockerfile / OCI image; the CLI
# builds and runs that image as-is.
#
# Native build:    docker buildx build --load -t tee-crafter -f apps/cli/Dockerfile apps/cli
# Multi-arch push: docker buildx build --platform linux/amd64,linux/arm64 -t user/tee-crafter:latest -f apps/cli/Dockerfile --push apps/cli
# TARGETARCH is set automatically by Docker BuildKit (amd64, arm64).

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV TEE_CRAFTER_IN_DOCKER=1

# BuildKit sets TARGETARCH (amd64, arm64)
ARG TARGETARCH

# --- System packages ---
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    software-properties-common \
    unzip \
    git \
    openssh-client \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# --- Python 3.12 ---
# distutils was removed in 3.12; setuptools (installed via pip) replaces it.
RUN add-apt-repository -y ppa:deadsnakes/ppa \
    && apt-get update -y \
    && apt-get install -y --no-install-recommends \
        python3.12 \
        python3.12-venv \
        python3.12-dev \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12 \
    && python3.12 -m pip install --no-cache-dir --upgrade pip setuptools wheel

# --- Terraform (arch-specific) ---
# 1.15.x is what these templates are actually planned/applied with; the
# container had drifted six minor versions behind the host, so the CLI was
# validating with a different Terraform than anyone testing by hand.
ARG TF_VERSION=1.15.9
RUN ARCH=$(echo $TARGETARCH | sed 's/amd64/amd64/;s/arm64/arm64/') \
    && curl -fsSL "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_${ARCH}.zip" -o /tmp/terraform.zip \
    && unzip -o /tmp/terraform.zip -d /usr/local/bin \
    && rm /tmp/terraform.zip \
    && terraform version

# --- AWS CLI v2 (arch-specific) ---
RUN ARCH=$(echo $TARGETARCH | sed 's/amd64/x86_64/;s/arm64/aarch64/') \
    && curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o /tmp/awscliv2.zip \
    && unzip -o /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install -i /usr/local/aws-cli -b /usr/local/bin \
    && rm -rf /tmp/awscliv2.zip /tmp/aws \
    && aws --version

# --- AWS Session Manager Plugin (arch-specific) ---
RUN SM_ARCH=$(echo $TARGETARCH | sed 's/amd64/64bit/;s/arm64/arm64/') \
    && curl -fsSL "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_${SM_ARCH}/session-manager-plugin.deb" -o /tmp/session-manager-plugin.deb \
    && dpkg -i /tmp/session-manager-plugin.deb \
    && rm /tmp/session-manager-plugin.deb \
    && session-manager-plugin --version 2>/dev/null || true

# --- Azure CLI + Bastion extension ---
RUN curl -fsSL https://aka.ms/InstallAzureCLIDeb | bash \
    && az version \
    && az extension add --name bastion --upgrade -y 2>/dev/null || true \
    && az extension add --name ssh --upgrade -y 2>/dev/null || true


# --- Google Cloud CLI (gcloud) ---
# Needed for GCP SNP/TDX bake & deploy flows.
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" \
      > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
      | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && apt-get update -y \
    && apt-get install -y --no-install-recommends google-cloud-cli \
    && rm -rf /var/lib/apt/lists/* \
    && gcloud --version

# --- Trivy (vulnerability scanner for compliance evidence) ---
RUN apt-get update -y \
    && apt-get install -y --no-install-recommends wget apt-transport-https lsb-release \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
      | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
      > /etc/apt/sources.list.d/trivy.list \
    && apt-get update -y \
    && apt-get install -y --no-install-recommends trivy \
    && rm -rf /var/lib/apt/lists/* \
    && trivy --version

# --- Gramine (for local SGX manifest signing, amd64 only) ---
# Gramine only publishes amd64 packages. On arm64 (Apple Silicon) the SGX
# signing tools are unavailable; SGX deploy still works because signing
# happens on the remote Azure VM, not in this CLI container.
RUN if [ "$TARGETARCH" = "amd64" ]; then \
      curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg \
          https://packages.gramineproject.io/gramine-keyring.gpg \
      && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] https://packages.gramineproject.io/ jammy main" \
          > /etc/apt/sources.list.d/gramine.list \
      && apt-get update -y \
      && apt-get install -y --no-install-recommends gramine \
      && rm -rf /var/lib/apt/lists/* \
      && sed -i '1s|#!/usr/bin/python3|#!/usr/bin/python3.12|' \
          /usr/bin/gramine-sgx-sign \
          /usr/bin/gramine-manifest \
          /usr/bin/gramine-sgx-gen-private-key \
      && python3.12 -m pip install --no-cache-dir \
          click tomli tomli-w cryptography \
      && python3.12 -c "from graminelibos import sgx_sign; print('graminelibos OK')"; \
    else \
      echo "Skipping Gramine on $TARGETARCH (amd64-only package)"; \
    fi

# Gramine signing key (used when signing locally, amd64 only)
RUN if [ "$TARGETARCH" = "amd64" ]; then \
      mkdir -p /root/.config/gramine \
      && (gramine-sgx-gen-private-key -o /root/.config/gramine/enclave-key.pem 2>/dev/null \
          || openssl genrsa -3 3072 2>/dev/null > /root/.config/gramine/enclave-key.pem) \
      && chmod 600 /root/.config/gramine/enclave-key.pem 2>/dev/null || true; \
    fi

# --- Gramine Shielded Containers (GSC), amd64 only ---
# `tee-crafter deploy --tee-platform sgx-azure --batch` graminizes the user's
# image with `gsc build` + `gsc sign-image` before upload, and now *fails* when
# `gsc` is missing (see cli/commands/deploy/flow_container._graminize_sgx_batch)
# rather than silently shipping an image the SGX VM would run outside any
# enclave.  Without this stanza that path could never succeed from the CLI
# image.
#
# GSC ships as a repo, not a package (https://gramine.readthedocs.io/projects/gsc/):
#   * prerequisites for Ubuntu 22.04 are `docker.io python3 python3-pip` plus
#     the pip packages `docker jinja2 tomli tomli-w pyyaml`;
#   * `gsc` is invoked as `./gsc` from the checkout — gsc.py resolves both
#     `config.yaml` (argparse default) and `templates/` (jinja2
#     FileSystemLoader('templates/')) against the *current working directory*,
#     so the wrapper below must cd into /opt/gsc.  `cli/deployment/sgx/gsc.py`
#     therefore passes the signing key as an absolute path.
# The `#!/usr/bin/env python3` shebang would pick Ubuntu 22.04's python3.10,
# which does not have the pip deps installed below, so the wrapper calls
# python3.12 explicitly.
# Two separate pins, because they are two different things.  GSC_REF is the
# revision of the GSC *tooling* checked out here; GRAMINE_BRANCH is the Gramine
# release that `gsc build` installs *inside* the graminized image.  A single ARG
# used for both (which is what this was) forces them to move together and makes
# it impossible to take a GSC fix without also retargeting Gramine.
#
# GSC_REF is a commit SHA rather than the v1.9 tag on purpose.  `gsc build`
# reads the application image's OCI config, and at v1.9
# `extract_user_from_image_config` did `config['User']` unguarded.  Docker
# **omits** that key entirely when the Dockerfile sets no `USER` — verified on
# Docker 29.6.1, where the config of a freshly built image (and of the official
# `python:3.12-slim`) has keys `[ArgsEscaped, Cmd, Env, ExposedPorts,
# WorkingDir]` and no `User`.  So `gsc build` died with `KeyError: 'User'` for
# essentially every user image, and `sgx-azure --batch` could not complete for
# anyone; hit on 2026-08-22.
#
# Upstream fixed it in 0b2ba93 ("Use config.get() for safer access to
# configuration", 2026-04-01) -> `config.get('User') or 'root'`, which lands
# *after* v1.9 (2025-06-20) and is not in any tag yet.  Pinned to the SHA rather
# than to `master` so the build stays reproducible; revert to a tag once a
# release contains that commit.
#
# The alternative was to keep v1.9 and have TEE-Crafter pre-build a derived
# image with an explicit `USER` so GSC had a key to read.  Rejected: it works
# around a fixed upstream bug with an extra image layer on every SGX deploy, and
# it would have had to inject `USER root` to preserve behaviour — writing an
# anti-pattern into the artifact we then measure.
ARG GSC_REF=0b2ba9312c6120b5ebe2e55fb2bd7315b334361e
ARG GRAMINE_BRANCH=v1.9
# Copied ahead of the main `COPY src/ src/` below because the GSC checkout has to
# be patched in the same layer it is created.  GSC's debian template (which the
# ubuntu template merely extends) adds Intel's SGX apt repo with `apt-key`,
# removed in Debian 13, and Debian 13's apt verifies with sqv rather than gpgv.
# The script itself documents the measurements and the rejected alternatives.
COPY src/tee_crafter/scripts/sgx_azure/patch_gsc_debian_template.py \
     /opt/tee-crafter/patch_gsc_debian_template.py
RUN if [ "$TARGETARCH" = "amd64" ]; then \
      python3.12 -m pip install --no-cache-dir \
          docker jinja2 tomli tomli-w pyyaml \
      && git init -q /opt/gsc \
      && git -C /opt/gsc remote add origin https://github.com/gramineproject/gsc.git \
      && git -C /opt/gsc fetch -q --depth 1 origin "${GSC_REF}" \
      && git -C /opt/gsc checkout -q FETCH_HEAD \
      && python3.12 /opt/tee-crafter/patch_gsc_debian_template.py /opt/gsc \
      && sed -e "s|Branch:.*|Branch:     \"${GRAMINE_BRANCH}\"|" \
          /opt/gsc/config.yaml.template > /opt/gsc/config.yaml \
      && printf '#!/bin/sh\ncd /opt/gsc && exec python3.12 ./gsc "$@"\n' \
          > /usr/local/bin/gsc \
      && chmod +x /usr/local/bin/gsc \
      && gsc --help > /dev/null \
      && grep -q "config.get('User')" /opt/gsc/gsc.py \
      && grep -q "signed-by=/etc/apt/keyrings/intel-sgx.asc" \
          /opt/gsc/templates/debian/Dockerfile.compile.template \
      && echo "GSC pinned at ${GSC_REF} (Gramine ${GRAMINE_BRANCH})"; \
    else \
      echo "Skipping GSC on $TARGETARCH (SGX/Gramine is amd64-only)"; \
    fi

# --- Docker CLI (arch-specific; for EIF builds via host socket) ---
# Pinned in an ARG rather than inline so the version is greppable and
# overridable. The client talks to the *host* daemon over the mounted
# socket, so it should not trail the daemon by two majors.
ARG DOCKER_CLI_VERSION=29.7.2
RUN ARCH=$(echo $TARGETARCH | sed 's/amd64/x86_64/;s/arm64/aarch64/') \
    && curl -fsSL "https://download.docker.com/linux/static/stable/${ARCH}/docker-${DOCKER_CLI_VERSION}.tgz" -o /tmp/docker.tgz \
    && tar -xzf /tmp/docker.tgz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/ \
    && rm -rf /tmp/docker.tgz /tmp/docker \
    && docker version 2>/dev/null || true

# --- Docker Buildx plugin (required for cross-platform container builds) ---
ARG BUILDX_VERSION=v0.36.1
RUN case "$TARGETARCH" in \
      amd64) BXA=amd64 ;; \
      arm64) BXA=arm64 ;; \
      *) echo "Unsupported TARGETARCH for buildx: $TARGETARCH" && exit 1 ;; \
    esac \
    && mkdir -p /usr/local/lib/docker/cli-plugins \
    && curl -fsSL \
      "https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-${BXA}" \
      -o /usr/local/lib/docker/cli-plugins/docker-buildx \
    && chmod +x /usr/local/lib/docker/cli-plugins/docker-buildx \
    && docker buildx version

# --- TEE-Crafter ---
# Install the package OUTSIDE /workspace.  At runtime the CLI bind-mounts the
# user's working directory onto /workspace (`-v <cwd>:/workspace`), which would
# shadow a package installed there and break the editable `.pth` link
# (ModuleNotFoundError: No module named 'tee_crafter').  /opt/tee-crafter is
# never mounted over, so the install survives the re-exec.
WORKDIR /opt/tee-crafter

COPY pyproject.toml .
COPY requirements.txt .
COPY README.md .
COPY src/ src/

RUN pip install --no-cache-dir -e . \
    && tee-crafter --help

# Runtime workdir is the mounted user workspace so relative --source paths,
# .env, and .gcloud resolve against the caller's directory.
WORKDIR /workspace

# Default: run tee-crafter with passed args
ENTRYPOINT ["tee-crafter"]
CMD ["--help"]
