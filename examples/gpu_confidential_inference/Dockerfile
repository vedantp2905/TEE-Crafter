# GPU-capable image for tee-crafter deploy on gpu-cc-* (linux/amd64).
# Local build on Apple Silicon: Docker still gets --platform linux/amd64 from the CLI.

# torch 2.5.1 carried CVE-2025-32434, a CRITICAL with an upstream fix in 2.6.0,
# and TEE-Crafter's vulnerability gate blocks any fixable CRITICAL
# (flow_container: VLN-002).  2.6.0 is the *lowest* base that clears it, which is
# why this is not on the newest tag: it keeps the CUDA runtime at 12.4, the
# version the baked GPU CC images' 550.x driver has actually been run against.
# Two MEDIUM torch findings remain (CVE-2025-2999 needs 2.9.1, CVE-2025-3730
# needs 2.8.0); the gate's MEDIUM threshold is 25, so they do not block.
FROM pytorch/pytorch:2.6.0-cuda12.4-cudnn9-runtime

# Apply the distro's security updates.  The base image is Ubuntu 22.04 and its
# package set lags the archive by however long since it was published, which on
# a scan of the 2.5.1 base showed up as 2,723 fixable OS findings — 2,565 of them
# in `linux-libc-dev` alone.  Same step, same reason, as
# examples/fintech_fraud_detection/Dockerfile.
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# HTTP stack for container-mode proxy (POST / with JSON)
RUN pip install --no-cache-dir \
    "fastapi>=0.115,<1" \
    "uvicorn[standard]>=0.30,<1"

COPY requirements.txt handler.py server.py ./

# Align torchvision with pinned torch (base image already ships matching torch)
RUN pip install --no-cache-dir -r requirements.txt

# Python-side security floors, applied *after* requirements.txt so nothing in it
# can pull one of these back down.  Every floor here is the fixed version Trivy
# named for a finding the gate counts as blocking; none is a precaution.  The
# packages come from the base image's own environment (torch, torchvision and
# conda pull them in), not from this app's dependency set, which is why they are
# upgraded rather than pinned in requirements.txt.
RUN pip install --no-cache-dir --upgrade \
    "pip>=26.1.2" \
    "setuptools>=83.0.0" \
    "wheel>=0.46.2" \
    "pillow>=12.3.0" \
    "urllib3>=2.7.0" \
    "requests>=2.33.0" \
    "idna>=3.15" \
    "Jinja2>=3.1.6" \
    "filelock>=3.20.3" \
    "h2>=4.4.1" \
    "Brotli>=1.2.0" \
    "soupsieve>=2.8.4"

EXPOSE 8080

ENV NVIDIA_VISIBLE_DEVICES=all
ENV NVIDIA_DRIVER_CAPABILITIES=compute,utility

CMD ["python", "-u", "server.py"]
