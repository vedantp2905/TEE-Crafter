FROM python:3.12-slim

WORKDIR /app

# Patch the base image before installing anything.  Without this the image ships
# Debian's `util-linux` 2.41-5, and Trivy reports 36 fixable HIGH findings across
# its nine binary packages (bsdutils, libblkid1, liblastlog2-2, libmount1,
# libsmartcols1, libuuid1, login, mount, util-linux) — the same four CVEs each,
# all fixed by 2.41.5-0+deb13u1.  That is enough to fail TEE-Crafter's
# vulnerability gate, which blocks on findings that *have* an upstream fix, so
# this example could not be deployed at all.  Found on 2026-08-22 when it was
# used as the batch workload for the Azure end-to-end runs.
RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Batch mode mounts the host's --input-dir read-only at /input, but it does not
# create /output — output capture works by `docker diff`-ing the container's own
# writable layer after it exits (see
# apps/cli/src/tee_crafter/resources/systemd/container.batch.service.template).
# So /output has to exist in the image, and anything written there is picked up.
RUN mkdir -p /output

# Batch: read data.json from /input and write results under /output
CMD ["sh", "-c", "python app.py < /input/data.json > /output/results.json"]
