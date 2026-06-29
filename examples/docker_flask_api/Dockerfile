FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*

RUN python -m pip install --no-cache-dir --upgrade \
        pip "setuptools>=78.1.1" wheel && \
    pip install --no-cache-dir flask && \
    # Drop ensurepip's bundled bootstrap wheel: Trivy scans inside it and
    # attributes its contents to the image, and a single-purpose container never
    # bootstraps pip into a fresh venv.
    #
    # pip itself deliberately stays. TEE-Crafter's generated Dockerfile does
    # `FROM tee-crafter-user-app:<tag>` and then `RUN python -m pip install` to
    # layer the TEE runtime on top, so removing pip here breaks every deploy of
    # this example.  (Tried it; that is how the constraint was found.)
    #
    # Everything Trivy still reports on this image is a Debian CVE marked
    # `affected` or `fix_deferred`.  No base-image choice avoids those: python
    # 3.12-slim, 3.13-slim, 3.14-slim and 3.13-alpine were all scanned on
    # 2026-08-21 and every one carries the same unfixed util-linux set.  That is
    # why the vulnerability gate blocks on *fixable* findings -- see
    # core/security/vuln_scan.py for why an unsatisfiable gate is worse than a
    # narrower one.
    rm -rf /usr/local/lib/python3.12/ensurepip

COPY app.py .

EXPOSE 8080

CMD ["python", "app.py"]
