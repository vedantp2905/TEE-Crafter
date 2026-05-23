#!/usr/bin/env python3
"""Make GSC's Debian template work on Debian 13 (trixie).

GSC pins its own Dockerfile templates, and ``templates/debian/Dockerfile.compile
.template`` adds Intel's SGX apt repository the way it was done in 2018::

    RUN echo 'deb [arch=amd64] https://download.01.org/...' \\
        > /etc/apt/sources.list.d/intel-sgx.list \\
        && apt-key add /intel-sgx-deb.key

Two things are wrong with that on Debian 13, and only the first is obvious.

1. ``apt-key`` was removed in Debian 13.  The compile stage dies with
   ``apt-key: not found`` and exit 127.  Measured on 2026-08-22 in
   ``debian:13``; ``debian:11``, ``debian:12``, ``ubuntu:22.04`` and
   ``ubuntu:24.04`` all still ship it.

2. Fixing only that is not enough.  Debian 13 carries apt 3.0.3, which verifies
   repository signatures with ``sqv`` (Sequoia) rather than ``gpgv``, and Sequoia
   rejects Intel's signature outright::

       Sub-process /usr/bin/sqv returned an error code (1) ...
       Malformed MPI: leading bit is not set: expected bit 8 to be set in 110100
       E: The repository '... bionic InRelease' is not signed.

   The signature is not actually bad -- ``gpgv`` on the same ``InRelease`` and
   the same key reports ``Good signature from "CN=Intel(R) Software Development
   Products"``.  Sequoia is stricter about MPI encoding than the GnuPG that
   produced it.  So the repository needs ``gpgv``, which Debian 13 does not
   install by default (only ``sqv`` is present).

Why this matters here rather than being someone else's problem: ``sgx-azure`` is
batch-only, and three of the four shipped examples -- including
``fintech_fraud_detection``, the only batch-shaped one -- are built on
``python:3.12-slim``, which reports ``debian:13``.  Without this patch the
platform cannot graminize its own examples.

Why patch instead of the alternatives:

* *Wait for upstream.*  There is nothing to wait for.  GSC ``master`` still has
  the ``apt-key`` call, and the commit this repo pins (0b2ba93) **is** master's
  tip, so bumping the pin changes nothing.
* *Tell users to use an Ubuntu base.*  That is the status quo and it means
  rewriting our own examples.  It also only defers the problem: the ``apt-key``
  call sits in the **shared** template -- ``templates/ubuntu/Dockerfile.compile
  .template`` is a single Jinja ``extends`` of the debian one -- so Ubuntu
  breaks the day it drops ``apt-key`` too.  This patch fixes both at once.
* *Force ``Distro: ubuntu:22.04`` in GSC's config.yaml.*  Tempting, since it
  needs no patching, but it is wrong.  The compile stage is ``FROM <Distro>``
  while the *build* stage is ``FROM <app image>`` and runs its own distro
  ``install`` block inside it.  That block branches on
  ``distro[1] | int >= 12``, and Jinja's ``int`` filter cannot parse
  ``"22.04"`` so it falls back to 0 -- taking the pre-PEP-668 path that
  ``pip install``s into what is really a Debian 13 image with an
  externally-managed environment.  It trades a loud failure for a quiet one.
* *``[trusted=yes]``.*  Rejected outright: it would install Intel's SGX
  libraries with signature verification disabled, in a project whose entire
  purpose is verifiable execution.  The patch keeps verification -- it changes
  *which* verifier runs, not *whether* one runs.

The ``APT::Key::gpgvcommand`` override lands in the **compile** stage only.
That stage exists to build Gramine; GSC's build stage copies ``/gramine/`` out
of it and discards everything else, so the override never reaches the
graminized image being measured.

Not covered here: GSC passes ``-Ddcap=enabled`` to Gramine's meson only when the
distro is ``ubuntu:``, so a Debian-based build gets Gramine without the DCAP
*verifier* libraries.  That is fine for TEE-Crafter -- the enclave only
*generates* quotes, through ``/dev/attestation/quote`` (see
``templates/sgx/app_gramine.template.py::_generate_dcap_quote``), which is a PAL
pseudo-file gated by ``sgx.remote_attestation`` in the manifest and not by that
meson option.  Nothing in this repository links ``ra_tls_verify_dcap`` or
``libsecret_prov_verify_dcap``; quote verification is pure Python, client-side,
in ``templates/sgx/client.template.py::verify_dcap_quote_signature``.

Usage: ``patch_gsc_debian_template.py /opt/gsc``

Exit 0 if the patch was applied or was already present, 1 otherwise.  Idempotent
on purpose, because the SGX VM image is baked once and re-run on boot.

NOTE FOR EDITORS: this file is injected verbatim into ``setup_sgx.sh``, which one
caller renders with ``str.format()``.  It must therefore contain no brace
characters anywhere -- including in this docstring -- so no f-strings and no dict
or set literals; use ``%`` formatting.
``tests/cli/test_gsc_debian_template_patch.py`` enforces this.
"""
import os
import sys

#: Path of the patched template, relative to the GSC checkout root.
TEMPLATE_RELPATH = os.path.join(
    "templates", "debian", "Dockerfile.compile.template")

#: The exact three lines shipped by GSC commit 0b2ba93.  Matched literally
#: rather than by regex: if upstream reformats this block the patch must fail
#: loudly at bake time, not silently half-apply at deploy time.
OLD_BLOCK = "\n".join([
    "RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' \\",
    "    > /etc/apt/sources.list.d/intel-sgx.list \\",
    "    && apt-key add /intel-sgx-deb.key",
])

#: apt reads an ASCII-armored key directly when the path ends in ``.asc``, and
#: ``keys/intel-sgx-deb.key`` is armored (it opens with "BEGIN PGP PUBLIC KEY
#: BLOCK"), so no ``gpg --dearmor`` and no ``gnupg`` package is needed -- which
#: is a simplification over the code being replaced, since ``apt-key`` needed
#: ``gpg`` present and GSC's package list only pulled it in transitively.
NEW_BLOCK = "\n".join([
    "RUN env DEBIAN_FRONTEND=noninteractive apt-get update \\",
    "    && env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gpgv \\",
    "    && mkdir -p /etc/apt/keyrings \\",
    "    && cp /intel-sgx-deb.key /etc/apt/keyrings/intel-sgx.asc \\",
    "    && echo 'APT::Key::gpgvcommand \"/usr/bin/gpgv\";'"
    " > /etc/apt/apt.conf.d/99-tee-crafter-intel-sgx-gpgv \\",
    "    && echo 'deb [arch=amd64 signed-by=/etc/apt/keyrings/intel-sgx.asc]"
    " https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' \\",
    "       > /etc/apt/sources.list.d/intel-sgx.list",
])

#: Cheap post-condition an operator (or the bake script) can grep for.
SENTINEL = "signed-by=/etc/apt/keyrings/intel-sgx.asc"


def patch_text(text):
    """Return (new_text, status) for *text*.

    status is "applied", "already" or an error string.  Kept separate from I/O
    so it can be tested against the real upstream template without a
    filesystem.
    """
    if SENTINEL in text:
        return text, "already"
    found = text.count(OLD_BLOCK)
    if found != 1:
        return text, (
            "expected exactly 1 occurrence of GSC's apt-key block, found %d "
            "-- the pinned GSC template has changed and this patch needs "
            "rewriting" % found)
    return text.replace(OLD_BLOCK, NEW_BLOCK), "applied"


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: patch_gsc_debian_template.py <gsc-checkout>\n")
        return 2
    path = os.path.join(argv[1], TEMPLATE_RELPATH)
    if not os.path.isfile(path):
        sys.stderr.write("GSC template not found: %s\n" % path)
        return 1
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    new_text, status = patch_text(text)
    if status == "already":
        sys.stdout.write("GSC debian template already patched for Debian 13\n")
        return 0
    if status != "applied":
        sys.stderr.write("GSC debian template patch failed: %s\n" % status)
        return 1
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(new_text)
    sys.stdout.write("GSC debian template patched for Debian 13 "
                     "(apt-key -> signed-by keyring + gpgv)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
