# --- Microsoft guest attestation (azguestattestation1) --------------------
#
# Shared by every Azure confidential-VM bake: tdx-azure, snp-azure and
# gpu-cc-azure. Inlined by cli/loaders.py at its placeholder rather than
# uploaded as a second file, because this runs on a freshly provisioned VM with
# nothing to copy from. (The placeholder token is deliberately not spelled here:
# a test greps rendered scripts for unresolved placeholders.)
#
# Two binaries come out of it, and the three platforms need them for different
# reasons:
#
#   AttestationClient  -- mints an MAA token from vTPM evidence.
#     Load-bearing on tdx-azure and nowhere else. An Azure paravisor TD gives
#     the guest a *raw* TDREPORT at offset 32 of NV 0x01400001 (1024 bytes)
#     whose REPORTMACSTRUCT only the TDX module and the Quoting Enclave can
#     verify, and no QE is reachable from under the paravisor. The guest
#     therefore cannot produce a DCAP quote itself -- but one does get produced:
#     this library POSTs the TDREPORT to IMDS http://169.254.169.254/acc/tdquote
#     and the host returns an Intel DCAP TD quote, which it then submits to
#     /attest/AzureGuest?api-version=2020-10-01. Verified against the shipped
#     artifact rather than the docs: libazguestattestation 1.1.2 exports
#     ImdsClient::GetTdxQuote, HclReportParser::ExtractTdxReportAndRuntimeData-
#     FromHclReport and IsolationInfo::CreateTdxEvidence, and the string
#     "/acc/tdquote" is in the binary. So the TD needs IMDS reachability, not
#     just MAA reachability.
#     snp-azure and gpu-cc-azure do not need it: they read a real SEV-SNP
#     ATTESTATION_REPORT and the client verifies it against AMD's root.
#
#   AzureAttestSKR    -- Secure Key Release, needed on ALL THREE.
#     Key Vault wraps a released key to the KEK named in the attestation token's
#     top-level `x-ms-runtime.keys`, and on a CVM that key is
#     `TpmEphemeralEncryptionKey` -- a paravisor key whose private half is sealed
#     to the vTPM. No Python process can unwrap it, so `--byok azure-skr`
#     delegates release *and* unwrap to this tool, which holds the sealed half.
#     Installing it only in the tdx-azure bake is what left snp-azure and
#     gpu-cc-azure with no working BYOK path at all.
#
# Built at bake time on purpose: compiling on first boot would put a toolchain
# and a network fetch inside the measured runtime path, and a bake that cannot
# produce these binaries must fail loudly here rather than on a live VM.
# https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-virtual-machines-design
# https://learn.microsoft.com/en-us/azure/confidential-computing/skr-flow-confidential-vm-sev-snp
#
# Idempotent, and that is load-bearing rather than tidy. This script runs twice:
# once at bake (egress open) and again on every deploy (egress locked down to
# the VNet by default, TF_VAR_allow_setup_egress=false). A second run that tried
# to re-download would fail the deploy on a VM that is already paid for -- so if
# the bake did its job, this whole block is skipped.
#
# GA_PURPOSE: what breaks on *this* platform without the binaries. Set by the
# including script before the placeholder; the fallback keeps the fragment
# runnable on its own.
GA_PURPOSE="${GA_PURPOSE:-attestation and secure key release}"
GA_CLIENT=/usr/local/bin/AttestationClient
GA_SKR=/usr/local/bin/AzureAttestSKR

if [ -x "$GA_CLIENT" ] && [ -x "$GA_SKR" ]; then
    echo "--- Microsoft guest attestation: already baked, skipping ---"
    echo "  $GA_CLIENT"
    echo "  $GA_SKR"
else
echo "--- Microsoft guest attestation library ---"
apt-get install -y \
    libssl-dev libcurl4-openssl-dev libjsoncpp-dev libboost-all-dev \
    nlohmann-json3-dev cmake git

GA_DEB_INDEX="https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/"
GA_TMP="$(mktemp -d)"

# Resolve the newest package from the index rather than pinning a version that
# silently 404s once Microsoft rotates it. Recorded in the bake log so the
# image's provenance names the exact .deb that went in.
GA_DEB="$(curl -fsSL "$GA_DEB_INDEX" \
    | grep -oE 'azguestattestation1_[0-9.]+_amd64\.deb' \
    | sort -V | tail -1 || true)"
if [ -z "$GA_DEB" ]; then
    echo "FATAL: could not resolve an azguestattestation1 .deb from $GA_DEB_INDEX"
    echo "  Refusing to bake an image without it: this VM needs it for"
    echo "  $GA_PURPOSE."
    exit 1
fi
echo "  Package: $GA_DEB"
curl -fsSL -o "$GA_TMP/$GA_DEB" "${GA_DEB_INDEX}${GA_DEB}"
dpkg -i "$GA_TMP/$GA_DEB"

# AttestationClient (-o token) and AzureAttestSKR (secure key release) come
# from the same Microsoft repo and link the library above.
git clone --depth 1 --recursive \
    https://github.com/Azure/confidential-computing-cvm-guest-attestation \
    "$GA_TMP/ga-src"

# Turn the sample app's logger back on, redirected to stderr.
#
# Upstream's Logger::Log builds the message and then throws it away: the only
# print is commented out, with the note "uncomment the below statement and
# rebuild if details debug logs are needed". The consequence is that
# AttestationClient reports MAA's verdict and nothing about how it got there --
# so a failure inside the library is indistinguishable from any other failure.
#
# That is not a theoretical loss. The library's TDX path reads the TDREPORT from
# the vTPM, then POSTs it to IMDS /acc/tdquote to have the host turn it into an
# Intel DCAP quote, and only then talks to MAA. It has distinct messages for
# each step -- "Failed to retrieve the TD quote from IMDS", "Empty Quote
# received from IMDS TD Quote Endpoint", "Failed to parse TD quote response" --
# and with the logger muted, all three present identically as an MAA rejection.
# A 2026-08-23 run burned a VM learning only `InvalidParameter`.
#
# stderr, not stdout, and that is load-bearing: our contract with this binary is
# that stdout is the bare JWT and nothing else, so a diagnostic on stdout would
# be read as a malformed token.
_LOGGER_CPP="$GA_TMP/ga-src/cvm-attestation-sample-app/Logger.cpp"
if [ -f "$_LOGGER_CPP" ]; then
    sed -i 's|^[[:space:]]*//[[:space:]]*printf("Level: |    fprintf(stderr, "Level: |' \
        "$_LOGGER_CPP"
    if grep -q 'fprintf(stderr, "Level: ' "$_LOGGER_CPP"; then
        echo "  Logger::Log enabled (stderr)"
    else
        # Non-fatal: a silent client still attests. Say so, because the next
        # person debugging a blind failure needs to know why it is blind.
        echo "  WARNING: could not enable Logger::Log -- upstream changed the"
        echo "           commented printf. AttestationClient will not explain"
        echo "           which internal step failed."
    fi
fi

build_ga_tool() {
    _dir="$1"; _artifact="$2"; _install_as="$3"
    if [ ! -d "$GA_TMP/ga-src/$_dir" ]; then
        echo "FATAL: $_dir is not present in the guest-attestation checkout"
        exit 1
    fi
    ( cd "$GA_TMP/ga-src/$_dir" \
      && mkdir -p build && cd build \
      && cmake .. -DCMAKE_BUILD_TYPE=Release \
      && make -j"$(nproc)" )
    _built="$(find "$GA_TMP/ga-src/$_dir/build" -maxdepth 2 -type f \
                -name "$_artifact" -perm -u+x | head -1)"
    if [ -z "$_built" ]; then
        echo "FATAL: built $_dir but produced no $_artifact"
        exit 1
    fi
    install -m 0755 "$_built" "/usr/local/bin/$_install_as"
    echo "  Installed /usr/local/bin/$_install_as"
}

build_ga_tool cvm-attestation-sample-app AttestationClient AttestationClient
build_ga_tool cvm-securekey-release-app AzureAttestSKR AzureAttestSKR

rm -rf "$GA_TMP"
fi

# Fail now rather than at verify time on a running VM. Checked outside the
# skip-branch so a deploy onto a stale image (baked before this block existed)
# stops here with the reason, instead of booting a VM that cannot do the job.
for _bin in "$GA_CLIENT" "$GA_SKR"; do
    if [ ! -x "$_bin" ]; then
        echo "FATAL: $_bin is missing."
        echo "  This VM needs it for $GA_PURPOSE."
        echo "  If this is a deploy onto a pre-baked image, that image predates"
        echo "  the guest-attestation step -- re-bake it (the bake runs with"
        echo "  egress open; the deploy does not, by design)."
        exit 1
    fi
done
echo "  azguestattestation1 + AttestationClient + AzureAttestSKR: present"

# Deliberately NOT here: granting the service account vTPM access. Both binaries
# need /dev/tpmrm0 (root:tss 0660), but this fragment is inlined near the top of
# each setup script -- before the unprivileged enclave user is created -- so a
# `usermod -aG tss` here would silently do nothing on a first bake. Each
# platform script does it after user creation instead; grep for `tss`.
