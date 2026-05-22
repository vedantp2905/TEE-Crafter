# --- SB-AWS: UEFI Secure Boot enrollment (in-VM, baked into AMI NVRAM) ---
#
# Injected into setup_nitro.sh and setup_snp_aws.sh when bake-ami is invoked
# with --enable-secure-boot.  Empirically validated on:
#   - Ubuntu 22.04 Jammy on m6a.xlarge (AMD SEV-SNP enabled)
#   - Amazon Linux 2023 on c6a.xlarge (Nitro Enclaves enabled)
# both with NitroTPM and UEFI boot mode.  See docs/security.md §"AWS Secure
# Boot" for the threat model and the bake/launch flow.
#
# Strategy per distro:
#   - AL2023: enroll AWS-shipped Platform Key + KEK + db from
#             /usr/share/amazon-linux-sb-keys/{PK,KEK,db}.esl.auth, signed by
#             the Amazon Linux Secure Boot Signing CA which also signs
#             /boot/efi/EFI/BOOT/BOOTX64.EFI (grub) and the kernel image.
#   - Ubuntu 22.04: generate a tee-crafter PK + KEK, then enroll a db that
#             contains both (a) Microsoft Corporation UEFI CA 2011 extracted
#             from /usr/lib/shim/shimx64.efi.signed (so the existing
#             shim->grub->kernel chain continues to verify), and (b) a
#             self-signed tee-crafter db cert so operators can sign their own
#             EFI binaries / shim MOK extensions later.
#
# The enrollment is done in Setup Mode via efi-updatevar; the next boot of
# any instance launched from the resulting AMI starts with Secure Boot
# enforcing because aws ec2 create-image captures the UEFI NVRAM into the
# AMI's UefiData field.  Failure to enroll is fatal — the bake aborts so
# the operator never gets a "secure_boot=enabled"-tagged AMI that isn't.
echo ""
echo "=== TEE-Crafter: enrolling UEFI Secure Boot keys (AWS) ==="

. /etc/os-release || { echo "FATAL [SB-AWS]: /etc/os-release missing"; exit 1; }

if [ "$ID" = "amzn" ] || [ "$ID_LIKE" = "amzn" ]; then
    # --- Amazon Linux 2023 path ---
    dnf install -y -q efitools mokutil efivar-libs openssl sbsigntools amazon-linux-sb-keys >/dev/null 2>&1 || true
    if [ ! -d /usr/share/amazon-linux-sb-keys ]; then
        echo "FATAL [SB-AWS]: amazon-linux-sb-keys package missing on AL2023" >&2
        exit 1
    fi
    cd /usr/share/amazon-linux-sb-keys
    # Sanity: the binaries we're about to trust must verify against the
    # bundled signing-CA.crt.  If not, the AMI's grub/kernel won't load
    # under enforcing SB and the deploy will brick.
    if ! sbverify --cert signing-CA.crt /boot/efi/EFI/BOOT/BOOTX64.EFI >/dev/null 2>&1; then
        echo "FATAL [SB-AWS]: /boot/efi/EFI/BOOT/BOOTX64.EFI does NOT verify against amazon-linux signing-CA.crt — refusing to enroll" >&2
        exit 1
    fi
    KVER=$(uname -r)
    if [ -f "/boot/vmlinuz-${KVER}" ] && ! sbverify --cert signing-CA.crt "/boot/vmlinuz-${KVER}" >/dev/null 2>&1; then
        echo "FATAL [SB-AWS]: /boot/vmlinuz-${KVER} does NOT verify against amazon-linux signing-CA.crt — refusing to enroll" >&2
        exit 1
    fi
    for VAR in db KEK PK; do
        if [ ! -f "${VAR}.esl.auth" ]; then
            echo "FATAL [SB-AWS]: ${VAR}.esl.auth missing in amazon-linux-sb-keys" >&2
            exit 1
        fi
        chattr -i /sys/firmware/efi/efivars/${VAR}-* 2>/dev/null || true
        echo "[SB-AWS] enrolling ${VAR}"
        if ! efi-updatevar -f "${VAR}.esl.auth" "$VAR"; then
            echo "FATAL [SB-AWS]: efi-updatevar failed for ${VAR}" >&2
            exit 1
        fi
    done
    # dbx is intentionally optional — AL2023 ships an empty dbx.esl.auth
    # whose write may fail with EIO on first install; that's harmless.
    chattr -i /sys/firmware/efi/efivars/dbx-* 2>/dev/null || true
    efi-updatevar -f dbx.esl.auth dbx 2>/dev/null || true

elif [ "$ID" = "ubuntu" ]; then
    # --- Ubuntu 22.04 path ---
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y -qq sbsigntool efitools efivar mokutil openssl osslsigncode uuid-runtime >/dev/null
    SHIM=""
    for cand in /usr/lib/shim/shimx64.efi.signed /usr/lib/shim/shimx64.efi.signed.previous /boot/efi/EFI/BOOT/BOOTX64.EFI; do
        [ -f "$cand" ] && SHIM="$cand" && break
    done
    if [ -z "$SHIM" ]; then
        echo "FATAL [SB-AWS]: no shimx64.efi.signed* binary found on this Ubuntu image" >&2
        exit 1
    fi
    WORK=$(mktemp -d)
    cd "$WORK"
    osslsigncode extract-signature -pem -in "$SHIM" -out sig.pem >/dev/null 2>&1 || {
        echo "FATAL [SB-AWS]: osslsigncode failed to extract sig from $SHIM" >&2
        exit 1
    }
    openssl pkcs7 -in sig.pem -print_certs -out chain.pem 2>/dev/null || {
        echo "FATAL [SB-AWS]: openssl pkcs7 parse failed" >&2
        exit 1
    }
    csplit -z -f cert- -b '%02d.pem' chain.pem '/-----BEGIN CERTIFICATE-----/' '{*}' >/dev/null 2>&1
    MSCA=""
    for f in cert-*.pem; do
        if openssl x509 -in "$f" -noout -subject 2>/dev/null \
                | grep -q "Microsoft Corporation UEFI CA 2011"; then
            MSCA="$f"; break
        fi
    done
    if [ -z "$MSCA" ]; then
        echo "FATAL [SB-AWS]: 'Microsoft Corporation UEFI CA 2011' cert not present in $SHIM signature chain" >&2
        exit 1
    fi
    echo "[SB-AWS] Found MS UEFI CA 2011 cert in $SHIM → $MSCA"

    GUID=$(uuidgen)
    for KEY in PK KEK; do
        openssl req -newkey rsa:2048 -nodes \
            -keyout "$KEY.key" -new -x509 -sha256 -days 3650 \
            -subj "/CN=TEE-Crafter ${KEY}/" -out "$KEY.crt" 2>/dev/null
        cert-to-efi-sig-list -g "$GUID" "$KEY.crt" "$KEY.esl"
    done
    cert-to-efi-sig-list -g "$GUID" "$MSCA" db_ms.esl
    openssl req -newkey rsa:2048 -nodes -keyout db.key -new -x509 -sha256 -days 3650 \
        -subj "/CN=TEE-Crafter db/" -out db.crt 2>/dev/null
    cert-to-efi-sig-list -g "$GUID" db.crt db_self.esl
    cat db_ms.esl db_self.esl > db.esl
    sign-efi-sig-list -k PK.key  -c PK.crt  PK  PK.esl  PK.auth
    sign-efi-sig-list -k PK.key  -c PK.crt  KEK KEK.esl KEK.auth
    sign-efi-sig-list -k KEK.key -c KEK.crt db  db.esl  db.auth

    chattr -i /sys/firmware/efi/efivars/db-*  2>/dev/null || true
    chattr -i /sys/firmware/efi/efivars/KEK-* 2>/dev/null || true
    chattr -i /sys/firmware/efi/efivars/PK-*  2>/dev/null || true

    echo "[SB-AWS] enrolling db (MS UEFI CA 2011 + tee-crafter self-signed db)"
    efi-updatevar -f db.auth db || { echo "FATAL [SB-AWS]: db enrollment failed" >&2; exit 1; }
    echo "[SB-AWS] enrolling KEK"
    efi-updatevar -f KEK.auth KEK || { echo "FATAL [SB-AWS]: KEK enrollment failed" >&2; exit 1; }
    echo "[SB-AWS] enrolling PK (exits Setup Mode)"
    efi-updatevar -f PK.auth PK || { echo "FATAL [SB-AWS]: PK enrollment failed" >&2; exit 1; }

    # Persist our PK/KEK/db key material on the AMI under a tightly-permed
    # path so operators can re-sign EFI binaries later WITHOUT having to
    # re-bake.  Note: PK/KEK private keys are sensitive — they control
    # which firmware policy can be replaced; operators should rotate them
    # via `bake-ami --enable-secure-boot` and not check them into source.
    install -d -m 0700 /etc/tee_crafter/sb-keys
    install -m 0600 PK.key PK.crt KEK.key KEK.crt db.key db.crt /etc/tee_crafter/sb-keys/
    chmod 0700 /etc/tee_crafter/sb-keys

    cd /
    rm -rf "$WORK"
else
    echo "FATAL [SB-AWS]: unsupported distro for Secure Boot enrollment: ID=$ID" >&2
    exit 1
fi

# --- Verify enrollment landed in firmware NVRAM ---
SB_RAW=$(od -An -tu1 /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | awk '{print $5}' | head -1)
SM_RAW=$(od -An -tu1 /sys/firmware/efi/efivars/SetupMode-*  2>/dev/null | awk '{print $5}' | head -1)
echo "[SB-AWS] firmware bytes: SecureBoot=$SB_RAW SetupMode=$SM_RAW"
SB_STATE=$(mokutil --sb-state 2>&1 || true)
echo "[SB-AWS] mokutil: $SB_STATE"
case "$SB_STATE" in
    *"SecureBoot enabled"*)
        echo "[SB-AWS] ✓ Secure Boot ENABLED in UEFI NVRAM — AMI snapshot will inherit this state"
        mkdir -p /etc/tee_crafter
        {
            echo "secure_boot=enabled"
            echo "enrolled_at=$(date -u +%Y%m%dT%H%M%SZ)"
            echo "distro_id=${ID}"
            [ -n "${MSCA:-}" ] && echo "db_includes=MicrosoftCorporationUEFICA2011,tee-crafter-self-signed"
            [ -d /usr/share/amazon-linux-sb-keys ] && echo "db_includes=amazon-linux-sb-keys"
        } > /etc/tee_crafter/secure_boot
        chmod 0644 /etc/tee_crafter/secure_boot
        ;;
    *)
        echo "FATAL [SB-AWS]: Secure Boot NOT enabled after enrollment — refusing to produce a misleading AMI" >&2
        exit 1
        ;;
esac
echo "=== TEE-Crafter: Secure Boot enrollment complete ==="
