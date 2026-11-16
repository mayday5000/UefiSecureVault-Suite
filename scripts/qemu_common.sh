#!/usr/bin/env bash
# Shared QEMU/OVMF lab helpers for 02_run_qemu.sh and 12_run_patched_iso_qemu.sh.
# Sourced, not executed. Callers must set USV_ROOT before qemu_common_init.
# shellcheck shell=bash
# shellcheck disable=SC2034  # USV_* state is read by callers and later helpers

# Defaults (callers may override before qemu_common_init).
USV_MEM="${USV_MEM:-2048}"
USV_SMP="${USV_SMP:-1}"
USV_TPM="${USV_TPM:-1}"
USV_TPM_MODEL="${USV_TPM_MODEL:-crb}"
USV_SMM="${USV_SMM:-1}"
USV_VBS="${USV_VBS:-auto}"
USV_IOMMU="${USV_IOMMU:-0}"
USV_FW_PROTECTIONS="${USV_FW_PROTECTIONS:-0}"
USV_FW_CFG_ITEMS=()
USV_SMBIOS_PROFILE="${USV_SMBIOS_PROFILE:-}"
USV_ACPI_TABLES=()
USV_DEBUGCON="${USV_DEBUGCON:-0}"
USV_DEBUGCON_PATH="${USV_DEBUGCON_PATH:-}"
USV_GDB="${USV_GDB:-0}"
USV_GDB_PORT="${USV_GDB_PORT:-}"
USV_SEV="${USV_SEV:-0}"
USV_TDX="${USV_TDX:-0}"
USV_DRY_RUN="${USV_DRY_RUN:-0}"
USV_NOGRAPHIC="${USV_NOGRAPHIC:-0}"
USV_SERIAL_LOG="${USV_SERIAL_LOG:-}"
USV_RESET_VARS="${USV_RESET_VARS:-0}"
USV_EMPTY_KEYS="${USV_EMPTY_KEYS:-0}"
USV_QMP_PATH="${USV_QMP_PATH:-}"
USV_MONITOR_PATH="${USV_MONITOR_PATH:-}"
USV_VM_NAME="${USV_VM_NAME:-lab}"
USV_PARSE_SHIFT=1

USV_QEMU_BIN="${USV_QEMU_BIN:-qemu-system-x86_64}"
USV_QEMU_ARGS=()
USV_EXTRA_ARGS=()
USV_BOOT_ORDER=""
USV_EXTRA_DRIVES=()
USV_FEATURE_LINES=()
USV_CLEANUP_REGISTERED=0
USV_SWTPM_PID=""

qemu_common_usage() {
    cat <<'EOF'
Common QEMU lab flags (02_run_qemu.sh and 12_run_patched_iso_qemu.sh):
  --tpm / --no-tpm     TPM 2.0 via swtpm (default: on). --no-tpm disables it.
  --tpm-tis            Use tpm-tis instead of tpm-crb.
  --smm / --no-smm     System Management Mode (default: on).
  --vbs auto|on|off    VBS/HVCI-oriented CPU: KVM + nested HV enlightenments.
                       auto (default) enables them when /dev/kvm and nested
                       virtualization are available.
  --iommu              Intel IOMMU (intremap=on,caching-mode=on) with KVM only.
  --fw-protections     Documented OVMF fw_cfg: PcdSetNxForStack=yes and
                       EnableLegacyLoader=no (see EDK2 OvmfPkg/RUNTIME_CONFIG.md).
  --fw-cfg SPEC        Pass-through -fw_cfg SPEC (name=...,string=... or file=...).
  --smbios-profile F   File of type=N,key=value lines, passed as -smbios.
  --acpitable FILE     Pass-through -acpitable file=FILE.
  --debugcon [PATH]    OVMF debug console at I/O 0x402 (default:
                       workspace/logs/ovmf_debug.log).
  --gdb                Wait for gdb on TCP 1234 (-s -S).
  --gdb-port PORT      Wait for gdb on TCP PORT (-S).
  --sev / --tdx        Experimental. Enabled only when the host device or
                       module is present, and refused when mixed with SMM.
  --reset-vars         Recopy OVMF VARS from the template (drops enrollments).
  --empty-keys         Use an empty VARS template (Setup Mode), not MS keys.
  --own-pk             Same as --empty-keys.
  --nographic          Headless: -display none (keeps serial on a log or stdio).
  --serial-log PATH    Write the guest serial console to PATH.
  --qmp PATH           QMP unix socket (server, nowait).
  --monitor PATH       HMP monitor unix socket (server, nowait).
  --boot ORDER         Pass -boot ORDER (for example order=d or c).
  --extra-drive FILE   Add a raw -drive file=FILE,format=raw (repeatable).
  --dry-run            Print the feature table and full command; do not launch.
  -h, --help           Show script help.
EOF
}

qemu_common_parse() {
    USV_PARSE_SHIFT=1
    case "$1" in
        --tpm) USV_TPM=1 ;;
        --no-tpm) USV_TPM=0 ;;
        --tpm-tis) USV_TPM=1; USV_TPM_MODEL="tis" ;;
        --smm) USV_SMM=1 ;;
        --no-smm) USV_SMM=0 ;;
        --vbs)
            USV_VBS="${2:?--vbs requires auto, on, or off}"
            case "$USV_VBS" in
                auto|on|off) ;;
                *) echo "[-] --vbs must be auto, on, or off" >&2; return 2 ;;
            esac
            USV_PARSE_SHIFT=2
            ;;
        --iommu) USV_IOMMU=1 ;;
        --fw-protections) USV_FW_PROTECTIONS=1 ;;
        --fw-cfg)
            USV_FW_CFG_ITEMS+=("${2:?--fw-cfg requires name=...,string=... or file=...}")
            USV_PARSE_SHIFT=2
            ;;
        --smbios-profile)
            USV_SMBIOS_PROFILE="${2:?--smbios-profile requires a file path}"
            USV_PARSE_SHIFT=2
            ;;
        --acpitable)
            USV_ACPI_TABLES+=("${2:?--acpitable requires a file path}")
            USV_PARSE_SHIFT=2
            ;;
        --debugcon)
            USV_DEBUGCON=1
            if [ "${2:-}" ] && [ "${2:0:1}" != "-" ]; then
                USV_DEBUGCON_PATH="$2"
                USV_PARSE_SHIFT=2
            fi
            ;;
        --gdb) USV_GDB=1; USV_GDB_PORT="${USV_GDB_PORT:-1234}" ;;
        --gdb-port)
            USV_GDB=1
            USV_GDB_PORT="${2:?--gdb-port requires a port}"
            USV_PARSE_SHIFT=2
            ;;
        --sev) USV_SEV=1 ;;
        --tdx) USV_TDX=1 ;;
        --reset-vars) USV_RESET_VARS=1 ;;
        --empty-keys|--own-pk) USV_EMPTY_KEYS=1 ;;
        --nographic) USV_NOGRAPHIC=1 ;;
        --serial-log)
            USV_SERIAL_LOG="${2:?--serial-log requires a path}"
            USV_PARSE_SHIFT=2
            ;;
        --qmp)
            USV_QMP_PATH="${2:?--qmp requires a socket path}"
            USV_PARSE_SHIFT=2
            ;;
        --monitor)
            USV_MONITOR_PATH="${2:?--monitor requires a socket path}"
            USV_PARSE_SHIFT=2
            ;;
        --boot)
            USV_BOOT_ORDER="${2:?--boot requires an order such as d or order=d}"
            USV_PARSE_SHIFT=2
            ;;
        --extra-drive)
            USV_EXTRA_DRIVES+=("${2:?--extra-drive requires a file path}")
            USV_PARSE_SHIFT=2
            ;;
        --dry-run) USV_DRY_RUN=1 ;;
        *) return 1 ;;
    esac
    return 0
}

qemu_common_init() {
    if [ -z "${USV_ROOT:-}" ]; then
        echo "[-] qemu_common_init: USV_ROOT is not set" >&2
        return 1
    fi
    USV_WORKSPACE="${USV_WORKSPACE:-$USV_ROOT/workspace}"
    USV_OVMF_DIR="$USV_WORKSPACE/ovmf"
    USV_OVMF_CODE="$USV_OVMF_DIR/CODE.fd"
    USV_OVMF_VARS="$USV_OVMF_DIR/VARS.fd"
    USV_OVMF_STAMP="$USV_OVMF_DIR/stamp"
    USV_LOG_DIR="$USV_WORKSPACE/logs"
    USV_TPM_BASE="$USV_WORKSPACE/tpm"
    USV_TPM_DIR="$USV_TPM_BASE/$USV_VM_NAME"
    mkdir -p "$USV_WORKSPACE" "$USV_OVMF_DIR" "$USV_LOG_DIR"
    if [ -z "$USV_DEBUGCON_PATH" ]; then
        USV_DEBUGCON_PATH="$USV_LOG_DIR/ovmf_debug.log"
    fi
}

qemu_feature() {
    local name="$1" state="$2" reason="$3"
    USV_FEATURE_LINES+=("$(printf '%-16s %-10s %s' "$name" "$state" "$reason")")
}

qemu_print_feature_table() {
    echo "========================================================================="
    echo "[+] QEMU lab feature table"
    echo "========================================================================="
    printf "%-16s %-10s %s\n" "feature" "state" "reason"
    local line
    for line in "${USV_FEATURE_LINES[@]}"; do
        printf "%s\n" "$line"
    done
    echo "========================================================================="
}

qemu_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

qemu_file_size() {
    stat -c%s "$1"
}

# Classify an OVMF CODE or VARS image as 4M or 2M. CODE and VARS of the same
# family have different byte sizes (e.g. Debian 4M CODE is 3653632, VARS 540672).
qemu_ovmf_family() {
    local path="$1"
    local base size
    base="$(basename "$path")"
    size="$(qemu_file_size "$path")"
    if [[ "$base" == *_4M* ]]; then
        echo "4M"
        return 0
    fi
    if [ "$size" -ge 1048576 ]; then
        if [ "$size" -ge 3000000 ]; then echo "4M"; else echo "2M"; fi
    else
        if [ "$size" -ge 400000 ]; then echo "4M"; else echo "2M"; fi
    fi
}

qemu_first_existing() {
    local candidate
    for candidate in "$@"; do
        if [ -f "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

# Select a whole CODE+VARS pair from one directory. Never mix families.
qemu_pair_from_dir() {
    local dir="$1"
    local code="" vars=""
    if [ ! -d "$dir" ]; then
        return 1
    fi
    if [ "$USV_EMPTY_KEYS" -eq 1 ]; then
        code="$(qemu_first_existing \
            "$dir/OVMF_CODE_4M.secboot.fd" \
            "$dir/OVMF_CODE_4M.fd" \
            "$dir/OVMF_CODE.secboot.fd" \
            "$dir/OVMF_CODE.ms.fd" \
            "$dir/OVMF_CODE.fd" || true)"
        vars="$(qemu_first_existing \
            "$dir/OVMF_VARS_4M.fd" \
            "$dir/OVMF_VARS.fd" || true)"
    else
        code="$(qemu_first_existing \
            "$dir/OVMF_CODE_4M.secboot.fd" \
            "$dir/OVMF_CODE_4M.fd" \
            "$dir/OVMF_CODE.secboot.fd" \
            "$dir/OVMF_CODE.ms.fd" \
            "$dir/OVMF_CODE.fd" || true)"
        vars="$(qemu_first_existing \
            "$dir/OVMF_VARS_4M.ms.fd" \
            "$dir/OVMF_VARS_4M.fd" \
            "$dir/OVMF_VARS.ms.fd" \
            "$dir/OVMF_VARS.fd" || true)"
    fi
    if [ -n "$code" ] && [ -n "$vars" ]; then
        if [ "$(qemu_ovmf_family "$code")" != "$(qemu_ovmf_family "$vars")" ]; then
            return 1
        fi
        USV_OVMF_SRC_CODE="$code"
        USV_OVMF_SRC_VARS="$vars"
        USV_OVMF_FAMILY="$(qemu_ovmf_family "$code")"
        return 0
    fi
    return 1
}

qemu_select_ovmf_pair() {
    local dir
    for dir in \
        /usr/share/OVMF \
        /usr/share/edk2/ovmf \
        /usr/share/qemu \
        /usr/share/ovmf \
        "$USV_ROOT"
    do
        if qemu_pair_from_dir "$dir"; then
            return 0
        fi
    done
    echo "[-] No matching OVMF CODE+VARS pair found under /usr/share/OVMF, /usr/share/edk2/ovmf, /usr/share/qemu, or the repo root." >&2
    return 1
}

qemu_migrate_root_vars() {
    # Preserve enrollments from a previous 02_run_qemu.sh that staged
    # OVMF_VARS.fd at the repository root, when the new dest is empty.
    if [ -f "$USV_OVMF_VARS" ]; then
        return 1
    fi
    if [ ! -f "$USV_ROOT/OVMF_VARS.fd" ]; then
        return 1
    fi
    echo "[*] Migrating existing $USV_ROOT/OVMF_VARS.fd into $USV_OVMF_VARS"
    cp "$USV_ROOT/OVMF_VARS.fd" "$USV_OVMF_VARS"
    if [ -f "$USV_ROOT/OVMF_CODE.fd" ] && [ ! -f "$USV_OVMF_CODE" ]; then
        cp "$USV_ROOT/OVMF_CODE.fd" "$USV_OVMF_CODE"
    fi
    return 0
}

qemu_write_stamp() {
    cat > "$USV_OVMF_STAMP" <<EOF
CODE_SRC=$USV_OVMF_SRC_CODE
CODE_SHA256=$(qemu_sha256 "$USV_OVMF_SRC_CODE")
CODE_SIZE=$(qemu_file_size "$USV_OVMF_SRC_CODE")
VARS_SRC=$USV_OVMF_SRC_VARS
VARS_SHA256=$(qemu_sha256 "$USV_OVMF_SRC_VARS")
VARS_SIZE=$(qemu_file_size "$USV_OVMF_SRC_VARS")
FAMILY=$USV_OVMF_FAMILY
EOF
}

qemu_stamp_field() {
    local key="$1"
    awk -F= -v k="$key" '$1==k {print substr($0, index($0,"=")+1)}' "$USV_OVMF_STAMP" 2>/dev/null || true
}

qemu_stage_ovmf() {
    qemu_select_ovmf_pair
    local src_code_hash src_stamp_hash dest_family vars_family
    src_code_hash="$(qemu_sha256 "$USV_OVMF_SRC_CODE")"

    qemu_migrate_root_vars || true

    if [ -f "$USV_OVMF_STAMP" ] && [ -f "$USV_OVMF_CODE" ] && [ -f "$USV_OVMF_VARS" ] && [ "$USV_RESET_VARS" -eq 0 ]; then
        src_stamp_hash="$(qemu_stamp_field CODE_SHA256)"
        if [ -n "$src_stamp_hash" ] && [ "$src_stamp_hash" != "$src_code_hash" ]; then
            echo "[-] OVMF CODE source changed ($USV_OVMF_SRC_CODE)." >&2
            echo "    Stamped: $src_stamp_hash" >&2
            echo "    Current: $src_code_hash" >&2
            echo "    Refusing to mix a new CODE image with an existing VARS store." >&2
            echo "    Re-run with --reset-vars to recopy the VARS template (this drops enrollments)." >&2
            return 1
        fi
        vars_stamp_hash="$(qemu_stamp_field VARS_SHA256)"
        vars_now_hash="$(qemu_sha256 "$USV_OVMF_SRC_VARS")"
        if [ -n "$vars_stamp_hash" ] && [ "$vars_stamp_hash" != "$vars_now_hash" ]; then
            echo "[-] OVMF VARS template changed ($USV_OVMF_SRC_VARS)." >&2
            echo "    Stamped: $vars_stamp_hash" >&2
            echo "    Current: $vars_now_hash" >&2
            echo "    This happens when switching --empty-keys / --own-pk, or when the package template changed." >&2
            echo "    Re-run with --reset-vars to recopy the new VARS template (this drops enrollments)." >&2
            return 1
        fi
    fi

    mkdir -p "$USV_OVMF_DIR"
    cp "$USV_OVMF_SRC_CODE" "$USV_OVMF_CODE"
    if [ "$USV_RESET_VARS" -eq 1 ] || [ ! -f "$USV_OVMF_VARS" ]; then
        echo "[*] Initializing NVRAM from $USV_OVMF_SRC_VARS"
        cp "$USV_OVMF_SRC_VARS" "$USV_OVMF_VARS"
    else
        echo "[*] Reusing existing NVRAM $USV_OVMF_VARS"
    fi

    dest_family="$(qemu_ovmf_family "$USV_OVMF_CODE")"
    vars_family="$(qemu_ovmf_family "$USV_OVMF_VARS")"
    if [ "$dest_family" != "$vars_family" ]; then
        echo "[-] OVMF family mismatch: CODE is $dest_family ($(qemu_file_size "$USV_OVMF_CODE") bytes), VARS is $vars_family ($(qemu_file_size "$USV_OVMF_VARS") bytes)." >&2
        echo "    Refusing to launch. Pass --reset-vars to recopy a matching pair." >&2
        return 1
    fi
    USV_OVMF_FAMILY="$dest_family"
    qemu_write_stamp

    # Compatibility copies at the repo root (gitignored), used by older docs.
    cp "$USV_OVMF_CODE" "$USV_ROOT/OVMF_CODE.fd"
    cp "$USV_OVMF_VARS" "$USV_ROOT/OVMF_VARS.fd"

    echo "[*] OVMF CODE: $USV_OVMF_SRC_CODE -> $USV_OVMF_CODE"
    echo "[*] OVMF VARS: $USV_OVMF_VARS ($USV_OVMF_FAMILY pair)"
    qemu_feature "firmware" "on" "$USV_OVMF_SRC_CODE + $(basename "$USV_OVMF_SRC_VARS") ($USV_OVMF_FAMILY)"
}

qemu_has_kvm() {
    [ -e /dev/kvm ] && [ -r /dev/kvm ]
}

# /dev/kvm can be present but unusable (this host leaves QEMU unresponsive to
# QMP once -accel kvm is on). Probe with a tiny VM and a QMP handshake.
USV_KVM_USABLE_CACHED=""
qemu_kvm_usable() {
    if [ -n "$USV_KVM_USABLE_CACHED" ]; then
        [ "$USV_KVM_USABLE_CACHED" = "yes" ]
        return
    fi
    if ! qemu_has_kvm; then
        USV_KVM_USABLE_CACHED="no"
        return 1
    fi
    local sock pid rc=1
    sock="$(mktemp -u /tmp/usv-kvmprobe.XXXXXX.sock)"
    "$USV_QEMU_BIN" -display none -machine none -m 16 -accel kvm         -qmp "unix:$sock,server,nowait" -serial none -monitor none         >/dev/null 2>&1 &
    pid=$!
    local i
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        if [ -S "$sock" ]; then
            break
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done
    if [ -S "$sock" ] && command -v python3 >/dev/null 2>&1; then
        if python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2)
s.connect(sys.argv[1])
s.recv(4096)
s.sendall(b"{"execute":"qmp_capabilities"}\n")
r = s.recv(4096)
sys.exit(0 if b"return" in r else 1)
' "$sock"
        then
            rc=0
        fi
    fi
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$sock"
    if [ "$rc" -eq 0 ]; then
        USV_KVM_USABLE_CACHED="yes"
        return 0
    fi
    USV_KVM_USABLE_CACHED="no"
    return 1
}

qemu_nested_ok() {
    local val path
    for path in /sys/module/kvm_intel/parameters/nested /sys/module/kvm_amd/parameters/nested; do
        if [ -r "$path" ]; then
            val="$(tr -d '[:space:]' < "$path")"
            case "$val" in
                Y|y|1) return 0 ;;
            esac
        fi
    done
    return 1
}

qemu_host_virt_flag() {
    if [ -d /sys/module/kvm_intel ]; then
        echo "+vmx"
    elif [ -d /sys/module/kvm_amd ]; then
        echo "+svm"
    elif grep -qw vmx /proc/cpuinfo; then
        echo "+vmx"
    elif grep -qw svm /proc/cpuinfo; then
        echo "+svm"
    else
        echo ""
    fi
}

qemu_hv_passthrough_ok() {
    # machine=none fails later (apic-id), but an unknown CPU property is
    # reported immediately as "Property ... not found".
    local err
    err="$("$USV_QEMU_BIN" -display none -machine none -cpu host,hv-passthrough \
        -accel tcg -nographic -monitor none -serial none 2>&1 || true)"
    if printf '%s' "$err" | grep -Eqi "Property 'host-x86_64-cpu.hv-passthrough' not found|hv-passthrough.*not found"; then
        return 1
    fi
    return 0
}

qemu_sysfs_truthy() {
    local path="$1"
    local val
    [ -r "$path" ] || return 1
    val="$(tr -d '[:space:]' < "$path")"
    case "$val" in
        Y|y|1) return 0 ;;
    esac
    return 1
}

qemu_sev_available() {
    [ -e /dev/sev ] || [ -e /dev/sev-guest ] || qemu_sysfs_truthy /sys/module/kvm_amd/parameters/sev_snp || qemu_sysfs_truthy /sys/module/kvm_amd/parameters/sev
}

qemu_tdx_available() {
    [ -e /dev/tdx-guest ] || [ -e /dev/tdx_guest ] || qemu_sysfs_truthy /sys/module/kvm_intel/parameters/tdx
}

qemu_swtpm_stop() {
    local pidfile="$USV_TPM_DIR/swtpm.pid"
    local pid=""
    if [ -n "${USV_SWTPM_PID:-}" ]; then
        pid="$USV_SWTPM_PID"
    elif [ -f "$pidfile" ]; then
        pid="$(tr -d '[:space:]' < "$pidfile")"
    fi
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        local i
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi
    USV_SWTPM_PID=""
    rm -f "$USV_TPM_DIR/swtpm-sock" "$pidfile"
}

qemu_cleanup() {
    qemu_swtpm_stop
}

qemu_register_cleanup() {
    if [ "$USV_CLEANUP_REGISTERED" -eq 0 ]; then
        trap qemu_cleanup EXIT INT TERM
        USV_CLEANUP_REGISTERED=1
    fi
}

qemu_swtpm_setup() {
    mkdir -p "$USV_TPM_DIR"
    if [ -f "$USV_TPM_DIR/tpm2-00.permall" ]; then
        return 0
    fi
    echo "[*] Authoring swtpm TPM 2.0 state in $USV_TPM_DIR"
    local log="$USV_LOG_DIR/swtpm_setup_${USV_VM_NAME}.log"
    if swtpm_setup --tpm2 --tpm-state "$USV_TPM_DIR" \
        --create-ek-cert --create-platform-cert --lock-nvram --not-overwrite \
        >"$log" 2>&1
    then
        USV_TPM_CERTS="ek+platform"
        return 0
    fi
    echo "[*] swtpm_setup with EK/platform certs failed; retrying without certificates."
    if swtpm_setup --tpm2 --tpm-state "$USV_TPM_DIR" --lock-nvram --not-overwrite \
        >>"$log" 2>&1
    then
        USV_TPM_CERTS="none (swtpm_localca not usable; PCRs still measured)"
        return 0
    fi
    echo "[-] swtpm_setup failed. See $log" >&2
    tail -n 20 "$log" >&2 || true
    return 1
}

qemu_swtpm_start() {
    local sock="$USV_TPM_DIR/swtpm-sock"
    local pidfile="$USV_TPM_DIR/swtpm.pid"
    if [ -S "$sock" ]; then
        qemu_swtpm_stop
    fi
    rm -f "$sock" "$pidfile"
    swtpm socket \
        --tpm2 \
        --tpmstate "dir=$USV_TPM_DIR" \
        --ctrl "type=unixio,path=$sock" \
        --pid "file=$pidfile" \
        --log "file=$USV_TPM_DIR/swtpm.log" \
        --daemon
    local i
    for _ in $(seq 1 50); do
        if [ -S "$sock" ]; then
            if [ -f "$pidfile" ]; then
                USV_SWTPM_PID="$(tr -d '[:space:]' < "$pidfile")"
            fi
            USV_SWTPM_SOCK="$sock"
            return 0
        fi
        sleep 0.1
    done
    echo "[-] swtpm did not create $sock" >&2
    cat "$USV_TPM_DIR/swtpm.log" >&2 || true
    return 1
}

qemu_prepare_accel_and_cpu() {
    USV_HAS_KVM=0
    USV_NESTED_OK=0
    USV_VBS_EFFECTIVE="off"
    USV_ACCEL="tcg"
    USV_CPU="max"
    USV_HV_MODE="none"

    if qemu_kvm_usable; then
        USV_HAS_KVM=1
        USV_ACCEL="kvm"
        USV_CPU="host"
        local virt
        virt="$(qemu_host_virt_flag)"
        if [ -n "$virt" ]; then
            USV_CPU="host,$virt"
        fi
        qemu_feature "kvm" "on" "/dev/kvm usable (QMP probe succeeded)"
    elif qemu_has_kvm; then
        USV_HAS_KVM=0
        qemu_feature "kvm" "skipped" "/dev/kvm is present but a QMP probe did not respond; TCG fallback"
    else
        qemu_feature "kvm" "off" "/dev/kvm missing or not readable; TCG fallback"
    fi

    if qemu_nested_ok; then
        USV_NESTED_OK=1
        qemu_feature "nested" "on" "kvm_intel/kvm_amd nested parameter is Y or 1"
    else
        qemu_feature "nested" "off" "nested virtualization is not enabled"
    fi

    local want_vbs=0
    case "$USV_VBS" in
        on) want_vbs=1 ;;
        off) want_vbs=0 ;;
        auto)
            if [ "$USV_HAS_KVM" -eq 1 ] && [ "$USV_NESTED_OK" -eq 1 ]; then
                want_vbs=1
            fi
            ;;
    esac

    if [ "$want_vbs" -eq 1 ]; then
        if [ "$USV_HAS_KVM" -ne 1 ]; then
            qemu_feature "vbs" "skipped" "--vbs requested but /dev/kvm is not available"
        elif [ "$USV_NESTED_OK" -ne 1 ]; then
            qemu_feature "vbs" "skipped" "--vbs requested but nested virtualization is off"
        else
            USV_VBS_EFFECTIVE="on"
            if qemu_hv_passthrough_ok; then
                USV_CPU="${USV_CPU},hv-passthrough"
                USV_HV_MODE="hv-passthrough"
            else
                USV_CPU="${USV_CPU},hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-vpindex,hv-runtime,hv-synic,hv-stimer,hv-time,hv-frequencies,hv-tlbflush,hv-ipi"
                USV_HV_MODE="explicit"
            fi
            qemu_feature "vbs" "on" "KVM + nested, $USV_HV_MODE (VBS/HVCI guest enlightenments)"
        fi
    elif [ "$USV_VBS" = "auto" ]; then
        qemu_feature "vbs" "off" "auto: needs both /dev/kvm and nested virtualization"
    else
        qemu_feature "vbs" "off" "not requested (or --vbs off / --no-nested)"
    fi
}

qemu_prepare_iommu() {
    USV_IOMMU_EFFECTIVE="off"
    if [ "$USV_IOMMU" -ne 1 ]; then
        qemu_feature "iommu" "off" "not requested"
        return 0
    fi
    if [ "$USV_HAS_KVM" -ne 1 ]; then
        qemu_feature "iommu" "skipped" "--iommu requires KVM"
        return 0
    fi
    USV_IOMMU_EFFECTIVE="on"
    qemu_feature "iommu" "on" "intel-iommu intremap=on,caching-mode=on; kernel-irqchip=split"
}

qemu_prepare_smm() {
    USV_SMM_EFFECTIVE="off"
    if [ "$USV_SMM" -eq 1 ]; then
        USV_SMM_EFFECTIVE="on"
        qemu_feature "smm" "on" "-machine q35,smm=on; cfi.pflash01 secure=on"
    else
        qemu_feature "smm" "off" "--no-smm"
    fi
}

qemu_prepare_confidential() {
    USV_SEV_EFFECTIVE="off"
    USV_TDX_EFFECTIVE="off"
    if [ "$USV_SEV" -eq 1 ]; then
        if [ "$USV_SMM_EFFECTIVE" = "on" ]; then
            qemu_feature "sev" "skipped" "refused: experimental SEV is not mixed with SMM"
        elif ! qemu_sev_available; then
            qemu_feature "sev" "skipped" "no /dev/sev, /dev/sev-guest, or sev_snp/sev module flag"
        else
            # Host looks capable, but this lab does not emit an untested
            # -object sev-guest / machine confidentiality line.
            qemu_feature "sev" "skipped" "host SEV present, but no tested SEV object line is emitted"
        fi
    else
        qemu_feature "sev" "off" "not requested"
    fi
    if [ "$USV_TDX" -eq 1 ]; then
        if [ "$USV_SMM_EFFECTIVE" = "on" ]; then
            qemu_feature "tdx" "skipped" "refused: experimental TDX is not mixed with SMM"
        elif ! qemu_tdx_available; then
            qemu_feature "tdx" "skipped" "no TDX device or kvm_intel tdx parameter"
        else
            qemu_feature "tdx" "skipped" "host TDX present, but no tested TDX object line is emitted"
        fi
    else
        qemu_feature "tdx" "off" "not requested"
    fi
}

qemu_prepare_tpm() {
    USV_TPM_EFFECTIVE="off"
    USV_TPM_CERTS=""
    if [ "$USV_TPM" -ne 1 ]; then
        qemu_feature "tpm" "off" "--no-tpm"
        return 0
    fi
    if ! command -v swtpm >/dev/null 2>&1 || ! command -v swtpm_setup >/dev/null 2>&1; then
        qemu_feature "tpm" "skipped" "swtpm / swtpm_setup not installed"
        return 0
    fi
    if [ "$USV_DRY_RUN" -eq 1 ]; then
        USV_TPM_EFFECTIVE="on"
        USV_SWTPM_SOCK="$USV_TPM_DIR/swtpm-sock"
        qemu_feature "tpm" "on" "swtpm TPM 2.0 tpm-$USV_TPM_MODEL (dry-run; state $USV_TPM_DIR)"
        return 0
    fi
    qemu_register_cleanup
    qemu_swtpm_setup
    qemu_swtpm_start
    USV_TPM_EFFECTIVE="on"
    local extra="tpm-$USV_TPM_MODEL, state $USV_TPM_DIR"
    if [ -n "$USV_TPM_CERTS" ]; then
        extra="$extra; certs: $USV_TPM_CERTS"
    fi
    qemu_feature "tpm" "on" "$extra"
}

qemu_build_machine() {
    USV_MACHINE="q35"
    if [ "$USV_SMM_EFFECTIVE" = "on" ]; then
        USV_MACHINE="${USV_MACHINE},smm=on"
    fi
    if [ "$USV_IOMMU_EFFECTIVE" = "on" ]; then
        USV_MACHINE="${USV_MACHINE},kernel-irqchip=split"
    fi
    # No experimental SEV/TDX -object or machine properties are added.
}

qemu_append_fw_cfg() {
    if [ "$USV_FW_PROTECTIONS" -eq 1 ]; then
        USV_QEMU_ARGS+=(-fw_cfg "name=opt/ovmf/PcdSetNxForStack,string=yes")
        USV_QEMU_ARGS+=(-fw_cfg "name=opt/org.tianocore/EnableLegacyLoader,string=no")
        qemu_feature "fw-protections" "on" "opt/ovmf/PcdSetNxForStack=yes, opt/org.tianocore/EnableLegacyLoader=no"
    else
        qemu_feature "fw-protections" "off" "not requested"
    fi
    local spec
    for spec in "${USV_FW_CFG_ITEMS[@]+"${USV_FW_CFG_ITEMS[@]}"}"; do
        USV_QEMU_ARGS+=(-fw_cfg "$spec")
    done
    if [ "${#USV_FW_CFG_ITEMS[@]}" -gt 0 ]; then
        qemu_feature "fw-cfg" "on" "${#USV_FW_CFG_ITEMS[@]} pass-through item(s)"
    else
        qemu_feature "fw-cfg" "off" "no extra --fw-cfg items"
    fi
}

qemu_append_smbios() {
    if [ -z "$USV_SMBIOS_PROFILE" ]; then
        qemu_feature "smbios" "off" "no profile"
        return 0
    fi
    if [ ! -f "$USV_SMBIOS_PROFILE" ]; then
        echo "[-] SMBIOS profile not found: $USV_SMBIOS_PROFILE" >&2
        return 1
    fi
    local line count=0
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|\#*) continue ;;
        esac
        if [[ "$line" != type=* ]]; then
            echo "[-] SMBIOS profile line must start with type=: $line" >&2
            return 1
        fi
        USV_QEMU_ARGS+=(-smbios "$line")
        count=$((count + 1))
    done < "$USV_SMBIOS_PROFILE"
    qemu_feature "smbios" "on" "$USV_SMBIOS_PROFILE ($count type line(s))"
}

qemu_append_acpi() {
    local f
    if [ "${#USV_ACPI_TABLES[@]}" -eq 0 ]; then
        qemu_feature "acpitable" "off" "not requested"
        return 0
    fi
    for f in "${USV_ACPI_TABLES[@]}"; do
        if [ ! -f "$f" ]; then
            echo "[-] ACPI table not found: $f" >&2
            return 1
        fi
        USV_QEMU_ARGS+=(-acpitable "file=$f")
    done
    qemu_feature "acpitable" "on" "${#USV_ACPI_TABLES[@]} table file(s)"
}

qemu_shell_quote() {
    local out="" arg
    for arg in "$@"; do
        out+=" $(printf '%q' "$arg")"
    done
    printf '%s\n' "${out# }"
}

qemu_build_args() {
    USV_QEMU_ARGS=("$USV_QEMU_BIN")
    USV_QEMU_ARGS+=(-machine "$USV_MACHINE")
    USV_QEMU_ARGS+=(-accel "$USV_ACCEL")
    USV_QEMU_ARGS+=(-cpu "$USV_CPU")
    USV_QEMU_ARGS+=(-smp "$USV_SMP")
    USV_QEMU_ARGS+=(-m "$USV_MEM")

    if [ "$USV_SMM_EFFECTIVE" = "on" ]; then
        USV_QEMU_ARGS+=(-global "driver=cfi.pflash01,property=secure,value=on")
    fi
    USV_QEMU_ARGS+=(-drive "if=pflash,format=raw,unit=0,file=$USV_OVMF_CODE,readonly=on")
    USV_QEMU_ARGS+=(-drive "if=pflash,format=raw,unit=1,file=$USV_OVMF_VARS")

    if [ "$USV_TPM_EFFECTIVE" = "on" ]; then
        USV_QEMU_ARGS+=(-chardev "socket,id=chrtpm,path=$USV_SWTPM_SOCK")
        USV_QEMU_ARGS+=(-tpmdev "emulator,id=tpm0,chardev=chrtpm")
        if [ "$USV_TPM_MODEL" = "tis" ]; then
            USV_QEMU_ARGS+=(-device "tpm-tis,tpmdev=tpm0")
        else
            USV_QEMU_ARGS+=(-device "tpm-crb,tpmdev=tpm0")
        fi
    fi

    if [ "$USV_IOMMU_EFFECTIVE" = "on" ]; then
        USV_QEMU_ARGS+=(-device "intel-iommu,intremap=on,caching-mode=on")
    fi

    qemu_append_fw_cfg
    qemu_append_smbios
    qemu_append_acpi

    if [ "$USV_DEBUGCON" -eq 1 ]; then
        mkdir -p "$(dirname "$USV_DEBUGCON_PATH")"
        USV_QEMU_ARGS+=(-debugcon "file:$USV_DEBUGCON_PATH")
        USV_QEMU_ARGS+=(-global isa-debugcon.iobase=0x402)
        qemu_feature "debugcon" "on" "isa-debugcon 0x402 -> $USV_DEBUGCON_PATH"
    else
        qemu_feature "debugcon" "off" "not requested"
    fi

    if [ -n "$USV_SERIAL_LOG" ]; then
        mkdir -p "$(dirname "$USV_SERIAL_LOG")"
        USV_QEMU_ARGS+=(-serial "file:$USV_SERIAL_LOG")
        qemu_feature "serial" "on" "file:$USV_SERIAL_LOG"
    elif [ "$USV_NOGRAPHIC" -eq 1 ]; then
        USV_QEMU_ARGS+=(-serial mon:stdio)
        qemu_feature "serial" "on" "mon:stdio (headless)"
    else
        qemu_feature "serial" "off" "QEMU default"
    fi

    if [ "$USV_NOGRAPHIC" -eq 1 ]; then
        USV_QEMU_ARGS+=(-display none)
        qemu_feature "display" "off" "--nographic / -display none"
    else
        qemu_feature "display" "on" "caller video device (usually -vga std)"
    fi

    if [ -n "$USV_QMP_PATH" ]; then
        mkdir -p "$(dirname "$USV_QMP_PATH")"
        rm -f "$USV_QMP_PATH"
        USV_QEMU_ARGS+=(-qmp "unix:$USV_QMP_PATH,server,nowait")
        qemu_feature "qmp" "on" "$USV_QMP_PATH"
    else
        qemu_feature "qmp" "off" "not requested"
    fi

    if [ -n "$USV_MONITOR_PATH" ]; then
        mkdir -p "$(dirname "$USV_MONITOR_PATH")"
        rm -f "$USV_MONITOR_PATH"
        USV_QEMU_ARGS+=(-monitor "unix:$USV_MONITOR_PATH,server,nowait")
        qemu_feature "monitor" "on" "$USV_MONITOR_PATH"
    else
        qemu_feature "monitor" "off" "not requested"
    fi

    if [ "$USV_GDB" -eq 1 ]; then
        local port="${USV_GDB_PORT:-1234}"
        USV_QEMU_ARGS+=(-gdb "tcp::$port" -S)
        qemu_feature "gdb" "on" "tcp::$port (waits with -S)"
    else
        qemu_feature "gdb" "off" "not requested"
    fi

    if [ -n "$USV_BOOT_ORDER" ]; then
        USV_QEMU_ARGS+=(-boot "$USV_BOOT_ORDER")
        qemu_feature "boot" "on" "-boot $USV_BOOT_ORDER"
    else
        qemu_feature "boot" "off" "firmware default boot order"
    fi

    local drv i=0
    for drv in "${USV_EXTRA_DRIVES[@]+"${USV_EXTRA_DRIVES[@]}"}"; do
        if [ ! -f "$drv" ] && [ "$USV_DRY_RUN" -ne 1 ]; then
            echo "[-] --extra-drive file not found: $drv" >&2
            return 1
        fi
        # q35 has no implicit PIIX IDE; attach as AHCI/ide-hd with a bootindex
        # so OVMF can boot a raw FAT/ESP without depending on Virtio.
        i=$((i + 1))
        USV_QEMU_ARGS+=(-drive "file=$drv,format=raw,if=none,id=usvextra${i}")
        USV_QEMU_ARGS+=(-device "ide-hd,drive=usvextra${i},bootindex=${i}")
    done
    if [ "${#USV_EXTRA_DRIVES[@]}" -gt 0 ]; then
        qemu_feature "extra-drive" "on" "${#USV_EXTRA_DRIVES[@]} raw drive(s)"
    fi

    if [ "${#USV_EXTRA_ARGS[@]}" -gt 0 ]; then
        USV_QEMU_ARGS+=("${USV_EXTRA_ARGS[@]}")
    fi
}

qemu_prepare() {
    qemu_common_init
    USV_FEATURE_LINES=()
    if ! command -v "$USV_QEMU_BIN" >/dev/null 2>&1; then
        echo "[-] $USV_QEMU_BIN is not on PATH. Install qemu-system-x86 (and ovmf, swtpm) or run ./build_uefi.sh." >&2
        return 1
    fi
    qemu_stage_ovmf
    qemu_prepare_accel_and_cpu
    qemu_prepare_smm
    qemu_prepare_iommu
    qemu_prepare_confidential
    qemu_prepare_tpm
    qemu_build_machine
    qemu_build_args
    qemu_print_feature_table
}

qemu_print_command() {
    echo "[*] QEMU command:"
    qemu_shell_quote "${USV_QEMU_ARGS[@]}"
    if [ "$USV_TPM" -eq 1 ]; then
        echo "[*] swtpm state directory: $USV_TPM_DIR"
        echo "[*] swtpm command (started unless --dry-run):"
        qemu_shell_quote swtpm socket --tpm2 --tpmstate "dir=$USV_TPM_DIR" \
            --ctrl "type=unixio,path=$USV_TPM_DIR/swtpm-sock" \
            --pid "file=$USV_TPM_DIR/swtpm.pid" \
            --log "file=$USV_TPM_DIR/swtpm.log" \
            --daemon
    fi
}

qemu_exec() {
    qemu_print_command
    if [ "$USV_DRY_RUN" -eq 1 ]; then
        echo "[*] --dry-run: not launching QEMU or swtpm."
        return 0
    fi
    echo "[*] Launching QEMU..."
    local rc=0
    "${USV_QEMU_ARGS[@]}" || rc=$?
    # Keep the compatibility root copy in sync with enrollments written to dest VARS.
    if [ -f "$USV_OVMF_VARS" ]; then
        cp "$USV_OVMF_VARS" "$USV_ROOT/OVMF_VARS.fd"
    fi
    return "$rc"
}
