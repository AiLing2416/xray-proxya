#!/bin/bash
# ==============================================================================
# Xray-Proxya OpenWrt APK Packaging Tool (for OpenWrt 25.10+ / apk-tools)
# Builds spec-compliant, standalone .apk packages for the Slim build profile.
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PKGNAME="xray-proxya-slim"
RELEASE="r1"
OUTPUT_DIR="$REPO_ROOT/build"
BINARY_PATH=""
TARGET_ARCH=""
VERSION=""
MODE="auto"
AUTO_BUILD=false
VERIFY=false

usage() {
    cat << EOF
Usage: $(basename "$0") [options]

Build an OpenWrt / Alpine apk-tools package (.apk) for Xray-Proxya Slim.

Options:
  -a, --arch ARCH        Target architecture (e.g. x86_64, aarch64, armv7, x86)
                         Default: auto-detected from host or binary
  -b, --binary PATH      Path to pre-compiled xray-proxya-slim binary
                         Default: build/xray-proxya-slim (or auto-built if --build)
  -o, --out-dir DIR      Output directory for generated .apk (default: build/)
  -v, --version VER      Package version (default: parsed from internal/buildinfo)
  -r, --release REL      Package release revision (default: r1)
  -n, --pkgname NAME     Package name (default: xray-proxya-slim)
  -m, --mode MODE        Packaging engine: auto, container, native, fallback
                         Default: auto (tries container abuild-tar, then native, then python)
      --build            Automatically build the binary with 'go build' if missing
      --verify           Verify generated .apk using podman/docker in alpine:3.21
  -h, --help             Show this help message
EOF
    exit 0
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--arch)
            TARGET_ARCH="$2"
            shift 2
            ;;
        -b|--binary)
            BINARY_PATH="$2"
            shift 2
            ;;
        -o|--out-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -r|--release)
            RELEASE="$2"
            shift 2
            ;;
        -n|--pkgname)
            PKGNAME="$2"
            shift 2
            ;;
        -m|--mode)
            MODE="$2"
            shift 2
            ;;
        --build)
            AUTO_BUILD=true
            shift
            ;;
        --verify)
            VERIFY=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}❌ Unknown argument: $1${NC}" >&2
            usage
            ;;
    esac
done

# 1. Resolve Version
if [ -z "$VERSION" ]; then
    VERSION_FILE="$REPO_ROOT/internal/buildinfo/version.go"
    if [ -f "$VERSION_FILE" ]; then
        VERSION=$(grep 'const Version =' "$VERSION_FILE" | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
    fi
    if [ -z "$VERSION" ]; then
        VERSION="0.5.4"
    fi
fi

# 2. Resolve Architecture Mapping
HOST_UNAME="$(uname -m)"
RAW_ARCH="${TARGET_ARCH:-$HOST_UNAME}"

case "$RAW_ARCH" in
    x86_64|amd64)
        ARCH="x86_64"
        GOARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        GOARCH="arm64"
        ;;
    armv7*|armhf|arm)
        ARCH="armv7"
        GOARCH="arm"
        ;;
    i386|i686|386|x86)
        ARCH="x86"
        GOARCH="386"
        ;;
    *)
        ARCH="$RAW_ARCH"
        GOARCH="$RAW_ARCH"
        ;;
esac

echo -e "${BLUE}📦 Packaging OpenWrt APK for ${GREEN}${PKGNAME}${BLUE} v${VERSION}-${RELEASE} (${ARCH})${NC}"

# 3. Locate or Build Target Binary
if [ -z "$BINARY_PATH" ]; then
    CANDIDATES=(
        "$OUTPUT_DIR/xray-proxya-slim-${ARCH}"
        "$OUTPUT_DIR/xray-proxya-slim-linux-${GOARCH}"
    )
    if [ "$ARCH" = "x86_64" ] && [ "$HOST_UNAME" = "x86_64" ]; then
        CANDIDATES=("$OUTPUT_DIR/xray-proxya-slim" "${CANDIDATES[@]}")
    elif [ "$ARCH" = "aarch64" ] && [ "$HOST_UNAME" = "aarch64" ]; then
        CANDIDATES=("$OUTPUT_DIR/xray-proxya-slim" "${CANDIDATES[@]}")
    fi

    for cand in "${CANDIDATES[@]}"; do
        if [ -f "$cand" ]; then
            BINARY_PATH="$cand"
            break
        fi
    done
fi

if [ -z "$BINARY_PATH" ] || [ ! -f "$BINARY_PATH" ]; then
    if [ "$AUTO_BUILD" = true ] || [ -z "$BINARY_PATH" ]; then
        if command -v go >/dev/null 2>&1; then
            mkdir -p "$OUTPUT_DIR"
            if [ "$ARCH" = "x86_64" ] && [ "$HOST_UNAME" = "x86_64" ]; then
                BINARY_PATH="$OUTPUT_DIR/xray-proxya-slim"
            else
                BINARY_PATH="$OUTPUT_DIR/xray-proxya-slim-${ARCH}"
            fi
            echo -e "⚙️ Compiling Slim binary for linux/${GOARCH} -> ${BINARY_PATH}..."
            CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" go build -trimpath -tags slim -ldflags "-s -w" -o "$BINARY_PATH" "$REPO_ROOT/cmd/xray-proxya/"
        else
            echo -e "${RED}❌ Slim binary not found and 'go' compiler is not available.${NC}" >&2
            echo -e "${YELLOW}Please provide binary with --binary or install Go.${NC}" >&2
            exit 1
        fi
    else
        echo -e "${RED}❌ Binary not found at: $BINARY_PATH${NC}" >&2
        exit 1
    fi
fi

if [ ! -s "$BINARY_PATH" ]; then
    echo -e "${RED}❌ Target binary is empty: $BINARY_PATH${NC}" >&2
    exit 1
fi

BINARY_PATH="$(cd "$(dirname "$BINARY_PATH")" && pwd)/$(basename "$BINARY_PATH")"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
APK_FILENAME="${PKGNAME}_${VERSION}-${RELEASE}_${ARCH}.apk"
FINAL_APK="$OUTPUT_DIR/$APK_FILENAME"

echo -e "🔍 Source Binary: ${GREEN}$BINARY_PATH${NC} ($(ls -lh "$BINARY_PATH" | awk '{print $5}'))"

# 4. Prepare Staging Tree
STAGING_DIR="$(mktemp -d "$OUTPUT_DIR/.staging-apk.XXXXXX")"
cleanup() {
    rm -rf "$STAGING_DIR"
}
trap cleanup EXIT INT TERM

PKG_DIR="$STAGING_DIR/pkg"
CTRL_DIR="$STAGING_DIR/ctrl"

mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/etc/init.d"
mkdir -p "$CTRL_DIR"

# A. Binary: /usr/bin/xray-proxya
cp "$BINARY_PATH" "$PKG_DIR/usr/bin/xray-proxya"
chmod 0755 "$PKG_DIR/usr/bin/xray-proxya"

# B. Multi-call Symlink: /usr/bin/pathd -> xray-proxya
(cd "$PKG_DIR/usr/bin" && ln -sf "xray-proxya" "pathd")

# C. Procd Service: /etc/init.d/xray-proxya
cat << 'EOF' > "$PKG_DIR/etc/init.d/xray-proxya"
#!/bin/sh /etc/rc.common

START=95
STOP=10
USE_PROCD=1

PROG="/usr/bin/xray-proxya"
WORKDIR="/root/.local/share/xray-proxya"
ASSETDIR="/root/.local/share/xray-proxya/bin"

start_service() {
	mkdir -p "$WORKDIR" "$ASSETDIR"
	chmod 0700 "$WORKDIR" "$ASSETDIR"

	procd_open_instance "main"
	procd_set_param command "$PROG" run
	procd_set_param env XRAY_LOCATION_ASSET="$ASSETDIR"
	procd_set_param respawn 3600 2 5
	procd_set_param term_timeout 15
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_set_param user root
	procd_close_instance
}

stop_service() {
	return 0
}

reload_service() {
	restart
}
EOF
chmod 0755 "$PKG_DIR/etc/init.d/xray-proxya"

# D. Lifecycle scripts: .post-install & .pre-deinstall
cat << 'EOF' > "$CTRL_DIR/.post-install"
#!/bin/sh
[ -x /etc/init.d/xray-proxya ] && /etc/init.d/xray-proxya enable 2>/dev/null || true
exit 0
EOF
chmod 0755 "$CTRL_DIR/.post-install"

cat << 'EOF' > "$CTRL_DIR/.pre-deinstall"
#!/bin/sh
[ -x /etc/init.d/xray-proxya ] && {
	/etc/init.d/xray-proxya stop 2>/dev/null || true
	/etc/init.d/xray-proxya disable 2>/dev/null || true
}
exit 0
EOF
chmod 0755 "$CTRL_DIR/.pre-deinstall"

# Calculate uncompressed size of regular files
SIZE_BIN=$(stat -c%s "$PKG_DIR/usr/bin/xray-proxya")
SIZE_INIT=$(stat -c%s "$PKG_DIR/etc/init.d/xray-proxya")
TOTAL_SIZE=$((SIZE_BIN + SIZE_INIT))
BUILD_DATE="${SOURCE_DATE_EPOCH:-$(date +%s)}"

# E. Metadata: .PKGINFO
cat << EOF > "$CTRL_DIR/.PKGINFO"
pkgname = ${PKGNAME}
pkgver = ${VERSION}-${RELEASE}
pkgdesc = Xray-Proxya slim proxy daemon and gateway
url = https://github.com/ailing2416/xray-proxya
builddate = ${BUILD_DATE}
packager = xray-proxya
size = ${TOTAL_SIZE}
arch = ${ARCH}
origin = ${PKGNAME}
license = GPL-3.0
EOF

# 5. Packaging Engines Implementation

pack_container() {
    local engine="$1"
    echo -e "🐳 Packaging using container ($engine + abuild-tar)..."
    "$engine" run --pids-limit=-1 --rm -v "$STAGING_DIR:/workspace:Z" alpine:3.21 sh -c '
        set -e
        if ! command -v abuild-tar >/dev/null 2>&1; then
            apk add --no-cache abuild pigz >/dev/null 2>&1
        fi
        gzip_cmd=$(command -v pigz || echo gzip)

        cd /workspace/pkg
        find * -print0 | LC_ALL=C sort -z | \
            tar --format=posix --no-recursion --null -T - -cf - --owner=0 --group=0 --numeric-owner | \
            abuild-tar --hash | $gzip_cmd -9 -n > /workspace/data.tar.gz

        datahash=$(sha256sum /workspace/data.tar.gz | cut -d" " -f1)
        echo "datahash = $datahash" >> /workspace/ctrl/.PKGINFO

        cd /workspace/ctrl
        tar --format=posix -cf - --owner=0 --group=0 --numeric-owner .PKGINFO .post-install .pre-deinstall | \
            abuild-tar --cut | $gzip_cmd -9 -n > /workspace/control.tar.gz

        cat /workspace/control.tar.gz /workspace/data.tar.gz > /workspace/package.apk
    '
    mv "$STAGING_DIR/package.apk" "$FINAL_APK"
}

pack_native() {
    echo -e "⚡ Packaging using native abuild-tar..."
    local gzip_cmd
    gzip_cmd=$(command -v pigz || echo gzip)

    (
        cd "$PKG_DIR"
        find * -print0 | LC_ALL=C sort -z | \
            tar --format=posix --no-recursion --null -T - -cf - --owner=0 --group=0 --numeric-owner | \
            abuild-tar --hash | "$gzip_cmd" -9 -n > "$STAGING_DIR/data.tar.gz"
    )

    local datahash
    datahash=$(sha256sum "$STAGING_DIR/data.tar.gz" | cut -d" " -f1)
    echo "datahash = $datahash" >> "$CTRL_DIR/.PKGINFO"

    (
        cd "$CTRL_DIR"
        tar --format=posix -cf - --owner=0 --group=0 --numeric-owner .PKGINFO .post-install .pre-deinstall | \
            abuild-tar --cut | "$gzip_cmd" -9 -n > "$STAGING_DIR/control.tar.gz"
    )

    cat "$STAGING_DIR/control.tar.gz" "$STAGING_DIR/data.tar.gz" > "$FINAL_APK"
}

pack_python() {
    echo -e "🐍 Packaging using portable Python 3 generator (with embedded SHA1 PAX headers)..."
    python3 - << 'PYEOF' "$PKG_DIR" "$CTRL_DIR" "$FINAL_APK"
import os, sys, tarfile, io, hashlib, gzip

pkg_dir = sys.argv[1]
ctrl_dir = sys.argv[2]
out_apk = sys.argv[3]

# 1. Build data.tar.gz
data_tar_io = io.BytesIO()
with tarfile.open(fileobj=data_tar_io, mode="w", format=tarfile.PAX_FORMAT) as tar:
    for root, dirs, files in os.walk(pkg_dir):
        dirs.sort()
        files.sort()
        rel_root = os.path.relpath(root, pkg_dir)
        if rel_root != ".":
            ti = tarfile.TarInfo(name=rel_root)
            st = os.stat(root)
            ti.mode = st.st_mode
            ti.type = tarfile.DIRTYPE
            ti.mtime = 0
            ti.uname = "root"
            ti.gname = "root"
            tar.addfile(ti)

        for name in files:
            rel_path = os.path.normpath(os.path.join(rel_root, name)) if rel_root != "." else name
            full_path = os.path.join(root, name)
            if os.path.islink(full_path):
                target = os.readlink(full_path)
                ti = tarfile.TarInfo(name=rel_path)
                ti.type = tarfile.SYMTYPE
                ti.linkname = target
                ti.mode = 0o777
                ti.mtime = 0
                ti.uname = "root"
                ti.gname = "root"
                ti.pax_headers = {"APK-TOOLS.checksum.SHA1": hashlib.sha1(target.encode("utf-8")).hexdigest()}
                tar.addfile(ti)
            else:
                st = os.stat(full_path)
                with open(full_path, "rb") as f:
                    data = f.read()
                ti = tarfile.TarInfo(name=rel_path)
                ti.size = len(data)
                ti.mode = st.st_mode
                ti.type = tarfile.REGTYPE
                ti.mtime = 0
                ti.uname = "root"
                ti.gname = "root"
                ti.pax_headers = {"APK-TOOLS.checksum.SHA1": hashlib.sha1(data).hexdigest()}
                tar.addfile(ti, io.BytesIO(data))

data_tar_bytes = data_tar_io.getvalue()
data_tar_gz = gzip.compress(data_tar_bytes, mtime=0)
datahash = hashlib.sha256(data_tar_gz).hexdigest()

# 2. Update .PKGINFO with datahash
pkginfo_path = os.path.join(ctrl_dir, ".PKGINFO")
with open(pkginfo_path, "r", encoding="utf-8") as f:
    pkginfo_text = f.read()
lines = [l for l in pkginfo_text.splitlines() if not l.startswith("datahash")]
lines.append(f"datahash = {datahash}")
pkginfo_text = "\n".join(lines) + "\n"

# 3. Build control.tar.gz (with trailing EOF blocks stripped like abuild-tar --cut)
ctrl_tar_io = io.BytesIO()
with tarfile.open(fileobj=ctrl_tar_io, mode="w", format=tarfile.PAX_FORMAT) as tar:
    ti = tarfile.TarInfo(name=".PKGINFO")
    raw = pkginfo_text.encode("utf-8")
    ti.size = len(raw)
    ti.mode = 0o644
    ti.mtime = 0
    ti.uname = "root"
    ti.gname = "root"
    tar.addfile(ti, io.BytesIO(raw))

    for script in [".post-install", ".pre-deinstall"]:
        p = os.path.join(ctrl_dir, script)
        if os.path.exists(p):
            with open(p, "rb") as f:
                sdata = f.read()
            ti = tarfile.TarInfo(name=script)
            ti.size = len(sdata)
            ti.mode = 0o755
            ti.mtime = 0
            ti.uname = "root"
            ti.gname = "root"
            tar.addfile(ti, io.BytesIO(sdata))

ctrl_tar_bytes = ctrl_tar_io.getvalue()
while ctrl_tar_bytes.endswith(b"\x00" * 512):
    ctrl_tar_bytes = ctrl_tar_bytes[:-512]
ctrl_tar_gz = gzip.compress(ctrl_tar_bytes, mtime=0)

# 4. Concatenate control.tar.gz and data.tar.gz into APK v2
os.makedirs(os.path.dirname(os.path.abspath(out_apk)), exist_ok=True)
with open(out_apk, "wb") as f:
    f.write(ctrl_tar_gz)
    f.write(data_tar_gz)
PYEOF
}

pack_shell_fallback() {
    echo -e "⚠️ Packaging using standard shell tar+gzip fallback..."
    local gzip_cmd
    gzip_cmd=$(command -v pigz || echo gzip)

    (
        cd "$PKG_DIR"
        find * -print0 | LC_ALL=C sort -z | \
            tar --format=posix --no-recursion --null -T - -cf - --owner=0 --group=0 --numeric-owner | \
            "$gzip_cmd" -9 -n > "$STAGING_DIR/data.tar.gz"
    )

    local datahash
    datahash=$(sha256sum "$STAGING_DIR/data.tar.gz" | cut -d" " -f1)
    echo "datahash = $datahash" >> "$CTRL_DIR/.PKGINFO"

    (
        cd "$CTRL_DIR"
        tar --format=posix -cf - --owner=0 --group=0 --numeric-owner .PKGINFO .post-install .pre-deinstall | \
            "$gzip_cmd" -9 -n > "$STAGING_DIR/control.tar.gz"
    )

    cat "$STAGING_DIR/control.tar.gz" "$STAGING_DIR/data.tar.gz" > "$FINAL_APK"
}

# 6. Execute Packaging Engine based on MODE & Detection
CONTAINER_BIN=""
if command -v podman >/dev/null 2>&1; then
    CONTAINER_BIN="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_BIN="docker"
fi

PACK_SUCCESS=false

case "$MODE" in
    container)
        if [ -n "$CONTAINER_BIN" ]; then
            pack_container "$CONTAINER_BIN"
            PACK_SUCCESS=true
        else
            echo -e "${RED}❌ Container mode requested but neither podman nor docker found.${NC}" >&2
            exit 1
        fi
        ;;
    native)
        if command -v abuild-tar >/dev/null 2>&1; then
            pack_native
            PACK_SUCCESS=true
        else
            echo -e "${RED}❌ Native mode requested but abuild-tar not found in PATH.${NC}" >&2
            exit 1
        fi
        ;;
    fallback)
        if command -v python3 >/dev/null 2>&1; then
            pack_python
            PACK_SUCCESS=true
        else
            pack_shell_fallback
            PACK_SUCCESS=true
        fi
        ;;
    auto|*)
        if command -v abuild-tar >/dev/null 2>&1; then
            pack_native && PACK_SUCCESS=true
        elif [ -n "$CONTAINER_BIN" ]; then
            if pack_container "$CONTAINER_BIN"; then
                PACK_SUCCESS=true
            else
                echo -e "${YELLOW}⚠️ Container build failed; falling back to portable engine...${NC}"
            fi
        fi

        if [ "$PACK_SUCCESS" = false ]; then
            if command -v python3 >/dev/null 2>&1; then
                pack_python && PACK_SUCCESS=true
            else
                pack_shell_fallback && PACK_SUCCESS=true
            fi
        fi
        ;;
esac

if [ "$PACK_SUCCESS" != true ] || [ ! -s "$FINAL_APK" ]; then
    echo -e "${RED}❌ Packaging failed: $FINAL_APK was not created.${NC}" >&2
    exit 1
fi

echo -e "${GREEN}✅ Successfully generated OpenWrt APK:${NC} $FINAL_APK"
echo -e "📊 Size: $(ls -lh "$FINAL_APK" | awk '{print $5}')"
echo -e "📝 Contents:"
tar -ztvf "$FINAL_APK" | awk '{print "   " $1 " " $6 " " $7 " " $8 " " $9}'

# 7. Optional Verification (--verify)
if [ "$VERIFY" = true ]; then
    if [ -n "$CONTAINER_BIN" ]; then
        echo -e "\n${BLUE}🧪 Verifying package installation in alpine:3.21 (${CONTAINER_BIN})...${NC}"
        CONTAINER_DIR="$(dirname "$FINAL_APK")"
        CONTAINER_FILE="$(basename "$FINAL_APK")"
        "$CONTAINER_BIN" run --pids-limit=-1 --rm -v "$CONTAINER_DIR:/workspace:Z" alpine:3.21 sh -c "
            set -e
            echo '1. Testing apk add...'
            apk add --allow-untrusted -v '/workspace/$CONTAINER_FILE'
            echo '2. Verifying xray-proxya binary...'
            /usr/bin/xray-proxya version
            echo '3. Verifying pathd multi-call symlink...'
            /usr/bin/pathd serve --help || true
            echo '4. Verifying procd service script...'
            [ -x /etc/init.d/xray-proxya ] && echo 'Init script /etc/init.d/xray-proxya is executable'
            echo '5. Testing clean apk del...'
            apk del $PKGNAME
            echo '✅ Package verification PASSED!'
        "
    else
        echo -e "${YELLOW}⚠️ Cannot verify: neither podman nor docker available.${NC}"
    fi
fi
