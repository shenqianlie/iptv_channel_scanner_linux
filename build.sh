#!/usr/bin/env bash
# 一键构建 iptvscanner 三个平台版本
#   iptvscanner-armv7   ARMv7  纯整数（HS8145X6 / Cortex-A9）
#   iptvscanner-mipsel  MIPS32r2 小端（MT7621A / MT7620）
#   iptvscanner-x86_64  x86-64（软路由 / OpenWrt x86）
# 用法：bash build.sh
set -euo pipefail

SRC="${SRC:-iptvscanner.cpp}"
TARGETS="${TARGETS:-all}"   # all | armv7 | mipsel | x86_64（可空格分隔多选）
J="$(nproc 2>/dev/null || echo 2)"
VER=1.10.4

has() {
  [ "$TARGETS" = "all" ] && return 0
  case " $TARGETS " in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

[ -f "$SRC" ] || { echo "找不到源码 $SRC"; exit 1; }

check_static() {
  file "$1" | grep -q "statically linked" || { echo "!! $1 不是静态链接，上机必报 not found"; exit 1; }
}

# ---------- 准备 libpcap 源码 ----------
if [ ! -d "libpcap-$VER" ]; then
  [ -f "libpcap-$VER.tar.gz" ] || wget -q "https://www.tcpdump.org/release/libpcap-$VER.tar.gz"
  tar -zxf "libpcap-$VER.tar.gz"
fi

# ---------- ARMv7：软浮点（纯整数指令） ----------
if has armv7; then
echo "== 编译 libpcap (armv7 soft-float) =="
rm -rf libpcap-arm
cp -a "libpcap-$VER" libpcap-arm
(
  cd libpcap-arm
  ./configure \
    --host=arm-linux-gnueabi \
    --build=x86_64-pc-linux-gnu \
    --disable-shared \
    --disable-usb \
    --disable-bluetooth \
    --disable-netmap \
    --disable-dbus \
    --disable-rdma \
    --without-libnl \
    --prefix="$PWD/install" \
    CC=arm-linux-gnueabi-gcc \
    CFLAGS="-O2 -march=armv7-a -mfloat-abi=soft"
  make -j"$J"
  make install
)

echo "== 编译 iptvscanner-armv7 =="
arm-linux-gnueabi-g++ \
  -march=armv7-a \
  -mfloat-abi=soft \
  -O2 -std=c++17 \
  -Ilibpcap-arm/install/include \
  -Llibpcap-arm/install/lib \
  "$SRC" -o iptvscanner-armv7 \
  -lpcap -lpthread -lm -static
check_static iptvscanner-armv7
fi

# ---------- MIPS：mips32r2 小端（MT7621A） ----------
if has mipsel; then
echo "== 编译 libpcap (mipsel) =="
rm -rf libpcap-mips
cp -a "libpcap-$VER" libpcap-mips
(
  cd libpcap-mips
  ./configure \
    --host=mipsel-linux-gnu \
    --build=x86_64-pc-linux-gnu \
    --disable-shared \
    --disable-usb \
    --disable-bluetooth \
    --disable-netmap \
    --disable-dbus \
    --disable-rdma \
    --without-libnl \
    --prefix="$PWD/install" \
    CC=mipsel-linux-gnu-gcc \
    CFLAGS="-O2 -march=mips32r2"
  make -j"$J"
  make install
)

echo "== 编译 iptvscanner-mipsel =="
mipsel-linux-gnu-g++ \
  -march=mips32r2 \
  -mtune=24kc \
  -O2 -std=c++17 \
  -Ilibpcap-mips/install/include \
  -Llibpcap-mips/install/lib \
  "$SRC" -o iptvscanner-mipsel \
  -lpcap -lpthread -lm -static
check_static iptvscanner-mipsel
fi

# ---------- x86_64：原生 ----------
if has x86_64; then
echo "== 编译 libpcap (x86_64) =="
rm -rf libpcap-x64
cp -a "libpcap-$VER" libpcap-x64
(
  cd libpcap-x64
  ./configure \
    --disable-shared \
    --disable-usb \
    --disable-bluetooth \
    --disable-netmap \
    --disable-dbus \
    --disable-rdma \
    --without-libnl \
    --prefix="$PWD/install"
  make -j"$J"
  make install
)

echo "== 编译 iptvscanner-x86_64 =="
g++ \
  -O2 -std=c++17 \
  -Ilibpcap-x64/install/include \
  -Llibpcap-x64/install/lib \
  "$SRC" -o iptvscanner-x86_64 \
  -lpcap -lpthread -lm -static
check_static iptvscanner-x86_64
fi

# ---------- 汇总 ----------
echo
echo "== 产物 =="
for f in iptvscanner-armv7 iptvscanner-mipsel iptvscanner-x86_64; do
  if [ -f "$f" ]; then
    ls -lh "$f"
    file "$f"
    sha256sum "$f"
  fi
done
