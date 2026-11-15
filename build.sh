#!/usr/bin/env bash
# 一键构建 iptvscanner 三个平台版本
#   iptvscanner-armv7   ARMv7  纯整数（HS8145X6 / Cortex-A9）
#   iptvscanner-mipsel  MIPS32r2 小端（MT7621A / MT7620）
#   iptvscanner.exe     Windows x86_64（需安装 Npcap）
#   iptvscanner-aarch64 ARMv8-A aarch64（A53/A55/A72 通用）
# 用法：bash build.sh
set -euo pipefail

SRC="${SRC:-iptvscanner.cpp}"
TARGETS="${TARGETS:-all}"   # all | armv7 | mipsel | aarch64 | win（可空格分隔多选）
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

check_pe() {
  file "$1" | grep -q "PE32+" || { echo "!! $1 不是 Windows PE 程序"; exit 1; }
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

# ---------- Windows x86_64（mingw + Npcap SDK） ----------
if has win; then
echo "== 编译 iptvscanner.exe (Windows x86_64) =="
if [ ! -d npcap-sdk ]; then
  [ -f npcap-sdk.zip ] || wget -q -O npcap-sdk.zip https://npcap.com/dist/npcap-sdk-1.13.zip
  rm -rf npcap-sdk && mkdir -p npcap-sdk
  ( cd npcap-sdk && unzip -q ../npcap-sdk.zip )
fi
x86_64-w64-mingw32-g++ \
  -O2 -std=c++17 \
  -D_WIN32_WINNT=0x0600 \
  -Inpcap-sdk/Include \
  "$SRC" -o iptvscanner.exe \
  -Lnpcap-sdk/Lib/x64 -lwpcap -lPacket -lws2_32 -static
check_pe iptvscanner.exe
fi

# ---------- ARMv8-A aarch64：A53/A55/A72 通用 ----------
if has aarch64; then
echo "== 编译 libpcap (aarch64) =="
rm -rf libpcap-a64
cp -a "libpcap-$VER" libpcap-a64
(
  cd libpcap-a64
  ./configure \
    --host=aarch64-linux-gnu \
    --build=x86_64-pc-linux-gnu \
    --disable-shared \
    --disable-usb \
    --disable-bluetooth \
    --disable-netmap \
    --disable-dbus \
    --disable-rdma \
    --without-libnl \
    --prefix="$PWD/install" \
    CC=aarch64-linux-gnu-gcc \
    CFLAGS="-O2 -march=armv8-a"
  make -j"$J"
  make install
)

echo "== 编译 iptvscanner-aarch64 =="
aarch64-linux-gnu-g++ \
  -march=armv8-a \
  -O2 -std=c++17 \
  -Ilibpcap-a64/install/include \
  -Llibpcap-a64/install/lib \
  "$SRC" -o iptvscanner-aarch64 \
  -lpcap -lpthread -lm -static
check_static iptvscanner-aarch64
fi

# ---------- 汇总 ----------
echo
echo "== 产物 =="
for f in iptvscanner-armv7 iptvscanner-mipsel iptvscanner-aarch64 iptvscanner.exe; do
  if [ -f "$f" ]; then
    ls -lh "$f"
    file "$f"
    sha256sum "$f"
  fi
done
