#!/bin/bash

# format_number() {
#     num=$1
#     if ((num >= 1000000)); then
#         printf "%.0f%s\n" $(echo "scale=2; $num / 1000000" | bc) "m"
#     elif ((num >= 1000)); then
#         printf "%.0f%s\n" $(echo "scale=2; $num / 1000" | bc) "k"
#     else
#         echo "$num"
#     fi
# }

build() {
  compiler="$1"
  base="$2"
  shift 2
  extra_cflags=("$@")

  sizes=("100000" "200000" "500000" "1000000" "2000000" "5000000" "10000000")

  for size in "${sizes[@]}"; do
    $compiler container.c -Os -DCODE_SIZE=$size -o "bin/${base}_${size}" "${extra_cflags[@]}"
  done
}


mkdir -p bin
rm -f bin/* bin.zip || true


build clang mac_amd64 -arch x86_64
strip bin/mac_amd64_*
codesign --remove-signature bin/mac_amd64_*

build clang mac_arm64 -arch arm64
strip bin/mac_arm64_*
codesign --remove-signature bin/mac_arm64_*

build aarch64-linux-musl-gcc linux_arm64 -static
aarch64-linux-musl-strip bin/linux_arm64_*

build x86_64-linux-musl-gcc linux_amd64 -static
x86_64-linux-musl-strip bin/linux_amd64_*

build x86_64-w64-mingw32-gcc windows_amd64 -Wl,--image-base -Wl,0x10000000
x86_64-w64-mingw32-strip bin/windows_amd64_*


find bin -type f -exec sh -c 'printf "$0:\t" ; strings -a -t x "$0" | grep -w CODE_START | cut -d" " -f1' {} \; | sort

zip -jqr9 bin.zip bin
xxd -i bin.zip > bin.zip.h

echo -e "\n\nZip size: $(du -h bin.zip | cut -f1)"
