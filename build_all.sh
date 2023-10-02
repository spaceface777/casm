#!/bin/bash

set -e

sizes=("100000" "200000" "500000" "1000000" "2000000" "5000000" "10000000")

mkdir -p bin
rm -f bin/* bin.zip bin.zip.h || true

for size in "${sizes[@]}"; do
  x86_64-elf-gcc container.c -Os -DCODE_SIZE=$size -o "bin/amd64_${size}.com.dbg" "${extra_cflags[@]}"  -g -static -nostdlib -nostdinc -fno-pie -no-pie -mno-red-zone -gdwarf-4 -fno-omit-frame-pointer -pg -mnop-mcount -mno-tls-direct-seg-refs -fuse-ld=bfd -Wl,-T,thirdparty/cosmopolitan/ape.lds -Wl,--gc-sections -z noexecstack -include thirdparty/cosmopolitan/cosmopolitan.h thirdparty/cosmopolitan/crt.o thirdparty/cosmopolitan/ape-no-modify-self.o thirdparty/cosmopolitan/cosmopolitan.a
  x86_64-elf-objcopy -S -O binary "bin/amd64_${size}.com.dbg" "bin/amd64_${size}.com"
  rm -f "bin/amd64_${size}.com.dbg"
done

find bin -type f -exec sh -c 'printf "$0:\t" ; strings -a -t x "$0" | grep -w CODE_START | cut -d" " -f1' {} \; | sort

zip -jqr9 bin.zip bin
xxd -i bin.zip > bin.zip.h

echo -e "\n\nZip size: $(du -h bin.zip | cut -f1)"
