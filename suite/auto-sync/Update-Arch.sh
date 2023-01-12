#!/bin/sh

check_llvm() {
  llvm_root=$1
  tblgen=$2

  if [ ! -e "../vendor/llvm_root" ]; then
    echo "[*] Create symlink '../vendor/llvm_root -> $llvm_root'."
    ln -s "$llvm_root" ../vendor/llvm_root
  fi

  if [ ! -f $tblgen ]; then
    echo "[x] llvm-tblgen not found at '$tblgen'"
    exit
  fi
}

setup_build_dir() {
  llvm_inc_dir="llvm_inc"
  if [ ! -d "$llvm_inc_dir" ]; then
    echo "[*] Create ./$llvm_inc_dir directory"
    mkdir $llvm_inc_dir
  fi  

  cs_inc_dir="cs_inc"
  if [ ! -d "$cs_inc_dir" ]; then
    echo "[*] Create ./$cs_inc_dir directory"
    mkdir $cs_inc_dir
  fi

  translator_dir="trans_out"
  if [ ! -d "$translator_dir" ]; then
    echo "[*] Create ./$translator_dir directory"
    mkdir $translator_dir
  fi

  ts_so_dir="ts_libs"
  if [ ! -d "$ts_so_dir" ]; then
    echo "[*] Create ./$ts_so_dir directory"
    mkdir $ts_so_dir
  fi  
}

#
# Main
#

supported="ARM"

if [ $# -ne 2 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
  echo "$0 <arch> <path-llvm-project>"
  echo "\nCurrently supported architectures: $supported"
  exit
fi

arch="$1"
llvm_root="$2"
tblgen="$llvm_root/build/bin/llvm-tblgen"
llvm_target_dir="$1"

if ! echo $supported | grep -q -w "$arch" ; then
  echo "[x] $arch is not supported by the updater. Supported are: $supported"
  exit
fi

if [ $arch = "PPC" ]; then
  llvm_target_dir="PowerPC"
fi

setup_build_dir
check_llvm $llvm_root $tblgen

echo "[*] Generate disassembler..."
$tblgen --printerLang=CCS --gen-disassembler -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > "cs_inc/"$arch"GenDisassemblerTables.inc"
$tblgen --printerLang=C++ --gen-disassembler -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > "llvm_inc/"$arch"GenDisassemblerTables.inc"

echo "[*] Generate AsmWriter..."
$tblgen --printerLang=CCS --gen-asm-writer -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > "cs_inc/"$arch"GenAsmWriter.inc"
$tblgen --printerLang=C++ --gen-asm-writer -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > "llvm_inc/"$arch"GenAsmWriter.inc"

echo "[*] Generate RegisterInfo tables..."
$tblgen --printerLang=CCS --gen-register-info -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > "cs_inc/"$arch"GenRegisterInfo.inc"

# Todo run Subtarget feature

echo "[*] Generate Mapping tables..."
$tblgen --printerLang=CCS --gen-asm-matcher -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td"

echo "[*] Translate LLVM source files..."
cd ../CppTranslator/
. ./.venv/bin/activate
./CppTranslator.py -a "$arch" -g "../vendor/tree-sitter-cpp/" -l "../build/ts_libs/ts-cpp.so"
cd ../build

cs_root=$(git rev-parse --show-toplevel)
cs_arch_dir="$cs_root/arch/$arch/"
echo "[*] Copy files to $cs_arch_dir"
cp cs_inc/$arch* $cs_arch_dir
cp trans_out/$arch* $cs_arch_dir
cp $arch*.inc $cs_arch_dir 

# Give advice how to fix the translated C++ files.
