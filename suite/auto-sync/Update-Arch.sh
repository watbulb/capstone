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


llvm_c_inc_dir="llvm_c_inc"
llvm_inc_dir="llvm_inc"
translator_dir="trans_out"
ts_so_dir="ts_libs"
diff_dir="diff_out"

setup_build_dir() {
  if [ ! -d "$llvm_inc_dir" ]; then
    echo "[*] Create ./$llvm_inc_dir directory"
    mkdir $llvm_inc_dir
  fi  

  if [ ! -d "$llvm_c_inc_dir" ]; then
    echo "[*] Create ./$llvm_c_inc_dir directory"
    mkdir $llvm_c_inc_dir
  fi

  if [ ! -d "$translator_dir" ]; then
    echo "[*] Create ./$translator_dir directory"
    mkdir $translator_dir
  fi

  if [ ! -d "$ts_so_dir" ]; then
    echo "[*] Create ./$ts_so_dir directory"
    mkdir $ts_so_dir
  fi

  if [ ! -d "$diff_dir" ]; then
    echo "[*] Create ./$diff_dir directory"
    mkdir $diff_dir
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
$tblgen --printerLang=CCS --gen-disassembler -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/"$arch"GenDisassemblerTables.inc"
$tblgen --printerLang=C++ --gen-disassembler -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_inc_dir"/"$arch"GenDisassemblerTables.inc"

echo "[*] Generate AsmWriter..."
$tblgen --printerLang=CCS --gen-asm-writer -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/"$arch"GenAsmWriter.inc"
$tblgen --printerLang=C++ --gen-asm-writer -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_inc_dir"/"$arch"GenAsmWriter.inc"

echo "[*] Generate RegisterInfo tables..."
$tblgen --printerLang=CCS --gen-register-info -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/"$arch"GenRegisterInfo.inc"

echo "[*] Generate InstrInfo tables..."
$tblgen --printerLang=CCS --gen-instr-info -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/"$arch"GenInstrInfo.inc"

echo "[*] Generate SubtargetInfo tables..."
$tblgen --printerLang=CCS --gen-subtarget -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td" > $llvm_c_inc_dir"/"$arch"GenSubtargetInfo.inc"

echo "[*] Generate Mapping tables..."
$tblgen --printerLang=CCS --gen-asm-matcher -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td"

echo "[*] Generate System Register tables..."
$tblgen --printerLang=CCS --gen-searchable-tables -I "$llvm_root/llvm/include/" -I "$llvm_root/llvm/lib/Target/$llvm_target_dir/" "$llvm_root/llvm/lib/Target/$llvm_target_dir/$arch.td"
cp __ARCH__GenCSSystemRegisterEnum.inc $arch"GenCSSystemRegisterEnum.inc"
cp __ARCH__GenSystemRegister.inc $arch"GenSystemRegister.inc"

echo "[*] Translate LLVM source files..."
cd ../CppTranslator/
. ./.venv/bin/activate
./CppTranslator.py -a "$arch" -g "../vendor/tree-sitter-cpp/" -l "../build/ts_libs/ts-cpp.so"
echo "[*] Run differ..."
./Differ.py -a "$arch" -g "../vendor/tree-sitter-cpp"
cd ../build

cs_root=$(git rev-parse --show-toplevel)
cs_arch_dir="$cs_root/arch/$arch/"
cs_inc_dir="$cs_root/include/capstone"

echo "[*] Copy files to $cs_inc_dir"

into_cs_include=$arch"GenCSInsnEnum.inc "$arch"GenCSFeatureEnum.inc "$arch"GenCSRegEnum.inc "$arch"GenCSSystemRegisterEnum.inc"
for f in $into_cs_include; do
  cp $f "$cs_inc_dir/inc"
done

echo "[*] Copy files to $cs_arch_dir"

echo $into_cs_include
for f in $(ls | grep "\.inc"); do
  # echo "$f"
  if ! echo $into_cs_include | grep -q -w $f ; then
    cp $f $cs_arch_dir
    echo "CPIED $f"
  fi
done
cp $llvm_c_inc_dir/$arch* $cs_arch_dir
cp $diff_dir/$arch* $cs_arch_dir

# Give advice how to fix the translated C++ files.
