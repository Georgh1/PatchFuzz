if [ $# -ne 3 ]; then
    echo "Usage : <path/to/this/script> <TARGET_BINARY> <OUTPUT_DIR> <CUSTOMIZED_QEMU_ROOT_DIR>"
    echo "      <TARGET_BINARY>:The binray to be analyzed"
    echo "      <OUTPUT_DIR>:The directory where afl save the results"
    echo "      <CUSTOMIZED_QEMU_ROOT_DIR>:The directory where you build the customized qemu"
    echo "      example: ./run_filter.sh /root/cb-multios/build/challenges/FASTLANE/FASTLANE /root/workdir/output /root/tools/shellphish-qemu-linux/build/i386-linux-user/qemu-i386"
    exit
fi

FILE=filter/filter.py
if [ ! -f "$FILE" ]; then
    echo "$FILE does not exists."
    exit
fi
echo "Please note this script is for little endian host, for Big Endian host, please change"
echo "              int.from_bytes(......,byteorder='little') "
echo "                                              To"
echo "              int.from_bytes(......,byteorder='big') "
echo ""
export TARGET=$1
export OUTPUT=$2
export QEMU=$3
python3 $FILE $TARGET $OUTPUT $QEMU
