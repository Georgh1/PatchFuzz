if [ $# -ne 4 ]; then
    echo "Usage : <path/to/this/script> <AFL-ROOT> <INPUT_DIR> <OUTPUT_DIR> <AFL_CMDLINE>"
    echo "      <AFL-ROOT>:The directory where you compiled AFL into, \'afl-fuzz\' and \'afl-qemu-trace\'must be found in this directory!"
    echo "      <INPUT_DIR>:The directory where seeds you provide should reside"
    echo "      <OUTPUT_DIR>:The directory to save the results of fuzzing"
    echo "      <AFL_CMDLINE>:The target binary you wish to fuzz"
    echo "      example: ./run.sh $PWD /root/workdir/input /root/workdir/output /path/to/tested-binary "
    echo "      For some cases You might need to modify this script, Edit the exact arguments passed "
    exit
fi

echo "If this is a dynamically linked program, please rebase the program in ghidra/ghidra_analyze.py first"
echo "By providing the base address!"
echo "One way you can do this is by running"
echo "      ./afl-qemu-trace -d in_asm -D log.txt  target_binary"
echo "And calculate the base_addr qemu applied by looking at the log.txt to see how the block is organized"
echo "And Don't forget to run the symbolic process using run_symbolic.sh in another shell"

export AFL_ROOT=$1
export INPUT=$2
export OUTPUT=$3
export AFL_CMDLINE=$4
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# TODO: Edit here!
$AFL_ROOT/afl-fuzz  -m none   -M afl-master  -i $INPUT -o $OUTPUT  -Q  -- $AFL_CMDLINE
#$AFL_ROOT/afl-fuzz  -m none   -M afl-master  -i $INPUT -o $OUTPUT  -Q  -- $AFL_CMDLINE -c
