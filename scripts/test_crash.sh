
shopt -s extglob  # 启用扩展的globbing语法

for file in $2/!(*.txt|*.edge|*.patch|*.qemu); do
    # 在这里执行您想要对每个文件执行的操作
    echo "Processing $file"
    xxd $file.patch
    sleep 2
    cat $file |  timeout -k 3 3 /shared/shellphish-qemu-linux/build/x86_64-linux-user/qemu-x86_64 -P $file.patch -g 12345 $1
done
