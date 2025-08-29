#!/usr/bin/python3
import sys
import struct
import os
def get_file_patches(patch_file):
    data_list = []
    with open(patch_file + '.patch', 'rb') as file:
      data = file.read(8)
      while data:
        value = struct.unpack('<q', data)[0]
        data_list.append(value)
        data = file.read(8)
    return data_list

def write_dummy(data_list):

    with open('dummy', 'wb') as file:
        for number in data_list:
            file.write(number.to_bytes(8, byteorder='little'))
#TestCase refers to the crash file 
if len(sys.argv) != 3:
  print("./advanced_testone.sh EXECUTABLE TESTCASE")
  exit(0)
print('Currently testing:')
patches = get_file_patches(sys.argv[2])
for i in range(len(patches)):
    print(f'{i}): {hex(patches[i])}')
# 从键盘读取输入的用逗号隔开的数字
input_string = input("请输入用逗号隔开的数字(N不去掉patch):")
if input_string.lower() not in ['n']:
    # 去除空格，然后分割字符串
    numbers = input_string.replace(" ", "").split(",")

    numbers = sorted(numbers, reverse=True)

    # 将字符串转换为整数并打印
    for number in numbers:
        del patches[int(number)]

print('Currently testing:')
for i in range(len(patches)):
    print(f'{i}): {hex(patches[i])}')
write_dummy(patches)
os.system(f"cat {sys.argv[2]} | ./shellphish-qemu-linux/build/x86_64-linux-user/qemu-x86_64  -P dummy -g 23456 {sys.argv[1]}")
