#!/usr/bin/python3
import sys
if len(sys.argv) != 4:
  print("./bitmap_test.sh TARGET_PATH prev_loc cur_loc")
  exit(0)
# Open the binary file in read mode
with open(sys.argv[1]+'/'+'fuzz_bitmap', 'rb') as file:
    # Read the entire content of the file
    file_content = file.read()# Convert the binary content to a list
    byte_list =list(file_content)
    cur_loc = int(sys.argv[2],16)
    cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8)
    cur_loc &= (1 << 16) - 1
    prev_loc = cur_loc >> 1
    cur_loc = int(sys.argv[3],16)
    cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8)
    cur_loc &= (1 << 16) - 1
    print(byte_list[cur_loc ^ prev_loc])
    if int(byte_list[cur_loc ^ prev_loc]) == 0xff:
       print('untouched')
    else:
       print('touched')
