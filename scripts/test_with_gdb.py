import gdb
import struct
import pandas as pd
import os
import sys
import time

def get_file_patches(file_num, patch_file):
    data_list = '{}  '.format(file_num)
    with open(patch_file, 'rb') as file:
      data = file.read(8)
      while data:
        value = struct.unpack('<q', data)[0]
        data_list+= hex(value) + ' '
        data = file.read(8)
    return data_list


def get_register_values():
    register_values = ''
    print('Reg:')
    registers = list(gdb.selected_frame().architecture().registers())[0:17]
    for reg in registers:
        name = reg.name
        value = gdb.selected_frame().read_register(reg)
        register_values = register_values + '{} : {}\n'.format(name, '0x' + hex(value))
    return register_values
# Read the specified crash directory
# And test the crashes one after another with test_crash.sh
directory=input('Enter the directory path: ')
files = [file for file in os.listdir(directory) if not (file.endswith('.txt') or file.endswith('.edge') or file.endswith('.patch') or file.endswith('.qemu'))]
files.sort()
file_dict={}
hijack=[]
gdb.execute('set logging overwrite on')
gdb.execute('set logging on')
# Some useful infos
print('Testing {}'.format(directory))
print('Total of {}'.format(len(files)))


for i in files:
  print("Iteration {}".format(i))
  #time.sleep(5)
  # Try to connect to the server
  try_count = 10
  while try_count > 0:
      try:
        gdb.execute('target remote 172.17.0.2:12345')
        print('Connection Successful for {}'.format(i[0:9]))
        break
      except:
          print("Cannot connect, trying:{}".format(try_count))
          try_count = try_count - 1
  if try_count == 0:
      print("Server Not Responding!")
      break
  
  # If conntected , then run the program
  gdb.execute('c')
  try:
    # If segmentation fault, we can not read the frame
    address = gdb.selected_frame().pc()
  except Exception as e:
      # If the program exits normally, then it is likely that
      # we can not read any frame
      if 'No frame is currently selected.' in str(e):
          print('Looks like the program exits normally!')
          continue
      else:
          raise(e)
  try:
    # Save the context
    disassembly = gdb.execute("x/i " + str(address), to_string=True)
  except:
      # If we cannot read the disassembly, then it is likely that
      # we have a control flow hijack
      print('Control Flow hijack detected')
      hijack.append(i)
      continue
  
  #Save context
  out_put_registers = get_register_values()
  output_backtrace = gdb.execute('backtrace',to_string=True)
  print(disassembly)
  if disassembly not in list(file_dict.keys()):
    file_dict[disassembly]=[disassembly, 1,output_backtrace,out_put_registers, 'patched']
    if os.stat(directory + i+'.patch').st_size == 0:
        # No patch needed? then true positive
        file_dict[disassembly][4] = 'True positive'
    else:
        # Else, it still need to be analyzed 
        file_dict[disassembly].append(get_file_patches(i[0:9], directory + i+'.patch'))
    print(disassembly)
    print(output_backtrace)
  else:
    if os.stat(directory + i+'.patch').st_size == 0:
        #No patch needed? then true positive
        file_dict[disassembly][4] = 'True positive'
    else:
        # Else, it still need to be analyzed
        file_dict[disassembly].append(get_file_patches(i[0:9], directory + i+'.patch'))
    file_dict[disassembly][1]=file_dict[disassembly][1] + 1
  gdb.execute('disconnect')

# Save the captured data
df = pd.DataFrame({key: pd.Series(value) for key, value in file_dict.items()})
df.to_excel('data.xlsx', index=False)

#Save hijacked instances to hijacked.txt
with open('hijacked.txt','w') as f:
    for i in hijack:
        f.write(i)

