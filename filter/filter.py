import tracer
import sys
import os
def sort_out(input_list,dire, qemu_path):
    if len(input_list) == 0:
        input_elem = None
    else:
        input_elem = input_list.pop(0)
        #print(input_elem)
    if input_elem != None:
        
        input_path = dire + input_elem
        #print("processing {}".format(input_path))
        patch_elem = dire + input_elem + '.patch'
        patch_size = int(os.path.getsize(patch_elem) / 8)
        #print(patch_elem)
        
        patches = []
        with open(input_path,'rb') as f_input, open(patch_elem,'rb') as f_patch,  open(input_path,'rb') as f_input:
            for i in range(patch_size):
                patches.append(int.from_bytes(f_patch.read(8),byteorder="little"))
            input_data = f_input.read()
            r = tracer.qemu_runner.QEMURunner(binary, bytes(input_data), 
                                              qemu=qemu_path ,argv=['-P', patch_elem, binary, '-d'],)
            patch_order = []
            for trace in r.trace:
                if trace in patches and trace not in patch_order:
                    patch_order.append(trace)
            #Here we got a list of occurence order of patched points
            #Now we eliminate patches that are not needed!
            tmp_patches = "/tmp/patch_tmp"
            for patch in patch_order:
                with open(tmp_patches, 'wb') as t_p:
                    for tmp_patch in patch_order:
                        if tmp_patch != patch:
                            t_p.write(tmp_patch.to_bytes(8, 'little'))
                r = tracer.qemu_runner.QEMURunner(binary, bytes(input_data), 
                                              qemu=qemu_path ,argv=['-P', tmp_patches, binary],)
                if r.crash_addr !=None:
                    patch_order.remove(patch)
            with open(tmp_patches, 'wb') as t_p:
                    for tmp_patch in patch_order:
                            t_p.write(tmp_patch.to_bytes(8, 'little'))
            patch_route = dire + input_elem + '.patch_route'
            
            r = tracer.qemu_runner.QEMURunner(binary, bytes(input_data), 
                                              qemu=qemu_path ,argv=['-P', tmp_patches, binary],)
            
            if 0x0804d0d0 in r.trace:
                print("Found!")
                print(input_elem)
            # with open("trace.txt",'w') as fo:
            #     for trace in r.trace:
            #         fo.write(hex(trace))
            #         fo.write('\n')
            #breakpoint()
            with open(patch_route,"w") as f_route:
                #print("f_route:")
                f_route.write("f_route:\n")
                for trace in r.trace:
                    if trace in patches:
                        #print("[ {} ] ->\n".format(hex(trace)))
                        f_route.write("[ {} ] ->\n".format(hex(trace)))
        processed_list.append(input_elem)
if len(sys.argv) != 4:
    print("Error: Please Give The correct arguments!")
    print("If you don't know what arguments to give, consult the run_symbolic.sh script!")
    exit(0)
binary = sys.argv[1]
output_dir = sys.argv[2] + '/afl-master'
path_to_qemu = sys.argv[3]
if not os.access(output_dir, mode=os.F_OK):
    print("afl-master dir not found , please consult run.sh script in the fuzzer's root dir!")
    exit(-1)
crash_dir = output_dir + '/crashes/'
hangs_dir = output_dir + '/hangs/'
crash_input_list = []
hangs_input_list = []
processed_list = []

while True:
    crash_arr = os.listdir(crash_dir)
    hangs_arr = os.listdir(hangs_dir)
    
    for elem in crash_arr:
        if (not elem.startswith('id')) or elem.endswith('.patch') or elem.endswith('.edge') or elem.endswith('.patch_route'): 
            continue
        if elem not in crash_input_list and elem not in processed_list:
            crash_input_list.append(elem)
    for elem in hangs_arr:
        if (not elem.startswith('id')) or elem.endswith('.patch') or elem.endswith('.edge') or elem.endswith('.patch_route'): 
            continue
        if elem not in hangs_input_list and elem not in processed_list:
            hangs_input_list.append(elem)
    #qemu_path = sys.argv[]
    #qemu_path = '/root/tools/shellphish-qemu-linux/build/i386-linux-user/qemu-i386'
    
    sort_out(crash_input_list, crash_dir, path_to_qemu)
    
    #sort_out(hangs_input_list, hangs_dir, path_to_qemu)
    
    