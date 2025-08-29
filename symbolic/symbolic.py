from qsym import executor, minimizer
import os
import sys
import shutil
import random
import struct


def get_testcases(path_dir):
    for name in sorted(os.listdir(path_dir)):
        if name == "stat":
            continue
        if name == "pin.log":
            continue
        path = os.path.join(path_dir, name)
        yield path

def gen_queue_elem(testcase_file, patches, patch_edges, patch_qemu):
    with open(testcase_file + '.patch', 'wb') as f_patch, open(testcase_file + '.edge', 'wb') as f_edge, open(testcase_file + '.qemu', 'wb') as f_qemu:
        for i in range(0, len(patches)):
            chunk = struct.pack('<q', patches[i])
            f_patch.write(chunk)
            chunk = struct.pack('<q', patch_edges[i])
            f_edge.write(chunk)
            chunk = struct.pack('<q', patch_qemu[i])
            f_qemu.write(chunk)



def go_symbolic(input_list , dire, cmd, on_queue=False):
    
    if len(input_list) == 0:
        input_elem = None
    else:
        input_elem = input_list.pop(random.randrange(len(input_list)))
    if input_elem != None:
        
        input_path = dire + input_elem
        print("\033[32mProcessing {0}\033[0m".format(input_path))
        #print("processing {}".format(input_path))
        edge_elem = dire + input_elem + '.edge'
        edge_size = int(os.path.getsize(edge_elem) / 8)

        # if edge_size==0:
        #     shutil.copy(input_path,candidate_crash_path + "/id:%06d" % (len(os.listdir(candidate_crash_path))) )
        #     processed_list.append(input_elem)
        #     return

        if on_queue==False and edge_size==0:
            print("\033[1;31mNo Patch here, Maybe Crash Is Found!\033[m")
            shutil.copy(input_path,real_crash_path + "/id:%06d" % (len(os.listdir(real_crash_path))) )
            processed_list.append(input_elem)
            return

        if on_queue==True and edge_size==0:
            processed_list.append(input_elem)
            return
        patch_elem = dire + input_elem + '.patch'
        patch_size = int(os.path.getsize(patch_elem) / 8)
        qemu_elem = dire + input_elem + '.qemu'
        qemu_size = int(os.path.getsize(qemu_elem) / 8)
        
        #print(patch_elem)
        fuzz_bitmap_path_tmp = fuzz_bitmap_path + '.tmp' 
        
        patches = []
        patch_edges = []
        patch_qemu = []
        with open(patch_elem,'rb') as f_patch, open(fuzz_bitmap_path,'rb') as f_bitmap,open(edge_elem,'rb') as f_edge, open(qemu_elem,'rb') as f_qemu:
            for i in range(patch_size):
                patches.append(struct.unpack('<Q',f_patch.read(8))[0])
            for i in range(qemu_size):
                patch_qemu.append(struct.unpack('<Q',f_qemu.read(8))[0])    
            #print(patch_size)
            #print(patches)
            print("Patches are: ")
            for patch in patches:
                            print(hex(patch))
            cfuzz_bitmap = bytearray(f_bitmap.read())
            while edge_size > 0:
                #Note here, Most linux should be little endian, but for big endian ,please change the
                #byteorder='little' to byteorder='big'
                index = struct.unpack('<Q',f_edge.read(8))[0]
                #print(hex(index))
                #We set the patched edge to be 'unexplored(0xFF)'
                cfuzz_bitmap[index] = 0xFF
                patch_edges.append(index)
                edge_size -= 1
                
            with open(fuzz_bitmap_path_tmp,'wb') as f_tmp:
                f_tmp.write(bytes(cfuzz_bitmap))
            q = executor.Executor(cmd, input_path, 
                                  afl_slave, bitmap=fuzz_bitmap_path_tmp, argv=["-l", "1"])
            ret = q.run(90)
            print("Total=%d s, Emulation=%d s, Solver=%d s, Return=%d"
                     % (ret.total_time,
                        ret.emulation_time,
                        ret.solving_time,
                        ret.returncode))
            testcases = get_testcases(qsym_last)
            # testcases = list(testcases)
            # print('\033[32mGenerated {0} testcases\033[0m'.format(len(testcases)))
            for testcase in testcases:
                
                #packaged_minimizer.bitmap = cfuzz_bitmap
                if not packaged_minimizer.check_testcase(testcase):
                    #os.unlink(testcase)
                    continue
                else:
                    filename = os.path.join(
                        qsym_queue,
                        "id:%06d" % (len(os.listdir(qsym_queue))/4))
                    shutil.move(testcase, filename)
                    
                    bitmap = minimizer.read_bitmap_file(packaged_minimizer.temp_file)
                    
                    if os.path.exists(packaged_minimizer.crash_bitmap_file):
                        os.remove(packaged_minimizer.crash_bitmap_file)
                        
                        print("\033[1;31mCrash Is Found!\033[m")
                        shutil.copy(filename,real_crash_path + "/id:%06d" % (len(os.listdir(real_crash_path))) )
                        null_patches = []
                        null_edges = []
                        null_qemu = []
                        gen_queue_elem(filename, null_patches, null_edges, null_qemu)
                    else:
                        patch_solved = False
                        for patch_edge in patch_edges:
                            if bitmap[patch_edge]  != 0:
                                
                                index = patch_edges.index(patch_edge)
                                patch_edges.pop(index)
                                patches.pop(index)
                                patch_qemu.pop(index)
                                print("\033[1;34mOne patch solved\033[m")
                                patch_solved = True
                        if len(patches) == 0:
                            print("\033[1;31mNo patch left! maybe a crash!\033[m")
                            shutil.copy(filename,candidate_crash_path + "/id:%06d" % (len(os.listdir(candidate_crash_path))) )
                            gen_queue_elem(filename, patches, patch_edges, patch_qemu)

                        elif patch_solved == True:
                            print("\033[1;34mGenerating queue element!\033[m")
                            gen_queue_elem(filename, patches, patch_edges, patch_qemu)
                        elif patch_solved == False:
                            null_patches = []
                            null_edges = []
                            null_qemu = []
                            print("\033[1;34mGenerating queue element! This is a non-related edge\033[m")
                            gen_queue_elem(filename, null_patches, null_edges, null_qemu)

                        else:
                            os.remove(filename)
                        
                        

                    

            
        processed_list.append(input_elem)
    


if len(sys.argv) != 3:
    print("Error: Please Give correct arguments!")
    print("If you don't know what arguments to give, consult the run_symbolic.sh script!")
    exit(0)

binary = sys.argv[1]
afl_slave = sys.argv[2] + '/afl-slave'
sync_queue = afl_slave + '/queue/'
output_dir = sys.argv[2] + '/afl-master'

if not os.access(output_dir, os.F_OK):
    print("afl-master dir not found , please consult run.sh script in the fuzzer's root dir!")
    exit(-1)

if os.access(afl_slave, os.F_OK):
    shutil.rmtree(afl_slave, ignore_errors=True)
os.mkdir(afl_slave)
if os.access(sync_queue, os.F_OK):
    shutil.rmtree(sync_queue, ignore_errors=True)
os.mkdir(sync_queue)

crash_dir = output_dir + '/crashes/'
hangs_dir = output_dir + '/hangs/'
queue_for_me_dir = output_dir + '/queue_for_sym/'
fuzz_bitmap_path = output_dir + '/fuzz_bitmap'
qsym_last = afl_slave + '/qsym-last/'
qsym_queue = afl_slave + '/queue/'


real_crash_path = output_dir + '/real_crash/'
if os.access(real_crash_path, os.F_OK):
    shutil.rmtree(real_crash_path, ignore_errors=True)
os.mkdir(real_crash_path)

candidate_crash_path = output_dir + '/candidate_crash/'
if os.access(candidate_crash_path, os.F_OK):
    shutil.rmtree(candidate_crash_path, ignore_errors=True)
os.mkdir(candidate_crash_path)

cmd = [binary]
#cmd = [binary, '-1', '@@', '-o', '/tmp/1']

packaged_minimizer = minimizer.TestcaseMinimizer(cmd, os.getcwd(), output_dir, True)

crash_input_list = []
hangs_input_list = []
queue_input_list = []
processed_list = []

while True:
    crash_arr = os.listdir(crash_dir)
    hangs_arr = os.listdir(hangs_dir)
    queue_arr = os.listdir(qsym_queue)
    
    for elem in crash_arr:
        if (not elem.startswith('id')) or elem.endswith('.patch') or elem.endswith('.edge') or elem.endswith('.qemu'): 
            continue
        if elem not in crash_input_list and elem not in processed_list:
            crash_input_list.append(elem)
    for elem in hangs_arr:
        if (not elem.startswith('id')) or elem.endswith('.patch') or elem.endswith('.edge') or elem.endswith('.qemu'): 
            continue
        if elem not in hangs_input_list and elem not in processed_list:
            hangs_input_list.append(elem)
    for elem in queue_arr:
        if (not elem.startswith('id')) or elem.endswith('.patch') or elem.endswith('.edge') or elem.endswith('.qemu'): 
            continue
        if elem not in queue_input_list and elem not in processed_list:
            queue_input_list.append(elem)
    #qemu_path = sys.argv[]
    #qemu_path = '/root/tools/shellphish-qemu-linux/build/i386-linux-user/qemu-i386'
    
    go_symbolic(crash_input_list, crash_dir, cmd)
    
    if len(crash_input_list)==0:
        go_symbolic(hangs_input_list, hangs_dir, cmd)

    go_symbolic(queue_input_list, qsym_queue, cmd, on_queue=True)
    #go_symbolic_on_queue(path_to_qemu)
    
    