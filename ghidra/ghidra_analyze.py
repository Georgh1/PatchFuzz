import os
import sys
import pdb
import pyhidra
pyhidra.start()
import ghidra
import jpype
from libfuncs import exclude_funcs
import ghidra.app.decompiler as decomp
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor
from ghidra.program.model.address import *


#TODO,FILL IN THE UNDESIRED FUNCTION THAT YOU DO NOT WISH TO PATCH
undesired_func = [
    #On X86_64 and i386 for example ,I do not want to mess with some elf modules
    'frame_dummy','register_tm_clones','deregister_tm_clones','_start','_init','_fini','__x86.get_pc_thunk.bx','__libc_csu_init','__libc_csu_fini','__do_global_dtors_aux', '__gmon_start__'
    , '__stack_chk_fail', '_FINI_0'
]

#TODO,FILL IN THE UNDESIRED followup functions like paths leading to __stack_chk_fail
undesired_follow_up = ['__stack_chk_fail']

filter_addr = []

def myhex(n):
    return "".join(f"{n:08x}")

def filter_code_block(block , listing, flat_api):

    block_left = block.getOut(0)
    block_right = block.getOut(1)
    #left first
    offset = block_left.getStart().getOffset()
    end = block_left.getStop().getOffset()
    while offset<=end:
        code_unit = listing.getCodeUnitAt(flat_api.toAddr(jpype.java.lang.Long(offset)))
        if code_unit is None:
             offset+=1
             continue
        offset+=code_unit.getLength()
        if "CALL" in code_unit.getMnemonicString():
            for elem in filter_addr:
                if hex(elem)[2:] in code_unit.toString():
                    return 1
    offset = block_right.getStart().getOffset()
    end = block_right.getStop().getOffset()
    while offset<=end:
        code_unit = listing.getCodeUnitAt(flat_api.toAddr(jpype.java.lang.Long(offset)))
        if code_unit is None:
             offset+=1
             continue
        offset+=code_unit.getLength()
        if "CALL" in code_unit.getMnemonicString():
            for elem in filter_addr:
                if hex(elem)[2:] in code_unit.toString():
                    return 1
    return 0
def main(binray_path:str):
    with pyhidra.open_program(binray_path) as flat_api:
        print("Opening")
        program = flat_api.getCurrentProgram()
        #If this is a dynamically linked program, please rebase the program here!
        #rebase_offset = 0x4000000000 #the base address goes here!
        rebase_offset = 0x400000
        rebase_address = flat_api.toAddr(jpype.java.lang.Long(rebase_offset))
        program.setImageBase(rebase_address, False)

        decompinterface = decomp.DecompInterface()
        decompinterface.openProgram(program)
        functions = program.getFunctionManager().getFunctions(True)
        ex_functions = program.getFunctionManager().getExternalFunctions()
        listing = program.getListing()
        lard_list = []
        fun_len = 0
        for function in list(functions):
            #breakpoint()
            fun_len += 1

        for function in list(ex_functions):
            if function.getName() in undesired_follow_up:
                filter_addr.append(function.getEntryPoint().getOffset())

        functions = program.getFunctionManager().getFunctions(True)
        fun_count = 0
        print(f"Total of {fun_len} functions")
        for function in list(functions):
            fun_count += 1 
            #print(f"{fun_count}/{fun_len} {function.getName()} analyzed")
            
            # UCT: Filters!!!
            if function.getName() in undesired_func:
             continue
            if function.getName().startswith("~") or function.getName().startswith("__gconv") or function.getName().startswith("_IO_") or function.getName().startswith("_dl_") or function.getName().startswith("__dl") \
                or function.getName().startswith("_M_") or function.getName().startswith("_S_") or function.getName().startswith("_Unwind_"):
                continue
            if function.getName() in exclude_funcs:
                continue
            if "_GLOBAL__sub" in function.getName():
                continue
            # UCT end


            results = decompinterface.decompileFunction(function, 0,ConsoleTaskMonitor())
            #print("Decompilation OK")
            hf = results.getHighFunction()
            if hf is None:
               continue
            bbList = hf.getBasicBlocks()
            block_list = []
            for block in bbList:
                block_list.append(block)
            ordered_blocks = sorted(block_list, key=lambda x: x.getStart().getOffset())
            #pass_down_offset = 0
            #print("Processing blocks")
            already_printed = False
            for block in ordered_blocks:
                #pass_down = 1
                block_end_off = block.getStop().getOffset()
                #print(f"Dec:{hex(block_end_off)}")
                code_unit = listing.getCodeUnitAt(flat_api.toAddr(jpype.java.lang.Long(block_end_off)))
                #print(f"Dec:{hex(block_end_off)} complete")

                if block.getOutSize()==2:
                    if already_printed is False:
                        already_printed = True
                        #print(f"{fun_count}/{fun_len} Analyzing {function.getName()}")
                        print(f"\"{function.getName()}\", ")


                    # UCT: Use this to avoid patching the path leading to '__stack_chk_fail'
                    if( filter_code_block(block,listing, flat_api) == 1):
                        continue
                    # UCT end

                    
                    offset = block.getStart().getOffset()
                    record_offset = offset
                    end = block.getStop().getOffset()
                    call_site = 0
                    #print("Processing branch")
                    while offset<=end:
                        #print(hex(offset), hex(end))
                        code_unit = listing.getCodeUnitAt(flat_api.toAddr(jpype.java.lang.Long(offset)))
                        
                        if code_unit is None:
                            offset+=1
                            print("None code detected!")
                            continue
                        offset+=code_unit.getLength()
                        if "CALL" in code_unit.getMnemonicString():
                            call_site = offset
                        
                    final_code_unit = listing.getCodeUnitAt(flat_api.toAddr(jpype.java.lang.Long(end)))
                    
                    try:
                        int(final_code_unit.toString()[-6:], 16)
                    except Exception:
                        continue

                    if call_site!=0:
                        lard_list.append(myhex(call_site)[-6:] +
                                         myhex(end + final_code_unit.getLength())[-6:] + final_code_unit.toString()[-6:])
                        # if pass_down_offset != 0 :
                        #     lard_list.append(myhex(block.getStart().getOffset())[-3:] +
                        #                  myhex(block.getOut(0).getStart().getOffset())[-6:] + myhex(block.getOut(1).getStart().getOffset())[-6:])
                    else:
                        lard_list.append(myhex(record_offset)[-6:] +
                                         myhex(end + final_code_unit.getLength())[-6:] + final_code_unit.toString()[-6:])
                        # if pass_down_offset != 0 :
                        #     lard_list.append(myhex(block.getStart().getOffset())[-3:] +
                        #                  myhex(block.getOut(0).getStart().getOffset())[-6:] + myhex(block.getOut(1).getStart().getOffset())[-6:])

                # if pass_down == 1:
                #     if pass_down_offset == 0:
                #         pass_down_offset = block.getStart().getOffset()
                # else:
                #     pass_down_offset = 0

        if os.path.exists('./cfginfo.txt'):
            os.remove('./cfginfo.txt')
        ordered = sorted(lard_list, key=lambda x: int(x[0:6],base=16))

        with open('./cfginfo.txt', 'w') as outfile:
            outfile.write('\n'.join(str(i) for i in ordered))
            print("OK")
        #print("OK")
    return

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage : python3 ghidra_analyze.py <path/to/target_binary>")
        print("And please please please install pyhidra correctly!")
        exit(0)
    main(sys.argv[1])
    #print("OK")