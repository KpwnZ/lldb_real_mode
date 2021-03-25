import lldb

def get_current_addr():
    # get current address cs:ip
    interpreter = lldb.debugger.GetCommandInterpreter()
    return_object = lldb.SBCommandReturnObject()
    interpreter.HandleCommand('reg r cs', return_object)
    cs = int(return_object.GetOutput()[return_object.GetOutput().find("0"):], 0)
    interpreter.HandleCommand('reg r eip', return_object)
    eip = int(return_object.GetOutput()[return_object.GetOutput().find("0"):], 0)
    addr = '0x{:08x}'.format(cs * 16 + eip)
    return [cs, eip, addr]

def ins_addr(debugger, command, result, internal_dict):
    addr = get_current_addr()
    print("\t  cs: 0x{:08x}\n\t eip: 0x{:08x}\n\taddr: {}".format(addr[0], addr[1], addr[2]))

def run_to_real_addr(debugger, command, result, internal_dict):
    # check cr0 register to detect real mode
    interpreter = lldb.debugger.GetCommandInterpreter()
    return_object = lldb.SBCommandReturnObject()
    interpreter.HandleCommand('reg r cr0', return_object)
    real_mode_enabled = int(return_object.GetOutput()[return_object.GetOutput().find("0x"):], 0) & 0x1
    if real_mode_enabled != 0:
        print("not in real mode")
        return

    # shit code here :-(
    while True:
        addr = get_current_addr()
        if addr[0] * 16 + addr[1] == int(command, 0):
            print("at " + addr[2])
            interpreter.HandleCommand('x/10i ' + addr[2], return_object)
            print(return_object.GetOutput())
            break
        interpreter.HandleCommand('reg r cr0', return_object)

def sigtrap_stop_hook(bpaddr):
    # a simple stop hook, check the whether the breakpoint addr == current addr
    # when it hit the breakpoint, a SIGTRAP is sent actually, so we can catch it by writing a stop-hook
    addr = get_current_addr()
    if bpaddr == int(addr[2], 0):                       # the breakpoint addr
        print("current address: " + addr[2])
        print("Hit real mode breakpoint with cs:ip")
        lldb.debugger.HandleCommand("x/10i " + addr[2]) # print the instructions 


def break_real_addr(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    breakpoint = target.BreakpointCreateByAddress(int(command, 0))
    index = target.GetNumBreakpoints()
    
    # add stop-hook, use the real mode address of breakpoint as argument
    log_cmd = 'target stop-hook add -o \"script lldb_custom_command.sigtrap_stop_hook({})\"'.format(command)
    debugger.HandleCommand(log_cmd)

    # print("set real addr breakpoint: "+command)
    # breakpoint.SetScriptCallbackFunction('lldb_custom_command.breakpointHandler')     
    # we can't use script callback here because lldb think the process stop at eip

def __lldb_init_module(debugger, internal_dict):
    
    debugger.HandleCommand("command script add -f lldb_real_mode.ins_addr addr")
    debugger.HandleCommand("command script add -f lldb_real_mode.break_real_addr bkr")
    debugger.HandleCommand("command script add -f lldb_real_mode.run_to_real_addr rtr")
