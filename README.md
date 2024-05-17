# Shikata Ga Nai Decoder

This is a Python script that attempts to decode a shellcode that was encoded/encrypted with one or several iterations of Shikata Ga Nai.

It performs a totally static analysis leveraging on the [Capstone disassembler library,](https://www.capstone-engine.org/) and no code is ever executed.

Place the raw binary shellcode into a file and run the script against it.
So far, it managed to decode all ShikataGaNai encoded shellcodes I tried to decode.

You can also check an article about Shikata Ga Nai I wrote [here](https://peetkh.net/wp/blog/understanding-shikata-ga-nai-nop-sleds-and-why-my-shellcode-triggers-an-access-violation-in-the-debugger/).

## Usage

You need to have the [Capstone library](https://www.capstone-engine.org/) installed with Python bindings.

```
python3 ./shikataganai-decoder.py <shellcode_binary_file> [-o <sutput_file>]
```

If the `-o` argument is provided with a filename, the disassembly of the decoded shellcode (decoder stub + decoded payload) will be saved to that file.

## Example

```
┌──(kali㉿kali)-[/mnt/hgfs/dev/blog/2-shikataganai]
└─$ msfvenom -p windows/exec CMD='cmd /c echo Test shellcode.' -f raw -o shellcode.bin -e x86/shikata_ga_nai -i 2
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 2 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 239 (iteration=0)
x86/shikata_ga_nai succeeded with size 266 (iteration=1)
x86/shikata_ga_nai chosen with final size 266
Payload size: 266 bytes
Saved as: shellcode.bin

┌──(kali㉿kali)-[/mnt/hgfs/dev/blog/2-shikataganai]
└─$ python3 ./shikataganai-decoder.py shellcode.bin -o shellcode-decoded.txt 
[...]
[*] Saving to shellcode-decoded.txt.
                                                                                                                                                                                  
┌──(kali㉿kali)-[/mnt/hgfs/dev/blog/2-shikataganai]
└─$ cat shellcode-decoded.txt 
;------[ Shikata_ga_nai decoder | Iteration 1 ]-----
   0: BA89B63169           ...1i        mov edx, 0x6931b689 ; SetKey Step 1: Key stored in EDX, value = 6931b689
   5: DBC8                 ..           fcmovne st(0), st(0) ; GetIp Step 1: FPU instr at offset 005
   7: D97424F4             .t$.         fnstenv [esp - 0xc] ; GetIp Step 2: Dump FPU env
   B: 5B                   [            pop ebx         ; GetIp Step 3: FIP in register EBX
   C: 2BC9                 +.           sub ecx, ecx    ; SetCounter Step 1: Clear ECX
   E: B13C                 .<           mov cl, 0x3c    ; SetCounter Step 2: Counter set to 03c
  10: 83C304               ...          add ebx, 4      ; MainLoop: Advance pointer BEFORE XOR
  13: 315311               1S.          xor dword ptr [ebx + 0x11], edx ; MainLoop: XOR decode instruction. Encoded bytes start at offset 0x01a
  16: 035311               .S.          add edx, dword ptr [ebx + 0x11] ; MainLoop: Key feedback instruction
  19: E2F5                 ..           loop 0x10       ; MainLoop: Loop instruction. Payload start at offset 0x01b
;------[ Shikata_ga_nai decoder | Iteration 2 ]-----
  1B: DAC9                 ..           fcmove st(0), st(1) ; GetIp Step 1: FPU instr at offset 01b
  1D: BA1879302F           ..y0/        mov edx, 0x2f307918 ; SetKey Step 1: Key stored in EDX, value = 2f307918
  22: D97424F4             .t$.         fnstenv [esp - 0xc] ; GetIp Step 2: Dump FPU env
  26: 5E                   ^            pop esi         ; GetIp Step 3: FIP in register ESI
  27: 29C9                 ).           sub ecx, ecx    ; SetCounter Step 1: Clear ECX
  29: B136                 .6           mov cl, 0x36    ; SetCounter Step 2: Counter set to 036
  2B: 315617               1V.          xor dword ptr [esi + 0x17], edx ; MainLoop: XOR decode instruction. Encoded bytes start at offset 0x032
  2E: 035617               .V.          add edx, dword ptr [esi + 0x17] ; MainLoop: Key feedback instruction
  31: 83C604               ...          add esi, 4      ; MainLoop: Advance pointer AFTER XOR
  34: E2F5                 ..           loop 0x2b       ; MainLoop: Loop instruction. Payload start at offset 0x036
;----------------[ Decoded payload ]-----------------
  36: FC                   .            cld            
  37: E882000000           .....        call 0xbe      
  3C: 60                   `            pushal         
  3D: 89E5                 ..           mov ebp, esp   
  3F: 31C0                 1.           xor eax, eax   
  41: 648B5030             d.P0         mov edx, dword ptr fs:[eax + 0x30]
  45: 8B520C               .R.          mov edx, dword ptr [edx + 0xc]
  48: 8B5214               .R.          mov edx, dword ptr [edx + 0x14]
  4B: 8B7228               .r(          mov esi, dword ptr [edx + 0x28]
  4E: 0FB74A26             ..J&         movzx ecx, word ptr [edx + 0x26]
  52: 31FF                 1.           xor edi, edi   
  54: AC                   .            lodsb al, byte ptr [esi]
  55: 3C61                 <a           cmp al, 0x61   
  57: 7C02                 |.           jl 0x5b        
  59: 2C20                 ,.           sub al, 0x20   
  5B: C1CF0D               ...          ror edi, 0xd   
  5E: 01C7                 ..           add edi, eax   
  60: E2F2                 ..           loop 0x54      
  62: 52                   R            push edx       
  63: 57                   W            push edi       
  64: 8B5210               .R.          mov edx, dword ptr [edx + 0x10]
  67: 8B4A3C               .J<          mov ecx, dword ptr [edx + 0x3c]
  6A: 8B4C1178             .L.x         mov ecx, dword ptr [ecx + edx + 0x78]
  6E: E348                 .H           jecxz 0xb8     
  70: 01D1                 ..           add ecx, edx   
  72: 51                   Q            push ecx       
  73: 8B5920               .Y.          mov ebx, dword ptr [ecx + 0x20]
  76: 01D3                 ..           add ebx, edx   
  78: 8B4918               .I.          mov ecx, dword ptr [ecx + 0x18]
  7B: E33A                 .:           jecxz 0xb7     
  7D: 49                   I            dec ecx        
  7E: 8B348B               .4.          mov esi, dword ptr [ebx + ecx*4]
  81: 01D6                 ..           add esi, edx   
  83: 31FF                 1.           xor edi, edi   
  85: AC                   .            lodsb al, byte ptr [esi]
  86: C1CF0D               ...          ror edi, 0xd   
  89: 01C7                 ..           add edi, eax   
  8B: 38E0                 8.           cmp al, ah     
  8D: 75F6                 u.           jne 0x85       
  8F: 037DF8               .}.          add edi, dword ptr [ebp - 8]
  92: 3B7D24               ;}$          cmp edi, dword ptr [ebp + 0x24]
  95: 75E4                 u.           jne 0x7b       
  97: 58                   X            pop eax        
  98: 8B5824               .X$          mov ebx, dword ptr [eax + 0x24]
  9B: 01D3                 ..           add ebx, edx   
  9D: 668B0C4B             f..K         mov cx, word ptr [ebx + ecx*2]
  A1: 8B581C               .X.          mov ebx, dword ptr [eax + 0x1c]
  A4: 01D3                 ..           add ebx, edx   
  A6: 8B048B               ...          mov eax, dword ptr [ebx + ecx*4]
  A9: 01D0                 ..           add eax, edx   
  AB: 89442424             .D$$         mov dword ptr [esp + 0x24], eax
  AF: 5B                   [            pop ebx        
  B0: 5B                   [            pop ebx        
  B1: 61                   a            popal          
  B2: 59                   Y            pop ecx        
  B3: 5A                   Z            pop edx        
  B4: 51                   Q            push ecx       
  B5: FFE0                 ..           jmp eax        
  B7: 5F                   _            pop edi        
  B8: 5F                   _            pop edi        
  B9: 5A                   Z            pop edx        
  BA: 8B12                 ..           mov edx, dword ptr [edx]
  BC: EB8D                 ..           jmp 0x4b       
  BE: 5D                   ]            pop ebp        
  BF: 6A01                 j.           push 1         
  C1: 8D85B2000000         ......       lea eax, [ebp + 0xb2]
  C7: 50                   P            push eax       
  C8: 68318B6F87           h1.o.        push 0x876f8b31
  CD: FFD5                 ..           call ebp       
  CF: BBF0B5A256           ....V        mov ebx, 0x56a2b5f0
  D4: 68A695BD9D           h....        push 0x9dbd95a6
  D9: FFD5                 ..           call ebp       
  DB: 3C06                 <.           cmp al, 6      
  DD: 7C0A                 |.           jl 0xe9        
  DF: 80FBE0               ...          cmp bl, 0xe0   
  E2: 7505                 u.           jne 0xe9       
  E4: BB4713726F           .G.ro        mov ebx, 0x6f721347
  E9: 6A00                 j.           push 0         
  EB: 53                   S            push ebx       
  EC: FFD5                 ..           call ebp       
  EE: 636D64               cmd          arpl word ptr [ebp + 0x64], bp
  F1: 202F                 ./           and byte ptr [edi], ch
  F3: 6320                 c.           arpl word ptr [eax], sp
  F5: 6563686F             echo         arpl word ptr gs:[eax + 0x6f], bp
  F9: 20546573             .Tes         and byte ptr [ebp + 0x73], dl
  FD: 7420                 t.           je 0x11f       
  FF: 7368                 sh           jae 0x169      
 101: 656C                 el           insb byte ptr es:[edi], dx
 103: 6C                   l            insb byte ptr es:[edi], dx
 104: 636F64               cod          arpl word ptr [edi + 0x64], bp
 107: 652E00               e..        INVALID                           ; Could not be decompiled

```

