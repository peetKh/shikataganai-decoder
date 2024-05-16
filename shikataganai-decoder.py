#!/usr/bin/env python3

# References
#  1. ShikataGaNai source code
#     https://github.com/rapid7/metasploit-framework/blob/master/modules/encoders/x86/shikata_ga_nai.rb

import sys
import re
import capstone
from capstone import x86
import struct
import time
import binascii
import argparse



fpuInstrList = (
    'fld', 'fcmovbe', 'fnop', 'fldln2', 'fcmovnb', 'fcmovu',
    'fcmovnu', 'fcmove', 'fld1', 'fcmovb', 'fldl2t', 'ffree',
    'fcmovnbe', 'fldlg2', 'fcmovne', 'fxam', 'fabs', 'fldl2e',
    'fxch', 'fdecstp', 'fincstp', 'fldpi' )

def getInstr(code, ip):
    instrs = list( md.disasm(code[ip:ip+12], ip) )
    if len(instrs) == 0 :
        print("WARNING: Could not decompile bytes ", repr(code[ip:ip+12])[2:-2])
        return None
    return instrs[0]


def formatBytes( instrBytes ):
    instrNMaxBytes = 10
    instrBytesAscii = ''.join(chr(_) if ( 33 <= _ <= 126 ) else "." for _ in instrBytes)  \
        + ' ' * (instrNMaxBytes - len(instrBytes))
    instrBytesHex = instrBytes.hex().upper()  \
        + ' ' * 2 * (instrNMaxBytes - len(instrBytes))
    return instrBytesHex + ' ' + instrBytesAscii

def formatInstr(instr):
    instrBytesStr = formatBytes(instr.bytes)
    return "% 4X: %s   %s %s" %(
        instr.address, instrBytesStr, instr.mnemonic, instr.op_str)

def formatResult( instrsLst, commentsLst ):
    s = ""
    ip = 0
    itr = 0
    for instr, comment in zip(instrsLst, commentsLst):
        if itr == len(payloadStartOffsets) and ip == payloadStartOffsets[-1]:
            s += ";----------------[ Decoded payload ]-----------------\n"
        elif ip == 0 or ip == payloadStartOffsets[itr-1]:
            itr += 1
            s += ";------[ Shikata_ga_nai decoder | Iteration %d ]-----\n" % itr
        if type(instr) is capstone.CsInsn:
            s +=  "%-55s" %(formatInstr(instr)) \
                + ((" ; " + comment[5:].strip())  if comment else "") \
                + "\n"
            ip += len(instr.bytes)
        elif type(instr) is bytes:
            s +=  "% 4x: %s INVALID" %(ip, formatBytes(instr)) \
                + ((" "*26 + " ; " + comment[5:].strip())  if comment else "") \
                + "\n"
        else:
            raise Exception('Unexpected')
    return s 

class SgnNotFoundException(Exception):
    pass

def traceSgn(shellcode, ip = 0, iter = 1):

    def decode(shellcode, encodedOffset, keyVal):
        # Decode encoded bytes
        print("  Decoding payload...")
        decoded = shellcode[:encodedOffset]
        currentKey = keyVal
        l = len(shellcode)
        for ptr in range(encodedOffset, len(shellcode), 4):
            encDword = struct.unpack('<L', shellcode[ptr:ptr+4])[0]
            decDword = encDword ^ currentKey
            currentKey = ( currentKey + decDword ) & 0xffffffff
            print("     Cipher: %08x  key: %08x  clear: %08x" %(
                encDword, currentKey, decDword))
            decoded += struct.pack('<L', decDword )
        decoded = decoded[:l]
        print("Done.")
        return decoded

    print("\n[*] Tracing ShikataGaNai decoder, iteration %d...\n" % iter)
    # Trace shellcode
    fpuInstrIp = None
    ipRegId = None
    keyRegId = None
    keyVal = None
    counter = None
    getipStep = 0
    setcounterStep = 0
    setkeyStep = 0
    inMainLoop = False
    inDecoder = True
    instrsLst = []
    commentsLst = []
    while inDecoder and ip < len(shellcode):
        instr = getInstr(shellcode, ip)
        if not instr:
            print('Quitting.')
            sys.exit()
        instrBytes = instr.bytes.hex()
        print( formatInstr(instr) )
        if not inMainLoop: # Initialization stage
            if instr.mnemonic == 'int3':
                ip += len(instr.bytes)
                comment = "     Breakpoint\n"
                continue
            if getipStep == 0 and \
                    instr.mnemonic in fpuInstrList:
                fpuInstrIp = ip
                comment = "     GetIp Step 1: FPU instr at offset %03x\n" % ip
                getipStep = 1
            elif getipStep == 1 \
                    and instr.mnemonic in ('fstenv','fnstenv'):
                comment = "     GetIp Step 2: Dump FPU env\n"
                getipStep = 2
            elif getipStep == 2 \
                    and instr.mnemonic == 'pop':
                ipRegId = instr.operands[0].reg
                comment = "     GetIp Step 3: FIP in register %s\n" % instr.reg_name(ipRegId).upper()
                getipStep = 3
            elif setcounterStep == 0 \
                    and instr.mnemonic in ('xor','sub'):
                comment = "     SetCounter Step 1: Clear ECX\n"
                setcounterStep = 1
            elif setcounterStep == 1 \
                    and instr.mnemonic in ('add','sub','mov')  \
                    and instr.operands[0].reg == x86.X86_REG_CL:
                counter = abs(instr.operands[1].imm)
                comment = "     SetCounter Step 2: Counter set to %03x\n" % counter
                setcounterStep = 2
            elif setkeyStep == 0 \
                    and instr.mnemonic == 'mov' \
                    and instr.operands[0].reg not in (x86.X86_REG_CL, x86.X86_REG_CH, x86.X86_REG_CX, x86.X86_REG_ECX):
                keyRegId = instr.operands[0].reg
                keyVal = instr.operands[1].imm
                comment = "     SetKey Step 1: Key stored in %s, value = %08x\n" % (
                    instr.reg_name(keyRegId).upper(), keyVal)
                setkeyStep = 1
            else:
                raise SgnNotFoundException('Unexpected instruction. Shellcode may not be ShikataGaNai.')

            if getipStep == 3 and setcounterStep == 2 and setkeyStep == 1:
                inMainLoop = True
                foundXor = False
                foundAdd = False
        else: # In main loop
            if instr.mnemonic in ('add','sub') and instr.operands[0].reg == ipRegId:
                foundAdd = True
                if foundXor:
                    comment = "     MainLoop: Advance pointer AFTER XOR\n"
                else:
                    comment = "     MainLoop: Advance pointer BEFORE XOR\n"
            elif instr.mnemonic == 'xor':
                foundXor = True
                encodedOffset = fpuInstrIp \
                    + instr.operands[0].mem.scale * instr.operands[0].mem.disp \
                    + (4 if foundAdd else 0 )
                comment = "     MainLoop: XOR decode instruction. Encoded bytes start at offset 0x%03x\n" % encodedOffset
                shellcode = decode(shellcode, encodedOffset, keyVal)
            elif instr.mnemonic in ('add') and instr.operands[0].reg == keyRegId:
                comment = "     MainLoop: Key feedback instruction"
            elif instr.mnemonic == 'loop':
                inDecoder = False
                payloadOffset = ip + len(instr.bytes)
                comment = "     MainLoop: Loop instruction. Payload start at offset 0x%03x\n" % payloadOffset
            else:
                raise SgnNotFoundException('Unexpected instruction. Shellcode may not be ShikataGaNai or be broken ?')
        ip += len(instr.bytes)
        instrsLst.append(instr)
        commentsLst.append(comment)
        print(comment)
    print("Done.")

    # Check for other iteration of SGN
    try:
        shellcode, payloadOffsetIter, instrsLstIter, commentsLstIter  = \
            traceSgn(shellcode, payloadOffset, iter+1)
        instrsLst += instrsLstIter
        commentsLst += commentsLstIter
        payloadOffset = [payloadOffset] + payloadOffsetIter
    except SgnNotFoundException:
        payloadOffset = [payloadOffset]
        # Disassemble payload
        while ip < len(shellcode):
            instr = getInstr(shellcode, ip)
            if not instr:
                commentsLst.append( "     Could not be decompiled")
                instrsLst.append(shellcode[ip:ip+4])
                break
            else:
                instrBytes = instr.bytes.hex()
                instrsLst.append(instr)
                commentsLst.append(None)
                ip += len(instr.bytes)

    return shellcode, payloadOffset, instrsLst, commentsLst


if __name__ == "__main__":

    argParser = argparse.ArgumentParser( 
            prog = "Shikataganai Decoder",
            description = "Attempts to decode Shikataganai encoded shellcodes")
    argParser.add_argument('shellcodeFilename')
    argParser.add_argument('-o', '--output', action = 'store', default = None)
    args = argParser.parse_args()
    shellcodeFilename = args.shellcodeFilename
    outputFilename = args.output


    # Disassembler
    
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    # Shellcode to analyze
    with open(shellcodeFilename,'rb') as f:
        shellcode = f.read()



    # Naive decompilation

    print("\n"*4+"="*80 + "\nNaive decompilation attempt\n\n")
    ip = 0
    while ip < len(shellcode):
        instr = getInstr(shellcode, ip)
        if not instr:
            break
        instrBytes = instr.bytes.hex()
        print( formatInstr(instr) )
        ip += len(instr.bytes)
    

    # Trace Shikataganai (main loop)

    print("\n"*4+"="*80 + "\nShikataganai decoding attempt\n\n")
            
    decoded, payloadStartOffsets, instrsLst, commentsLst = traceSgn(shellcode)


    # Print result

    s = formatResult( instrsLst, commentsLst )
    print(s)
    if outputFilename:
        print("[*] Saving to %s." % outputFilename)
        with open(outputFilename, 'w') as f:
            f.write(s)
