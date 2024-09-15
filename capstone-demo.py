import os
import sys
import struct
import uuid
import subprocess
from pathlib import Path
from keystone import *
from capstone import Cs
from capstone import CS_ARCH_X86
from capstone import CS_MODE_32

# Author:  Mahatah (https://github.com/mahatah)
# Date:    September 15, 2024
# Title:   capstone-demo.py
# Purpose: To demonstrate use of Capstone Python module in disassmbling shellcode compiled by Keystone.

CODE = (
    " start:                             "  #
    "   mov   ebp, esp                  ;"  #   Store ESP in EBP
    "   sub   esp, 80h                  ;"  #   Mov ESP back 0x80 bytes to give EBP storage space

    " search_kernel32:                   "  #
    "   xor   ecx, ecx                  ;"  #   ECX -> 0
    "   mov   esi,fs:[ecx+30h]          ;"  #   ESI -> PEB structure
    "   mov   esi,[esi+0Ch]             ;"  #   ESI -> Ldr location
    "   mov   esi,[esi+1Ch]             ;"  #   ESI -> InInitOrder in Ldr

    " check_mod:                         "  #
    "   mov   ebx, [esi+8h]             ;"  #   EBX -> base address
    "   mov   edi, [esi+20h]            ;"  #   EDI -> module name
    "   mov   esi, [esi]                ;"  #   ESI -> flink
    "   cmp   [edi+18h], cx             ;"  #   Is 12th char (0n24 or 0x18 bytes) in module name null?
    "   jne   check_mod                 ;"  #   If no, try again
    "   ret                              "  #   If yes, return
)

def assemble_code_from_self(self_code):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(self_code)
    sh = b""
    for e in encoding:
        sh += struct.pack("B", e)
    formatted_shellcode = bytearray(sh)
    return formatted_shellcode

def disassemble_shellcode(shellcode):
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    disassembler_list = list()
    line = ""
    iter = 0
    for instruction in disassembler.disasm(shellcode, 0x1000):
        hex_code = ' '.join(f'{b:02x}' for b in instruction.bytes)
        print(f"{iter}" + "\t\t" + f"{hex_code:<40}\t{instruction.mnemonic}\t{instruction.op_str}")
        line = f"{iter}" + "\t" + f"{hex_code:<40}" + "\t" + f"{instruction.mnemonic}" + "     " + f"{instruction.op_str}"
        disassembler_list.append(line)
        iter = iter + 1
    return disassembler_list

def save_to_csv_file(input_list, headers_string, filepath):    
    try:
        startFile = open(filepath, "w")
        startFile.write(f"{headers_string}\n")
        startFile.close()
        for row in input_list:
            appendFile = open(filepath, "a")
            appendFile.write(f"{row}\n")
            appendFile.close()
        return 0
    except:
        return 1
    
def main():
    print("\n")
    if (("--help" in sys.argv) or ("-h" in sys.argv)):
        print("\n\n\n\tReplace this script's Keystone \"CODE\" variable with your own before running this script. Script will assemble the instructions into shellcode before disassembling that shellcode and displaying the bytes coresponding to each instruction. If you supply the \"--bad-bytes\" parameter with the bad bytes to detect, an additional output will display exactly which instructions contain one or more bad bytes.")
        print("\n\tUsage: python assemble-disassemble.py --bad-bytes (optional: <[string]hex_chars> --output-csv <[string]file_path> --powershell-alias <[string]alias>)")
        print("\n\t--bad-bytes\t\tBad bytes in hex with no leading \"0x\", space seperated. Example: \"00 0C 7E\"")
        print("\t--output-csv\t\tFile path to save the temporary CSV. Used to find bad bytes in disassembled instructions.")
        print("\t--powershell-alias\tScript will try to determine this value by default or it can be supplied with this param.")
        print("\n\tExample usage:\t\tpython assemble-disassemble.py --bad-bytes \"00 1C\" --output-csv \"/tmp/temp.csv\" --powershell-alias \"pwsh\"")
        print("\tExample usage:\t\tpython assemble-disassemble.py --bad-bytes \"00 A1 7C\"")
        print("\tExample usage:\t\tpython assemble-disassemble.py\n\n\n\n")
        sys.exit(1)

    bad_bytes = None
    csv_file_path = None
    is_windows = None
    powershell_alias = None
    retSaveCSV = None
    default_csv_file_path = f"./{uuid.uuid4().hex}.csv"

    if "--powershell-alias" in sys.argv:
        try:
            powershell_alias = sys.argv[sys.argv.index("--powershell-alias") + 1]
        except IndexError:
            print("Error: --powershell-alias specified but no filepath provided.")
            sys.exit(1)

    if ("--bad-bytes" in sys.argv):
        try:
            bad_bytes = sys.argv[sys.argv.index("--bad-bytes") + 1]
        except IndexError:
            print("Error: --bad-bytes specified but no bytes provided.")
            sys.exit(1)
        try:
            if(powershell_alias) is None:
                if(os.name.upper() == 'NT'):
                    powershell_alias = 'powershell.exe'
                else:
                    powershell_alias = 'pwsh'
                print(f"\n\nUsing \"{powershell_alias}\" for PowerShell alias.")
                print("Hint: You can manually set the PowerShell alias with \"--powershell-alias <alias>\"\n\n")
            else:
                print(f"\n\nUsing PowerShell alias: \"{powershell_alias}\"")
        except:
            print("Could not determine operating system!")
            print("Please provide PowerShell alias with \"--powershell-alias\" and try again.\n\n")
            sys.exit(1)
    else:
        print(f"\t*****\t No bad bytes specified! Displaying disassembly only!\t *****\n")

    if "--output-csv" in sys.argv:
        try:
            csv_file_path = sys.argv[sys.argv.index("--output-csv") + 1]
        except IndexError:
            print("Error: --output-csv specified but no filepath provided.")
            sys.exit(1)
    
    raw_shellcode = assemble_code_from_self(CODE)
    disasm_list = disassemble_shellcode(raw_shellcode)

    print("")
    
    if(bad_bytes) is not None:
        if(csv_file_path) is None:
            csv_file_path = default_csv_file_path
        try:
            full_csv_path = Path(csv_file_path).resolve()
        except:
            print(f"\nCould not resolve path for CSV with file path: \"{full_csv_path}\"")

        retSaveCSV = save_to_csv_file(disasm_list, "line\tbytes\tinstructions", full_csv_path)
        if(retSaveCSV == 1):
            print(f"\nThere was an error saving CSV file to \"{full_csv_path}\"!")
            if(bad_bytes) is not None:
                print("\nUnable to detect bad bytes without CSV! Displaying disassembly only!")

    print("")

    if(retSaveCSV == 0 and (bad_bytes) is not None and (full_csv_path) is not None):
        try:
            if(os.name.upper() == 'NT'):
                powerShellMessage = f'{powershell_alias} -ep bypass -c \"$badBytes = \\\"{bad_bytes}\\\"; $shellCodeCSV = Import-Csv \\\"{full_csv_path}\\\" -Delimiter \\\"`t\\\"; $badRows = @(); foreach($row in $shellCodeCsv)' + '{$rowBytesArray = $row.bytes.Trim().split(\\\" \\\"); foreach($rowByte in $rowBytesArray){ if($badBytes.split(\\\" \\\") -icontains $rowByte){ $badRows += [int]$row.line } } }; $out = $shellCodeCsv | ?{$_.line -in $badRows}; $out; Write-Host(\\\"`n`nBad bytes are: \\\" + $badBytes.ToLower() + \\\"`n\\\");\"'
            else:
                powerShellMessage = 'pwsh -c \'$badBytes = "' + f"{bad_bytes}" + '"; $shellCodeCSV = Import-Csv ' + f"{full_csv_path}" + f' -Delimiter "`t"; Remove-Item -Path "{full_csv_path}";' + ' $badRows = @(); foreach($row in $shellCodeCsv){ $rowBytesArray = $row.bytes.Trim().split(" "); foreach($rowByte in $rowBytesArray){ if($badBytes.split(" ") -icontains $rowByte){ $badRows += [int]$row.line } } }; $out = $shellCodeCsv | ?{$_.line -in $badRows}; $out;\''
            subprocess.check_call(powerShellMessage, shell=True)
        except:
            print(f"\nError: PowerShell subprocess encountered an error. Unable to determine bad bytes.\n")

if __name__ == "__main__":
    main()
