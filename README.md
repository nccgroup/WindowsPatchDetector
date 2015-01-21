# Experimental Windows .text section Patch Detector
======================

Experimental: Windows .text section compare - disk versus memory

###### Original Idea
After reading about the Skeleton Key malware (http://www.secureworks.com/cyber-threat-intelligence/threats/skeleton-key-malware-analysis/) develop a small tool which would compare the .text section of .exe and .dll files on disk with their RAM equivilent to detect patches.

###### Result
Working on the whole for 32bit and 64bit binaries... 

###### Features
This tool
* either for specific or all 32bit OR 64bit Windows processes enumerates the modules (.exe's and .dll's)
* find the .text (code) section in RAM
* find the .text (code) section on disk
* compares them taking into account base relocations

###### Command Line Options
* -h help
* -p [PID] - only analyze this PID
* -v - show the byte by byte diffs

###### Example Output (patched binary)
```
C:\Data\NCC\!Code\Git.Public\WindowsPatchDetector\Debug>NCCGroupWindowsPatchDetector.exe -p 6104 -v
[*] Experimental Windows Patch Detector - https://github.com/olliencc/WindowsPatchDetector
[*] NCC Group Plc - http://www.nccgroup.com/
[*] -h for help
[i] + [Amazon Music Helper.exe - PID: 6104 in session 1 - window station Console]
[i] Module C:\Users\Ollie\AppData\Local\Amazon Music\Amazon Music Helper.exe .text section at virtual address 00941000 has 0 relocations
[i] Relocations at 00F15000 of 149092 bytes
[diff] Offset 0000000e (0000100e) of 4156286: 90 versus e8 diff a8
[diff] Offset 0000000f (0000100f) of 4156286: 90 versus 55 diff 3b
[diff] Offset 00000010 (00001010) of 4156286: 90 versus 94 diff fc
[diff] Offset 00000011 (00001011) of 4156286: 90 versus 02 diff 8e
[diff] Offset 00000012 (00001012) of 4156286: 90 versus 00 diff 90
[diff] Offset 00000013 (00001013) of 4156286: 90 versus 59 diff 37
[!] 6 bytes different from a total of 4156286 - relocs 0
... snip ...
```

###### Example Output (unpatched binary)
```
[*] Experimental Windows Patch Detector - https://github.com/olliencc/WindowsPatchDetector
[*] NCC Group Plc - http://www.nccgroup.com/ 
[*] -h for help 
[i] + [Amazon Music Helper.exe - PID: 6104 in session 1 - window station Console]
[i] Module C:\Users\Ollie\AppData\Local\Amazon Music\Amazon Music Helper.exe .text section at virtual address 00941000 has 0 relocations
[i] Relocations at 00F15000 of 149092 bytes
[!] 0 bytes different from a total of 4156286 - relocs 0 
[i] Module C:\windows\SYSTEM32\ntdll.dll .text section at virtual address 778E1000 has 0 relocations
[i] Relocations at 77A42000 of 16956 bytes
[!] 0 bytes different from a total of 1005011 - relocs 0 
[i] Module C:\windows\SYSTEM32\KERNEL32.DLL .text section at virtual address 75CA0000 has 0 relocations
[i] Relocations at 75DB0000 of 75024 bytes
[!] 0 bytes different from a total of 401365 - relocs 0 
[i] Module C:\windows\SYSTEM32\KERNELBASE.dll .text section at virtual address 75DD1000 has 0 relocations
[i] Relocations at 75E9A000 of 23068 bytes
[!] 0 bytes different from a total of 771728 - relocs 0 
[i] Module C:\windows\SYSTEM32\WS2_32.dll .text section at virtual address 75F01000 has 0 relocations
[i] Relocations at 75F4A000 of 9800 bytes
[!] 0 bytes different from a total of 215027 - relocs 0 
[i] Module C:\windows\SYSTEM32\USER32.dll .text section at virtual address 754D1000 has 0 relocations
[i] Relocations at 75617000 of 17804 bytes
[diff] Offset 000002a4 (000012a4) of 508412: c0 versus a6 diff 1a
[diff] Offset 000002a5 (000012a5) of 508412: 8b versus 73 diff 18
[diff] Offset 000002a6 (000012a6) of 508412: 43 versus 00 diff 43
[diff] Offset 000002a7 (000012a7) of 508412: 02 versus 00 diff 02
[diff] Offset 000002a8 (000012a8) of 508412: d0 versus c1 diff 0f
[diff] Offset 000002a9 (000012a9) of 508412: 8b versus 73 diff 18
[diff] Offset 000002aa (000012aa) of 508412: 43 versus 00 diff 43
[diff] Offset 000002ab (000012ab) of 508412: 02 versus 00 diff 02
[diff] Offset 000002c0 (000012c0) of 508412: 00 versus dc diff 24
[diff] Offset 000002c1 (000012c1) of 508412: 8b versus 73 diff 18
[diff] Offset 000002c2 (000012c2) of 508412: 43 versus 00 diff 43
[diff] Offset 000002c3 (000012c3) of 508412: 02 versus 00 diff 02
[diff] Offset 000002c4 (000012c4) of 508412: 10 versus f7 diff 19
[diff] Offset 000002c5 (000012c5) of 508412: 8b versus 73 diff 18
[diff] Offset 000002c6 (000012c6) of 508412: 43 versus 00 diff 43
[diff] Offset 000002c7 (000012c7) of 508412: 02 versus 00 diff 02
[!] 16 bytes different from a total of 508412 - relocs 0 
[i] Module C:\windows\SYSTEM32\SHELL32.dll .text section at virtual address 76201000 has 0 relocations
[i] Relocations at 77350000 of 421664 bytes
[!] 0 bytes different from a total of 7311956 - relocs 0 
[i] Module C:\windows\SYSTEM32\ole32.dll .text section at virtual address 75321000 has 0 relocations
[i] Relocations at 75422000 of 40604 bytes
[!] 0 bytes different from a total of 930478 - relocs 0 
[i] Module C:\windows\SYSTEM32\OLEAUT32.dll .text section at virtual address 77651000 has 0 relocations
[i] Relocations at 776DE000 of 25116 bytes
[!] 0 bytes different from a total of 545189 - relocs 0 
[i] Module C:\windows\SYSTEM32\ADVAPI32.dll .text section at virtual address 75FF1000 has 0 relocations
[i] Relocations at 76063000 of 18220 bytes
[!] 0 bytes different from a total of 422057 - relocs 0 
[i] Module C:\windows\SYSTEM32\WINMM.dll .text section at virtual address 742E1000 has 0 relocations
[i] Relocations at 742FE000 of 5772 bytes
[!] 0 bytes different from a total of 80266 - relocs 0 
[i] Module C:\windows\SYSTEM32\CRYPT32.dll .text section at virtual address 76071000 has 0 relocations
[i] Relocations at 761EE000 of 37816 bytes
[!] 0 bytes different from a total of 905804 - relocs 0 
[i] Module C:\windows\SYSTEM32\NSI.dll .text section at virtual address 75F51000 has 0 relocations
[i] Relocations at 75F56000 of 248 bytes
[!] 0 bytes different from a total of 6440 - relocs 0 
[i] Module C:\windows\SYSTEM32\RPCRT4.dll .text section at virtual address 77761000 has 0 relocations
[i] Relocations at 7780B000 of 20048 bytes
[!] 0 bytes different from a total of 639180 - relocs 0 
[i] Module C:\windows\SYSTEM32\GDI32.dll .text section at virtual address 773C1000 has 0 relocations
[i] Relocations at 774C2000 of 17348 bytes
[!] 0 bytes different from a total of 957247 - relocs 0 
[i] Module C:\windows\SYSTEM32\msvcrt.dll .text section at virtual address 77591000 has 0 relocations
[i] Relocations at 7764A000 of 14360 bytes
[!] 0 bytes different from a total of 719071 - relocs 0 
[i] Module C:\windows\SYSTEM32\combase.dll .text section at virtual address 75831000 has 0 relocations
[i] Relocations at 7596B000 of 76008 bytes
[!] 0 bytes different from a total of 1107156 - relocs 0 
[i] Module C:\windows\SYSTEM32\SHLWAPI.dll .text section at virtual address 75B31000 has 0 relocations
[i] Relocations at 75B6E000 of 8744 bytes
[!] 0 bytes different from a total of 220948 - relocs 0 
[i] Module C:\windows\SYSTEM32\sechost.dll .text section at virtual address 75621000 has 0 relocations
[i] Relocations at 7565C000 of 8064 bytes
[!] 0 bytes different from a total of 211508 - relocs 0 
[i] Module C:\windows\SYSTEM32\WINMMBASE.dll .text section at virtual address 74081000 has 0 relocations
[i] Relocations at 7409E000 of 5636 bytes
[!] 0 bytes different from a total of 97074 - relocs 0 
[i] Module C:\windows\SYSTEM32\MSASN1.dll .text section at virtual address 75FE1000 has 0 relocations
[i] Relocations at 75FED000 of 636 bytes
[!] 0 bytes different from a total of 35567 - relocs 0 
[i] Module C:\windows\SYSTEM32\SspiCli.dll .text section at virtual address 752E1000 has 0 relocations
[i] Relocations at 752FB000 of 3796 bytes
[!] 0 bytes different from a total of 87463 - relocs 0 
[i] Module C:\windows\SYSTEM32\cfgmgr32.dll .text section at virtual address 756A1000 has 0 relocations
[i] Relocations at 756D8000 of 7604 bytes
[!] 0 bytes different from a total of 207169 - relocs 0 
[i] Module C:\windows\SYSTEM32\DEVOBJ.dll .text section at virtual address 73E01000 has 0 relocations
[i] Relocations at 73E1D000 of 5764 bytes
[!] 0 bytes different from a total of 97575 - relocs 0 
[i] Module C:\windows\SYSTEM32\CRYPTBASE.dll .text section at virtual address 752D1000 has 0 relocations
[i] Relocations at 752D8000 of 920 bytes
[!] 0 bytes different from a total of 15474 - relocs 0 
[i] Module C:\windows\SYSTEM32\bcryptPrimitives.dll .text section at virtual address 75271000 has 0 relocations
[i] Relocations at 752C0000 of 6520 bytes
[!] 0 bytes different from a total of 310965 - relocs 0 
[i] Module C:\windows\system32\IMM32.DLL .text section at virtual address 774D1000 has 0 relocations
[i] Relocations at 774F3000 of 4348 bytes
[!] 0 bytes different from a total of 103947 - relocs 0 
[i] Module C:\windows\SYSTEM32\MSCTF.dll .text section at virtual address 75B91000 has 0 relocations
[i] Relocations at 75C80000 of 27460 bytes
[!] 0 bytes different from a total of 686822 - relocs 0 
[i] Module C:\windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.9600.17031_none_a9efdb8b01377ea7\comctl32.dll .text section at virtual address 703D1000 has 0 relocations
[i] Relocations at 705A3000 of 74540 bytes
[!] 0 bytes different from a total of 1606349 - relocs 0 
[i] Module C:\windows\SYSTEM32\SHCORE.dll .text section at virtual address 73D81000 has 0 relocations
[i] Relocations at 73DEF000 of 25936 bytes
[!] 0 bytes different from a total of 424383 - relocs 0 
[i] Module C:\windows\SYSTEM32\ntmarta.dll .text section at virtual address 72C01000 has 0 relocations
[i] Relocations at 72C23000 of 5480 bytes
[!] 0 bytes different from a total of 118276 - relocs 0 
[i] Module C:\windows\system32\napinsp.dll .text section at virtual address 72A11000 has 0 relocations
[i] Relocations at 72A1F000 of 2888 bytes
[!] 0 bytes different from a total of 43988 - relocs 0 
[i] Module C:\windows\system32\pnrpnsp.dll .text section at virtual address 729F1000 has 0 relocations
[i] Relocations at 72A02000 of 4188 bytes
[!] 0 bytes different from a total of 57156 - relocs 0 
[i] Module C:\windows\system32\NLAapi.dll .text section at virtual address 729D1000 has 0 relocations
[i] Relocations at 729E3000 of 3140 bytes
[!] 0 bytes different from a total of 53523 - relocs 0 
[i] Module C:\windows\System32\mswsock.dll .text section at virtual address 73A11000 has 0 relocations
[i] Relocations at 73A52000 of 11856 bytes
[!] 0 bytes different from a total of 179304 - relocs 0 
[i] Module C:\windows\SYSTEM32\DNSAPI.dll .text section at virtual address 735F1000 has 0 relocations
[i] Relocations at 73666000 of 21824 bytes
[!] 0 bytes different from a total of 420007 - relocs 0 
[i] Module C:\windows\System32\winrnr.dll .text section at virtual address 729C1000 has 0 relocations
[i] Relocations at 729C8000 of 872 bytes
[!] 0 bytes different from a total of 14763 - relocs 0 
[i] Module C:\windows\system32\wshbth.dll .text section at virtual address 729B1000 has 0 relocations
[i] Relocations at 729BE000 of 2412 bytes
[!] 0 bytes different from a total of 31547 - relocs 0 
[i] Module C:\windows\SYSTEM32\kernel.appcore.dll .text section at virtual address 75111000 has 0 relocations
[i] Relocations at 75118000 of 520 bytes
[!] 0 bytes different from a total of 10040 - relocs 0 
[i] Module C:\windows\system32\uxtheme.dll .text section at virtual address 73C91000 has 0 relocations
[i] Relocations at 73D63000 of 29680 bytes
[!] 0 bytes different from a total of 807001 - relocs 0 
[i] Module C:\windows\SYSTEM32\PGPhk.dll .text section at virtual address 6E611000 has 0 relocations
[i] Relocations at 6E61C000 of 1556 bytes
[!] 0 bytes different from a total of 19834 - relocs 0 
[i] Module C:\Program Files (x86)\Common Files\microsoft shared\ink\tiptsf.dll .text section at virtual address 6FA71000 has 0 relocations
[i] Relocations at 6FAD6000 of 18176 bytes
[!] 0 bytes different from a total of 310243 - relocs 0 
[i] Module C:\windows\SYSTEM32\clbcatq.dll .text section at virtual address 75F61000 has 0 relocations
[i] Relocations at 75FD9000 of 15984 bytes
[!] 0 bytes different from a total of 455708 - relocs 0 
[i] Module C:\windows\SYSTEM32\CRYPTSP.dll .text section at virtual address 747E1000 has 0 relocations
[i] Relocations at 747F7000 of 2016 bytes
[!] 0 bytes different from a total of 76176 - relocs 0 
[i] Module C:\windows\system32\rsaenh.dll .text section at virtual address 747B1000 has 0 relocations
[i] Relocations at 747DC000 of 8848 bytes
[!] 0 bytes different from a total of 136675 - relocs 0 
[i] Module C:\windows\SYSTEM32\bcrypt.dll .text section at virtual address 74801000 has 0 relocations
[i] Relocations at 7481C000 of 2496 bytes
[!] 0 bytes different from a total of 97402 - relocs 0 
[i] Module C:\Windows\System32\rasadhlp.dll .text section at virtual address 72A21000 has 0 relocations
[i] Relocations at 72A26000 of 388 bytes
[!] 0 bytes different from a total of 5881 - relocs 0 
[i] Module C:\windows\SYSTEM32\IPHLPAPI.DLL .text section at virtual address 73741000 has 0 relocations
[i] Relocations at 7375D000 of 2736 bytes
[!] 0 bytes different from a total of 96797 - relocs 0 
[i] Module C:\windows\SYSTEM32\WINNSI.DLL .text section at virtual address 736E1000 has 0 relocations
[i] Relocations at 736E7000 of 628 bytes
[!] 0 bytes different from a total of 10183 - relocs 0 
[i] Module C:\windows\system32\PGPlsp.dll .text section at virtual address 739F1000 has 0 relocations
[i] Relocations at 73A01000 of 2176 bytes
[!] 0 bytes different from a total of 35098 - relocs 0 
[i] Module C:\windows\system32\dwmapi.dll .text section at virtual address 73C71000 has 0 relocations
[i] Relocations at 73C87000 of 2984 bytes
[!] 0 bytes different from a total of 51671 - relocs 0 
[i] Module C:\windows\System32\fwpuclnt.dll .text section at virtual address 72961000 has 0 relocations
[i] Relocations at 729A2000 of 7632 bytes
[!] 0 bytes different from a total of 242369 - relocs 0 
[i] Module C:\windows\SYSTEM32\gpapi.dll .text section at virtual address 72B91000 has 0 relocations
[i] Relocations at 72BAC000 of 4196 bytes
[!] 0 bytes different from a total of 85034 - relocs 0 
[i] Module C:\windows\SYSTEM32\ncrypt.dll .text section at virtual address 72BE1000 has 0 relocations
[i] Relocations at 72BFB000 of 3724 bytes
[!] 0 bytes different from a total of 84035 - relocs 0 
[i] Module C:\windows\SYSTEM32\NTASN1.dll .text section at virtual address 72BB1000 has 0 relocations
[i] Relocations at 72BD8000 of 8092 bytes
[!] 0 bytes different from a total of 145303 - relocs 0 
[i] Module C:\Windows\SYSTEM32\cryptnet.dll .text section at virtual address 6F741000 has 0 relocations
[i] Relocations at 6F763000 of 5052 bytes
[!] 0 bytes different from a total of 122001 - relocs 0 
[i] Module C:\windows\SYSTEM32\WLDAP32.dll .text section at virtual address 75EA1000 has 0 relocations
[i] Relocations at 75EED000 of 15952 bytes
[!] 0 bytes different from a total of 293784 - relocs 0 
[i] Module C:\windows\SYSTEM32\profapi.dll .text section at virtual address 73D71000 has 0 relocations
[i] Relocations at 73D7D000 of 1472 bytes
[!] 0 bytes different from a total of 32948 - relocs 0 
```
