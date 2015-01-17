# Experimental Windows .text section Patch Detector
======================

Experimental: Windows .text section compare - disk versus memory

###### Features
This tool
* either for specific or all 32bit Windows processes enumerates the modules (.exe's and .dll's)
* find the .text (code) section in RAM
* find the .text (code) section on disk
* compares them

###### Command Line Options
* -h help
* -p [PID] - only analyze this PID
* -v - show the byte by byte diffs (noisy!)

###### Example Output
```
C:\Data\NCC\!Code\Git.Public\WindowsPatchDetector\Debug>NCCGroupWindowsPatchDetector.exe -p 4784
[*] Windows Patching Detector - https://github.com/nccgroup/WindowsPatchDetector
[*] NCC Group Plc - http://www.nccgroup.com/
[*] -h for help
[i] + [Amazon Music Helper.exe - PID: 4784 in session 1 - window station Console]
[i] Module C:\Users\Ollie\AppData\Local\Amazon Music\Amazon Music Helper.exe .text section at virtual address 00941000 has 0 relocations
[!] 45094 bytes different from a total of 4156286
[i] Module C:\windows\SYSTEM32\ntdll.dll .text section at virtual address 778E1000 has 0 relocations
[!] 14624 bytes different from a total of 1005011
[i] Module C:\windows\SYSTEM32\KERNEL32.DLL .text section at virtual address 75CA0000 has 0 relocations
[!] 14584 bytes different from a total of 401365
[i] Module C:\windows\SYSTEM32\KERNELBASE.dll .text section at virtual address 75DD1000 has 0 relocations
[!] 20976 bytes different from a total of 771728
[i] Module C:\windows\SYSTEM32\WS2_32.dll .text section at virtual address 75F01000 has 0 relocations
[!] 9286 bytes different from a total of 215027
[i] Module C:\windows\SYSTEM32\USER32.dll .text section at virtual address 754D1000 has 0 relocations
[!] 16452 bytes different from a total of 508412
[i] Module C:\windows\SYSTEM32\SHELL32.dll .text section at virtual address 76201000 has 0 relocations
[!] 402436 bytes different from a total of 7311956
[i] Module C:\windows\SYSTEM32\ole32.dll .text section at virtual address 75321000 has 0 relocations
[!] 38088 bytes different from a total of 930478
[i] Module C:\windows\SYSTEM32\OLEAUT32.dll .text section at virtual address 77651000 has 0 relocations
[!] 23630 bytes different from a total of 545189
[i] Module C:\windows\SYSTEM32\ADVAPI32.dll .text section at virtual address 75FF1000 has 0 relocations
[!] 16946 bytes different from a total of 422057
[i] Module C:\windows\SYSTEM32\WINMM.dll .text section at virtual address 742E1000 has 0 relocations
[!] 5544 bytes different from a total of 80266
[i] Module C:\windows\SYSTEM32\CRYPT32.dll .text section at virtual address 76071000 has 0 relocations
[!] 35518 bytes different from a total of 905804
[i] Module C:\windows\SYSTEM32\NSI.dll .text section at virtual address 75F51000 has 0 relocations
[!] 228 bytes different from a total of 6440
[i] Module C:\windows\SYSTEM32\RPCRT4.dll .text section at virtual address 77761000 has 0 relocations
[!] 18028 bytes different from a total of 639180
[i] Module C:\windows\SYSTEM32\GDI32.dll .text section at virtual address 773C1000 has 0 relocations
[!] 15586 bytes different from a total of 957247
[i] Module C:\windows\SYSTEM32\msvcrt.dll .text section at virtual address 77591000 has 0 relocations
[!] 12200 bytes different from a total of 719071
[i] Module C:\windows\SYSTEM32\combase.dll .text section at virtual address 75831000 has 0 relocations
[!] 68504 bytes different from a total of 1107156
[i] Module C:\windows\SYSTEM32\SHLWAPI.dll .text section at virtual address 75B31000 has 0 relocations
[!] 7926 bytes different from a total of 220948
[i] Module C:\windows\SYSTEM32\sechost.dll .text section at virtual address 75621000 has 0 relocations
[!] 7448 bytes different from a total of 211508
[i] Module C:\windows\SYSTEM32\WINMMBASE.dll .text section at virtual address 74081000 has 0 relocations
[!] 5292 bytes different from a total of 97074
[i] Module C:\windows\SYSTEM32\MSASN1.dll .text section at virtual address 75FE1000 has 0 relocations
[!] 568 bytes different from a total of 35567
[i] Module C:\windows\SYSTEM32\SspiCli.dll .text section at virtual address 752E1000 has 0 relocations
[!] 3362 bytes different from a total of 87463
[i] Module C:\windows\SYSTEM32\cfgmgr32.dll .text section at virtual address 756A1000 has 0 relocations
[!] 6954 bytes different from a total of 207169
[i] Module C:\windows\SYSTEM32\DEVOBJ.dll .text section at virtual address 73E01000 has 0 relocations
[!] 5532 bytes different from a total of 97575
[i] Module C:\windows\SYSTEM32\CRYPTBASE.dll .text section at virtual address 752D1000 has 0 relocations
[!] 856 bytes different from a total of 15474
[i] Module C:\windows\SYSTEM32\bcryptPrimitives.dll .text section at virtual address 75271000 has 0 relocations
[!] 5864 bytes different from a total of 310965
[i] Module C:\windows\system32\IMM32.DLL .text section at virtual address 774D1000 has 0 relocations
[!] 4056 bytes different from a total of 103947
[i] Module C:\windows\SYSTEM32\MSCTF.dll .text section at virtual address 75B91000 has 0 relocations
[!] 25900 bytes different from a total of 686822
[i] Module C:\windows\WinSxS\x86_microsoft.windows.common-controls_6595b64144ccf1df_6.0.9600.17031_none_a9efdb8b01377ea7\comctl32.dll .text section
 virtual address 703D1000 has 0 relocations
[!] 70602 bytes different from a total of 1606349
[i] Module C:\windows\SYSTEM32\SHCORE.dll .text section at virtual address 73D81000 has 0 relocations
[!] 24704 bytes different from a total of 424383
[i] Module C:\windows\SYSTEM32\ntmarta.dll .text section at virtual address 72C01000 has 0 relocations
[!] 5044 bytes different from a total of 118276
[i] Module C:\windows\system32\napinsp.dll .text section at virtual address 72A11000 has 0 relocations
[!] 2774 bytes different from a total of 43988
[i] Module C:\windows\system32\pnrpnsp.dll .text section at virtual address 729F1000 has 0 relocations
[!] 4028 bytes different from a total of 57156
[i] Module C:\windows\system32\NLAapi.dll .text section at virtual address 729D1000 has 0 relocations
[!] 2982 bytes different from a total of 53523
[i] Module C:\windows\System32\mswsock.dll .text section at virtual address 73A11000 has 0 relocations
[!] 8560 bytes different from a total of 179304
[i] Module C:\windows\SYSTEM32\DNSAPI.dll .text section at virtual address 735F1000 has 0 relocations
[!] 19776 bytes different from a total of 420007
[i] Module C:\windows\System32\winrnr.dll .text section at virtual address 729C1000 has 0 relocations
[!] 752 bytes different from a total of 14763
[i] Module C:\windows\system32\wshbth.dll .text section at virtual address 729B1000 has 0 relocations
[!] 2210 bytes different from a total of 31547
[i] Module C:\windows\SYSTEM32\kernel.appcore.dll .text section at virtual address 75111000 has 0 relocations
[!] 502 bytes different from a total of 10040
[i] Module C:\windows\system32\uxtheme.dll .text section at virtual address 73C91000 has 0 relocations
[!] 24144 bytes different from a total of 807001
[i] Module C:\Program Files (x86)\Common Files\microsoft shared\ink\tiptsf.dll .text section at virtual address 6FA71000 has 0 relocations
[!] 17038 bytes different from a total of 310243
[i] Module C:\windows\SYSTEM32\clbcatq.dll .text section at virtual address 75F61000 has 0 relocations
[!] 14518 bytes different from a total of 455708
[i] Module C:\windows\SYSTEM32\CRYPTSP.dll .text section at virtual address 747E1000 has 0 relocations
[!] 1850 bytes different from a total of 76176
[i] Module C:\windows\system32\rsaenh.dll .text section at virtual address 747B1000 has 0 relocations
[!] 8492 bytes different from a total of 136675
[i] Module C:\windows\SYSTEM32\bcrypt.dll .text section at virtual address 74801000 has 0 relocations
[!] 2268 bytes different from a total of 97402
[i] Module C:\windows\system32\PGPlsp.dll .text section at virtual address 739F1000 has 0 relocations
[!] 1674 bytes different from a total of 35098
[i] Module C:\windows\system32\dwmapi.dll .text section at virtual address 73C71000 has 0 relocations
[!] 2802 bytes different from a total of 51671
[i] Module C:\Windows\System32\rasadhlp.dll .text section at virtual address 72A21000 has 0 relocations
[!] 356 bytes different from a total of 5881
[i] Module C:\windows\SYSTEM32\IPHLPAPI.DLL .text section at virtual address 73741000 has 0 relocations
[!] 2472 bytes different from a total of 96797
[i] Module C:\windows\SYSTEM32\WINNSI.DLL .text section at virtual address 736E1000 has 0 relocations
[!] 602 bytes different from a total of 10183
[i] Module C:\windows\system32\apphelp.dll .text section at virtual address 751D1000 has 0 relocations
[!] 21234 bytes different from a total of 474628
[i] Module C:\windows\System32\fwpuclnt.dll .text section at virtual address 72961000 has 0 relocations
[!] 7088 bytes different from a total of 242369
[i] Module C:\windows\SYSTEM32\gpapi.dll .text section at virtual address 72B91000 has 0 relocations
[!] 3882 bytes different from a total of 85034
[i] Module C:\windows\SYSTEM32\ncrypt.dll .text section at virtual address 72BE1000 has 0 relocations
[!] 3510 bytes different from a total of 84035
[i] Module C:\windows\SYSTEM32\NTASN1.dll .text section at virtual address 72BB1000 has 0 relocations
[!] 7558 bytes different from a total of 145303
[i] Module C:\Windows\SYSTEM32\cryptnet.dll .text section at virtual address 6F741000 has 0 relocations
[!] 4692 bytes different from a total of 122001
[i] Module C:\windows\SYSTEM32\WLDAP32.dll .text section at virtual address 75EA1000 has 0 relocations
[!] 15254 bytes different from a total of 293784
[i] Module C:\windows\SYSTEM32\profapi.dll .text section at virtual address 73D71000 has 0 relocations
[!] 1352 bytes different from a total of 32948
```
