function Syscall-Resolver {
#.SYNOPSIS
# PowerShell Script to Dynamically Resolve Syscall ID's (SSN's)
# Arbitrary Version Number: v0.9.9
# Author: Tyler C. McCann (@tylerdotrar)
#
#.DESCRIPTION
# Currently a work-in-progress script that will dynamically resolve a Syscall's ID (SSN), and
# optionally implement it into either a direct or indirect syscall stub for shellcode use via 
# the '-GenStub' parameter. Default behavior is to generate a direct syscall stub; use the
# '-Indirect' parameter for the latter.
#
# Note: Needs to be refactored to prevent false postives, but currently a good POC.
#
# Parameters:
#   -FunctionName  -->  Target Win32 syscall for SSN resolution.
#   -GenStub       -->  Generate a useable syscall stub including the resolved SSN.
#   -Indirect      -->  Generate an indirect syscall stub instead of direct.
#   -Help          -->  Return Get-Help information.
# 
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS


    Param(
        [string]$FunctionName,
        [switch]$GenStub,
        [switch]$Indirect,
        [switch]$Help
    )


    # Return Get-Help Information
    if ($Help) { return (Get-Help Syscall-Resolver) }


    # Minor Error Correction
    if (!$FunctionName) { return (Write-Host '[!] Error! Missing target function (e.g., "NtAllocateVirtualMemory").' -ForegroundColor Red) }
    if ($Indirect)      { $GenStub = $TRUE }

    # Internal Function(s)
    function Generic-Error() {
        Write-Host "[!] Unexpected error occured! Return details:" -ForegroundColor Red
        $Error[0]
        $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
        $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
        return
    }
    function Print-Hex ($Integer) {
        return ('0x{0:x2}' -f $Integer)
    }

    # Step 1: Acquire Memory Address of Target Win32 Function

    Try {
        $Library = 'Ntdll.dll'
        if ($PSVersionTable.PSEdition -eq 'Core') {
            
            # Get a handle to the target library via Load() method
            $LibraryHandle   = [System.Runtime.InteropServices.NativeLibrary]::Load($Library)
            if (($LibraryHandle -eq 0)   -or ($LibraryHandle -eq $NULL))   { return (Write-Host "[!] Error! Null handle to target library '${Library}'." -ForegroundColor Red) }

            # Acquire the memory address of the target function via GetExport() method
            $FunctionAddress = [System.Runtime.InteropServices.NativeLibrary]::GetExport($LibraryHandle, $FunctionName)
            if (($FunctionAddress -eq 0) -or ($FunctionAddress -eq $NULL)) { return (Write-Host "[!] Error! Unable to find address to target function '${FunctionName}'." -ForegroundColor Red) }
        }
        else {
        
            # Get a reference to System.dll in the Global Assembly Cache (GAC)
            $SystemAssembly  = [AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.GlobalAssemblyCache -and ($_.Location -like '*\System.dll') }
            $UnsafeMethods   = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')

            # Get a reference to the GetModuleHandle() and GetProcAddress() functions
            $GetModuleHandle = $UnsafeMethods.GetMethod('GetModuleHandle', [type[]]('System.String'))
            $GetProcAddress  = $UnsafeMethods.GetMethod('GetProcAddress',  [type[]]('IntPtr','System.String'))

            # Get a handle to the target library (module) via GetModuleHandle()
            $LibraryHandle   = $GetModuleHandle.Invoke($Null, @($Library))
            if (($LibraryHandle -eq 0)   -or ($LibraryHandle -eq $NULL))   { return (Write-Host "[!] Error! Null handle to target library '${Library}'." -ForegroundColor Red) }

            # Acquire the memory address of the target function (proc) via GetProcAddress() 
            $FunctionAddress = $GetProcAddress.Invoke($Null, @($LibraryHandle, $FunctionName))
            if (($FunctionAddress -eq 0) -or ($FunctionAddress -eq $NULL)) { return (Write-Host "[!] Error! Unable to find address to target function '${FunctionName}'." -ForegroundColor Red) }
        }
    }
    Catch { return Generic-Error }

    $pNativeFunction = $FunctionAddress
    if ($Indirect) { $sysAddrNativeFunction = ($pNativeFunction -as [Int64]) + 0x12 }
  
    $lpBaseAddress       = $pNativeFunction                       # Starting address to begin reading (e.g., address of NtAllocateVirtualMemory).
    $lpBuffer            = [Array]::CreateInstance([byte],0x15)   # Buffer to receive contents 

    [System.Runtime.InteropServices.Marshal]::Copy(
        $lpBaseAddress,  # source
        $lpBuffer,       # destination
        0,               # index
        $lpBuffer.Length # size
    )

    $SSN          = [BitConverter]::ToUInt32($lpBuffer, 4)
    $sysAddrBytes = [BitConverter]::GetBytes($sysAddrNativeFunction)

    if ($Indirect) { $InvokeMethod = 'Indirect Syscall' }
    else           { $InvokeMethod = 'Direct Syscall'   }
    
    Write-Host '[!] SysCall Resolution:' -ForegroundColor Yellow
    Write-Host ' o  Target Library    -->  Ntdll.dll'
    Write-Host " o  Native Function   -->  ${FunctionName}"
    if ($GenStub)  { Write-Host " o  Invocation Method -->  ${InvokeMethod}" }
    Write-Host " o  Function Address  -->  $(Print-Hex -Integer $pNativeFunction)"
    if ($Indirect) { Write-Host " o  Syscall Address   -->  $(Print-Hex -Integer $sysAddrNativeFunction)" }
    Write-Host " o  Syscall ID        -->  $(Print-Hex -Integer $SSN)"

    if ($GenStub) {
    
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
    
        Write-Host '[!] SysCall Stub:' -ForegroundColor Yellow
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
}
