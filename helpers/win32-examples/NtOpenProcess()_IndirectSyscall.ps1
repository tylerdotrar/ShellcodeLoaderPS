#######################
### NtOpenProcess() ###
#######################

# (via direct & indirect syscalls)


### 1. Load Helper Function(s)

. ${PSScriptRoot}\..\Load-Win32Function.ps1
. ${PSScriptRoot}\..\Build-Win32Struct.ps1
. ${PSScriptRoot}\..\SysCall-Resolver.ps1

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
    return ('0x{0:x2}' -f $Integer)
}


### 2. Define Required Struct(s)

# OBJECT_ATTRIBUTES
# Ref: https://ntdoc.m417z.com/object_attributes
# Ref: https://www.pinvoke.net/default.aspx/Structures/OBJECT_ATTRIBUTES.html
$StructMembers = @(
    [PSCustomObject]@{ Name = 'Length'                   ; Type = [UInt32] },
    [PSCustomObject]@{ Name = 'RootDirectory'            ; Type = [IntPtr] },
    [PSCustomObject]@{ Name = 'ObjectName'               ; Type = [IntPtr] },
    [PSCustomObject]@{ Name = 'Attributes'               ; Type = [UInt32] },
    [PSCustomObject]@{ Name = 'SecurityDescriptor'       ; Type = [IntPtr] },
    [PSCustomObject]@{ Name = 'SecurityQualityOfService' ; Type = [IntPtr] }
)
$ObjectAttributesType    = Build-Win32Struct -StructName "OBJECT_ATTRIBUTES" -MembersObject $StructMembers
$ObjectAttributesTypeRef = $ObjectAttributesType.MakeByRefType() # Used for creating function delegate(s)
$OBJECT_ATTRIBUTES       = [OBJECT_ATTRIBUTES]::new()            # Used for Win32 function parameter(s)

# CLIENT_ID
# Ref: https://ntdoc.m417z.com/client_id
# Ref: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/a11e7129-685b-4535-8d37-21d4596ac057
$StructMembers = @(
    [PSCustomObject]@{ Name = 'UniqueProcess'    ; Type = [UInt32] },
    [PSCustomObject]@{ Name = 'UniqueThread'     ; Type = [IntPtr] }
)
$ClientIdType    = Build-Win32Struct -StructName "CLIENT_ID" -MembersObject $StructMembers
$ClientIdTypeRef = $ClientIdType.MakeByRefType() # Used for creating function delegate(s)
$CLIENT_ID       = [CLIENT_ID]::new()            # Used for Win32 function parameter(s)


### 3. Define Required Constants(s)

# Ref: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
$ProcessAccess = @{
    PROCESS_ALL_ACCESS        = 0x000F0000 -bor 0x00100000 -bor 0xFFFF; # used
    PROCESS_CREATE_THREAD     = 0x0002;
    PROCESS_QUERY_INFORMATION = 0x0400;
    PROCESS_VM_OPERATION      = 0x0008;
    PROCESS_VM_READ           = 0x0010;
    PROCESS_VM_WRITE          = 0x0020;
}
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
$MemoryAllocation = @{
    MEM_COMMIT  = 0x00001000; # used
    MEM_RESERVE = 0x00002000; # used
}
# Ref: https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
$MemoryProtection = @{
    PAGE_EXECUTE           = 0x10;
    PAGE_EXECUTE_READ      = 0x20; #used
    PAGE_READWRITE         = 0x04;
    PAGE_EXECUTE_READWRITE = 0x40; #used
}

### 3. Load NtOpenProcess() Function into session

Write-Host '[!] Loading Win32 API Calls...' -ForegroundColor Yellow

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
    [IntPtr],                 #hProcess
    [IntPtr],                 #lpAddress
    [UInt32],                 # dwSize
    [UInt32],                 # flNewProtect
    [UInt32].MakeByRefType()  # lpflOldProtect
)
$VirtualProtectEx = Load-Win32Function -Library "Kernel32.dll" -FunctionName "VirtualProtectEx" -ParamTypes $VirtProtectExArgs -ReturnType ([Bool])


### Create SysCall Stub

$SysCallStub = SysCall-Resolver -FunctionName "NtOpenProcess" -Indirect


### Load Syscall Stub into Current Process

Write-Host "[!] Allocating memory within the current process..." -ForegroundColor Yellow

# VirtualAllocEx()
#  > Definition : Allocates memory within an external process and returns a pointer to said space.
#  > Location   : Kernel32.dll
#  > Reference  : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    
# Argument(s)
$hProcess         = [IntPtr](-1)                                                     # Handle to the target process (i.e., pseudo-handle).
$lpAddress        = [IntPtr]::Zero                                                   # Starting address in memory to allocate (i.e., if null this is dynamically determined).
$dwSize           = $SysCallStub.Length                                              # Size of the memory allocation in bytes.
$flAllocationType = $MemoryAllocation.MEM_COMMIT -bor $MemoryAllocation.MEM_RESERVE  # Flags for memory allocation type. 
$flProtect        = $MemoryProtection.PAGE_READWRITE                                 # Memory protection flags for the allocated region.

Write-Host ' o  ' -NoNewline ; Write-Host 'VirtualAllocEx()' -ForegroundColor Green

Try   { $StubAddress = $VirtualAllocEx.Invoke($hProcess, $lpAddress, $dwSize, $flAllocationType, $flProtect) }
Catch { return Generic-Error }
    
if ($StubAddress -eq 0) { return Win32-Error }
Write-Host " o  --> Allocated Memory Address : $(Print-Hex $StubAddress)"
Write-Host " o  --> Memory Block Size        : ${dwSize} bytes"
Write-Host " o  --> Memory Protection        : 0x04 (PAGE_READWRITE)"
       

Write-Host "[!] Writing syscall stub buffer to allocated memory..." -ForegroundColor Yellow

# WriteProcessMemory()
#  > Definition : Write data to an area of memory within a specified process.
#  > Location   : Kernel32.dll
#  > Reference  : https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

# Argument(s)
$hProcess               = [IntPtr](-1)        # Handle to the target process                       (i.e., acquired from OpenProcess).
$lpBaseAddress          = $StubAddress        # Starting address in memory to begin writing        (i.e., acquired from VirtualAllocEx).
$lpBuffer               = $SysCallStub        # Pointer to the memory to copy                      (i.e., target shellcode).
$nSize                  = $SysCallStub.Length # Size of the memory to copy                         (i.e., size of the shellcode).
$lpNumberOfBytesWritten = 0                   # Output variable to receive number of bytes written (i.e., essentially a throwaway variable).
    
Write-Host ' o  ' -NoNewline ; Write-Host 'WriteProcessMemory()' -ForegroundColor Green

Try   { $MemoryCopied = $WriteProcessMemory.Invoke($hProcess, $lpBaseAddress, $lpBuffer, $nSize, [ref]$lpNumberOfBytesWritten) }
Catch { return Generic-Error }

if (!$MemoryCopied) { return Win32-Error }
Write-Host " o  --> SysCall Stub Buffer Copied : ${MemoryCopied}"


Write-Host '[!] Changing memory buffer protection...' -ForegroundColor Yellow

# VirtualProtectEx()
#  > Definition  :  Changes the protection of a region of memory within a specified process.
#  > Location    :  Kernel32.dll
#  > Reference   :  https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect

# Argument(s)
$hProcess       = [IntPtr](-1)                        # Handle to the target process.   
$lpAddress      = $StubAddress                        # Pointer to the starting address in memory to change.
$dwSize         = $SysCallStub.Length                 # Size of the target memory buffer in bytes.
$flNewProtect   = $MemoryProtection.PAGE_EXECUTE_READ # Memory protection flags for the specified region.
$lpflOldProtect = 0                                   # Output variable to receive old memory protection flags.

Write-Host ' o  ' -NoNewline; Write-Host 'VirtualProtectEx()' -ForegroundColor Green

Try   { $Success = $VirtualProtectEx.Invoke($hProcess, $lpAddress, $dwSize, $flNewProtect, [ref]$lpflOldProtect) }
Catch { return Generic-Error }

if (!$Success) { return Win32-Error }
Write-Host ' o  --> Memory Protection : 0x20 (PAGE_EXECUTE_READ)'
          

### 4. Acquire process handle via Direct SysCall.

Write-Host '[!] Loading SysCall via Allocated Stub...' -ForegroundColor Yellow
$NtOpenProcArgs = @(
    [IntPtr].MakeByRefType()  # ProcessHandle (return value)
    [UInt32],                 # DesiredAccess
    $ObjectAttributesTypeRef, # ObjectAttributes
    $ClientIdTypeRef          # ClientId
)
$NtOpenProcess = Load-Win32Function -FunctionName "NtOpenProcess" -FunctionAddress $StubAddress -ParamTypes $NtOpenProcArgs -ReturnType ([Bool])

# Function Argument(s)

# NtOpenProcess()
#  > Description : Acquire a handle to process.
#  > Location    : Ntdll.dll
#  > Reference   : https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess

# Initialize Struct(s)
$OBJECT_ATTRIBUTES.Length                   = [IntPtr]::Size * 6
$OBJECT_ATTRIBUTES.RootDirectory            = [IntPtr]::Zero
$OBJECT_ATTRIBUTES.ObjectName               = [IntPtr]::Zero
$OBJECT_ATTRIBUTES.Attributes               = 0
$OBJECT_ATTRIBUTES.SecurityDescriptor       = [IntPtr]::Zero
$OBJECT_ATTRIBUTES.SecurityQualityOfService = [IntPtr]::Zero

$CLIENT_ID.UniqueProcess = $PID # Current PowerShell process
$CLIENT_ID.UniqueThread  = [IntPtr]::Zero

# Argument(s)
$ProcessHandle    = [ref][IntPtr]::Zero                # Returned handle to process
$DesiredAccess    = $ProcessAccess.PROCESS_ALL_ACCESS  # Desired access rights                (i.e., PROCESS_ALL_ACCESS).
$ObjectAttributes = [ref]$OBJECT_ATTRIBUTES            # Pointer to OBJECT_ATTRIBUTES struct  (i.e., no -- ignore this).
$ClientId         = [ref]$CLIENT_ID                    # Pointer to CLIENT_ID struct          (i.e., current process PID).

Try {
    Write-Host '[!] Acquiring handle to target process...' -ForegroundColor Yellow

    $Failed = $NtOpenProcess.Invoke($ProcessHandle, $DesiredAccess, $ObjectAttributes, $ClientId)
    
    if (!$Failed) {
        Write-Host " o  " -NoNewline ; Write-Host 'NtOpenProcess()' -ForegroundColor Green
        Write-Host " o  --> Target PID      : " -NoNewline ; Write-Host ${PID} -ForegroundColor Yellow
        Write-host " o  --> Process Handle  : " -NoNewline ; Write-Host ${ProcessHandle}.Value -ForegroundColor Yellow
    }
    else { return Win32-Error }
}

Catch { return Generic-Error }
