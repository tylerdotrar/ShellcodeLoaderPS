#######################
### NtOpenProcess() ###
#######################


### 1. Load Helper Function(s)

. ${PSScriptRoot}\..\Load-Win32Function.ps1
. ${PSScriptRoot}\..\Build-Win32Struct.ps1


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


### 3. Define Required Enum(s)

# Reference: https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
$Process = @{
    PROCESS_ALL_ACCESS        = 0x000F0000 -bor 0x00100000 -bor 0xFFFF;
    PROCESS_CREATE_THREAD     = 0x0002;
    PROCESS_QUERY_INFORMATION = 0x0400;
    PROCESS_VM_OPERATION      = 0x0008;
    PROCESS_VM_READ           = 0x0010;
    PROCESS_VM_WRITE          = 0x0020;
}


### 3. Load NtOpenProcess() Function into session

Write-Host '[!] Loading Win32 API Calls...' -ForegroundColor Yellow

# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa
$NtOpenProcArgs = @(
    [IntPtr].MakeByRefType()  # ProcessHandle (return value)
    [UInt32],                 # DesiredAccess
    $ObjectAttributesTypeRef, # ObjectAttributes
    $ClientIdTypeRef          # ClientId
)
$NtOpenProcess = Load-Win32Function -Library "Ntdll.dll" -FunctionName "NtOpenProcess" -ParamTypes $NtOpenProcArgs -ReturnType ([Bool])
Write-Host ' o  Function ' -NoNewline ; Write-Host "'Ntdll!NtOpenProcess()'" -NoNewline -ForegroundColor Green ; Write-Host ' loaded into session.'


### 4. Acquire process handle.

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
$ProcessHandle    = [ref][IntPtr]::Zero          # Returned handle to process
$DesiredAccess    = $Process.PROCESS_ALL_ACCESS  # Desired access rights                (i.e., PROCESS_ALL_ACCESS).
$ObjectAttributes = [ref]$OBJECT_ATTRIBUTES      # Pointer to OBJECT_ATTRIBUTES struct  (i.e., no -- ignore this).
$ClientId         = [ref]$CLIENT_ID              # Pointer to CLIENT_ID struct          (i.e., current process PID).

Try {
    Write-Host '[!] Acquiring handle to target process...' -ForegroundColor Yellow

    $Failed = $NtOpenProcess.Invoke($ProcessHandle, $DesiredAccess, $ObjectAttributes, $ClientId)
    
    if (!$Failed) {
        Write-Host " o  " -NoNewline ; Write-Host 'NtOpenProcess()' -ForegroundColor Green
        Write-Host " o  --> Target PID      : " -NoNewline ; Write-Host ${PID} -ForegroundColor Yellow
        Write-host " o  --> Process Handle  : " -NoNewline ; Write-Host ${ProcessHandle}.Value -ForegroundColor Yellow
    }
    else { return (Write-Host "[!] Error! Failed to acquire handle to target process via NtOpenProcess().`n o  Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red) }
}

Catch {
    Write-Host "[!] Error occured! Return details:" -ForegroundColor Red
    $Error[0]
    $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
    $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
}