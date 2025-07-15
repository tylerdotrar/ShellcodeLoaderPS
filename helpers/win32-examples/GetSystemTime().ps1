#######################
### GETSYSTEMTIME() ###
#######################


### 1. Load Helper Function(s)

. ${PSScriptRoot}\..\Load-Win32Function.ps1
. ${PSScriptRoot}\..\Build-Win32Struct.ps1


### 2. Define Required Struct(s)

# SYSTEMTIME
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-systemtime
$SystemTimeMembers = @(
    [PSCustomObject]@{ Name = 'wYear'         ; Type = [UInt16] },
    [PSCustomObject]@{ Name = 'wMonth'        ; Type = [UInt16] },
    [PSCustomObject]@{ Name = 'wDayOfWeek'    ; Type = [UInt16] },
    [PSCustomObject]@{ Name = 'wDay'          ; Type = [UInt16] },
    [PSCustomObject]@{ Name = 'wHour'         ; Type = [UInt16] },
    [PSCustomObject]@{ Name = 'wMinute'       ; Type = [UInt16] },
    [PSCustomObject]@{ Name = 'wSecond'       ; Type = [UInt16] },
    [PSCustomObject]@{ Name = 'wMilliseconds' ; Type = [UInt16] }
)
$CreatedType       = Build-Win32Struct -StructName "SYSTEMTIME" -MembersObject $SystemTimeMembers
$SystemTimeTypeRef = $CreatedType.MakeByRefType()
$SystemTime        = [SYSTEMTIME]::new()


### 3. Load GetSystemTime() Function into session

# Ref: https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtime
$ParamTypes = @(
    $SystemTimeTypeRef #lpSystemTime
)
$GetSystemTime = Load-Win32Function -Lib "kernel32.dll" -Func "GetSystemTime" -Param $ParamTypes -Ret ([Void])


### 4. Get Current System Time & Check Return

# Function Argument(s)
$lpSystemTime = [ref]$SystemTime

Try {
    $GetSystemTime.Invoke($lpSystemTime)
    Write-Host '[!] System Time: ' -NoNewline -ForegroundColor Green ; $SystemTime
}
Catch {
    Write-Host "[!] Error occured! Return details:" -ForegroundColor Red
    $Error[0]
    $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
    $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
}