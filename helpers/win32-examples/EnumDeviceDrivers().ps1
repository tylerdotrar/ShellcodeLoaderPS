###########################
### ENUMDEVICEDRIVERS() ###
###########################

# (Requires elevated privileges)

### 1. Load Helper Function(s)

. ${PSScriptRoot}\..\Load-Win32Function.ps1


### 2. Define Required Struct(s)
# N/A


### 3. Load Function into session

$ParamTypes = @(
    [UInt64[]],              # lpImageBase
    [Int32],                 # cb 
    [UInt32].MakeByRefType() # lpcbNeeded

)
$EnumDeviceDrivers = Load-Win32Function -Lib "psapi.dll" -Func "EnumDeviceDrivers" -Param $ParamTypes -Ret ([Bool])


### 4. Get Kernel Base Address

# Function Argument(s)
$lpImageBase = [Array]::CreateInstance([UInt64],1024)
$cb          = $lpImageBase.Length
$lpcbNeeded  = [ref]0

Try {
    if ( $EnumDeviceDrivers.Invoke($lpImageBase, $cb, $lpcbNeeded) ) {
        
        if ($lpImageBase[0] -eq 0) { return (Write-Host '[!] Error! Null base address indicates lack of SeDebugPrivilege.' -ForegroundColor Red) }

        Write-Host "[!] Success! Found the Kernel Base Address (ntoskrnl.exe)." -ForegroundColor Yellow
        Write-Host " o  Int : " -NoNewLine ; Write-Host $($lpImageBase[0]) -ForegroundColor Green
        Write-Host " o  Hex : " -NoNewLine ; Write-Host $('0x' + '{0:X}' -f $lpImageBase[0]) -ForegroundColor Green
	      #return $lpImageBase
    } else { Write-Host '[!] Failure! EnumDeviceDrivers returned false.' -ForegroundColor Red }
}
Catch {
    Write-Host "[!] Error occured! Return details:" -ForegroundColor Red
    $Error[0]
    $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
    $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
}
