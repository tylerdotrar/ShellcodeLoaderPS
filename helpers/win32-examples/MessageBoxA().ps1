#####################
### MESSAGEBOXA() ###
#####################


### 1. Load Helper Function(s)

. ${PSScriptRoot}\..\Load-Win32Function.ps1


### 2. Define Required Struct(s)

# None required for MessageBoxA().


### 3. Load MessageBoxA() Function into session

# Ref: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa
$ParamTypes = @(
    [IntPtr], #hWnd
    [String], #lpText
    [String], #lpCaption
    [Int]     #uType
)
$MessageBoxA = Load-Win32Function -Lib "user32.dll" -Func "MessageBoxA" -Param $ParamTypes -Ret ([Int])


### 4. Spawn Message Box

# Function Argument(s)
$hWnd      = [IntPtr]::Zero
$lpText    = 'Box contents here!'
$lpCaption = 'Box Title Here'
$uType     = 0

Try {
    $Success = $MessageBoxA.Invoke($hWnd, $lpText, $lpCaption, $uType)

    if ($Success) { Write-Host "[!] Success!" -ForegroundColor Green                                                                                  }
    else          { Write-Host "[!] Failure! Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red }
}
Catch {
    Write-Host "[!] Error occured! Return details:" -ForegroundColor Red
    $Error[0]
    $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
    $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
}