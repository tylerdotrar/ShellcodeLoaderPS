########################
### CREATEPROCESSA() ###
########################


### 1. Load Helper Function(s)

. ${PSScriptRoot}\..\Load-Win32Function.ps1
. ${PSScriptRoot}\..\Build-Win32Struct.ps1


### 2. Define Required Struct(s)

# PROCESS_INFORMATION
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
$StructMembers = @(
    [PSCustomObject]@{ Name = 'hProcess'    ; Type = [IntPtr] },
    [PSCustomObject]@{ Name = 'hThread'     ; Type = [IntPtr] },
    [PSCustomObject]@{ Name = 'dwProcessId' ; Type = [Int32]  },
    [PSCustomObject]@{ Name = 'dwThreadId'  ; Type = [Int32]  }
)
$CreatedType               = Build-Win32Struct -StructName "PROCESS_INFORMATION" -MembersObject $StructMembers
$ProcessInformationTypeRef = $CreatedType.MakeByRefType() # Used for creating function delegate
$ProcessInformation        = [PROCESS_INFORMATION]::new() # Used as Win32 function parameter

# STARTUPINFOA
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
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
$CreatedType        = Build-Win32Struct -StructName "STARTUPINFOA" -MembersObject $StructMembers
$StartupInfoTypeRef = $CreatedType.MakeByRefType() # Used for creating function delegate
$StartupInfo        = [STARTUPINFOA]::new()        # Used as Win32 function parameter

# SECURITY_ATTRIBUTES
# Ref: https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes
$StructMembers = @(
    [PSCustomObject]@{ Name = 'nLength'              ; Type = [Int32]  },
    [PSCustomObject]@{ Name = 'lpSecurityDescriptor' ; Type = [IntPtr] },
    [PSCustomObject]@{ Name = 'bInheritHandle'       ; Type = [Bool]   }
)
$CreatedType               = Build-Win32Struct -StructName "SECURITY_ATTRIBUTES" -MembersObject $StructMembers
$SecurityAttributesTypeRef = $CreatedType.MakeByRefType() # Used for creating function delegate
$ProcessAttributes         = [SECURITY_ATTRIBUTES]::new() # Used as Win32 function parameter
$ThreadAttributes          = [SECURITY_ATTRIBUTES]::new() # Used as Win32 function parameter


### 3. Load CreateProcess() Function into Session

# Ref: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
$ParamTypes = @(
    [String],                   #lpApplicationName
    [String],                   #lpCommandLine
    $SecurityAttributesTypeRef, #lpProcessAttributes
    $SecurityAttributesTypeRef, #lpThreadAttributes
    [Bool],                     #bInheritHandles
    [Int32],                    #dwCreationFlags
    [IntPtr],                   #lpEnvironment
    [String],                   #lpCurrentDirectory
    $StartupInfoTypeRef,        #lpStartupInfo
    $ProcessInformationTypeRef  #lpProcessInformation
)
$CreateProcessA = Load-Win32Function -Lib "kernel32.dll" -Func "CreateProcessA" -Param $ParamTypes -Ret ([Bool])


### 4. Launch "calc.exe"

# Function Argument(s)
$lpApplicationName    = "C:\Windows\system32\calc.exe"
$lpCommandLine        = $NULL
$lpProcessAttributes  = [ref]$ProcessAttributes
$lpThreadAttributes   = [ref]$ThreadAttributes
$bInheritHandles      = $False
$dwCreationFlags      = 0
$lpEnvironment        = [IntPtr]::Zero
$lpCurrentDirectory   = "C:"
$lpStartupInfo        = [ref]$StartupInfo
$lpProcessInformation = [ref]$ProcessInformation

Try { 
    $Success = $CreateProcessA.Invoke($lpApplicationName, $lpCommandLine, $lpProcessAttributes, $lpThreadAttributes, $bInheritHandles, $dwCreationFlags, $lpEnvironment, $lpCurrentDirectory, $lpStartupInfo, $lpProcessInformation)

    if ($Success) { Write-Host "[!] Success! PID: " -NoNewline -ForegroundColor Green; Write-Host $($ProcessInformation.dwProcessId)                  }
    else          { Write-Host "[!] Failure! Last Win32 Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" -ForegroundColor Red }
}
Catch {
    Write-Host "[!] Error occured! Return details:" -ForegroundColor Red
    $Error[0]
    $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
    $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
}