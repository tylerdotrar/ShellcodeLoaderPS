function Load-Win32Function {
#.SYNOPSIS
# PowerShell Script to Load Win32 API Calls into Session via the GAC
# Arbitrary Version Number: v1.0.0
# Author: Tyler C. McCann (@tylerdotrar)
#
#.DESCRIPTION
# This is a streamlined script intended to load Win32 API calls into PowerShell sessions without requiring the
# usage of C# or Add-Type by utilizing data accessible within the Global Assembly Cache (GAC).  While Add-Type
# is a much easier and convenient method of loading Win32 functions into session, the utilization of 'csc.exe'
# as well as both compiling and leaving files on disk make it a bit suboptimal.  Plus, relying on literal C# 
# code to get a PowerShell script working feels like cheating.
#
# Parameters:
#   -Library       -->  Library/DLL containing the target function.
#   -FunctionName  -->  Target Win32 function to load into session.
#   -ParamTypes    -->  Array of data-types for each function parameter (in order).
#   -ReturnType    -->  Data-type of the return of the function.
#   -Help          -->  Return Get-Help information.
#
# Example Usage:
#   PS> $MessageBoxA = Load-Win32Function -Lib "user32.dll" -Func "MessageBoxA" -Param @([IntPtr],[String],[String],[Int]) -Ret ([Int])
#   PS> $MessageBoxA.Invoke([IntPtr]::Zero, 'Box contents here!', 'Box Title Here', 0)
#
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS


    Param(
        [string]$Library,
        [string]$FunctionName,
        [type[]]$ParamTypes    = @($null),
        [type]  $ReturnType    = [Void],
        [switch]$Help
    )


    # Return Get-Help Information
    if ($Help) { return (Get-Help Load-Win32Function) }


    # Minor Error Correction
    if ($PSVersionTable.PSEdition -eq 'Core') { return (Write-Host '[!] Error! PowerShell Core does not utilize the Global Assembly Cache (GAC).' -ForegroundColor Red) }
    if (!$Library)      { return (Write-Host '[!] Error! Missing library (e.g., "user32.dll").' -ForegroundColor Red)          }
    if (!$FunctionName) { return (Write-Host '[!] Error! Missing target function (e.g., "MessageBoxA").' -ForegroundColor Red) }


    ### Step 1: Acquire Memory Address of Target Win32 Function

    Try {
        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.GlobalAssemblyCache -and ($_.Location -like '*\System.dll') }
        $UnsafeMethods  = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')

        # Get a reference to the GetModuleHandle() and GetProcAddress() functions
        $GetModuleHandle = ($UnsafeMethods.GetMethods() | ? {$_.Name -eq 'GetModuleHandle'})[0]
        $GetProcAddress  = ($UnsafeMethods.GetMethods() | ? {$_.Name -eq 'GetProcAddress'})[0]

        # Get a handle to the target library (module) via GetModuleHandle()
        $LibraryHandle   = $GetModuleHandle.Invoke($Null, @($Library))
        if (($LibraryHandle -eq 0) -or ($LibraryHandle -eq $NULL)) { return (Write-Host "[!] Error! Null handle to target library '${Library}'." -ForegroundColor Red) }

        # Acquire the memory address of the target function (proc) via GetProcAddress() 
        $FunctionAddress = $GetProcAddress.Invoke($Null, @($LibraryHandle, $FunctionName))
        if (($FunctionAddress -eq 0) -or ($FunctionAddress -eq $NULL)) { return (Write-Host "[!] Error! Unable to find address to target function '${FunctionName}'." -ForegroundColor Red) }
    }
    Catch {
        Write-Host "[!] Error acquiring function memory address! Return details:" -ForegroundColor Red
        $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
        $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
        return
    } 


    ### Step 2: Build Win32 Function Delegate for Parameter Types and Return Types

    Try {
        $AssemblyBuilder    = [AppDomain]::CurrentDomain.DefineDynamicAssembly([System.Reflection.AssemblyName]::new('ReflectedDelegate'), [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $TypeBuilder        = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')

        # Specify target function parameter types and return type
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $ParamTypes)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')

        $FunctionDelegate = $TypeBuilder.CreateType()
    }
    Catch {
        Write-Host "[!] Error acquiring function memory address! Return details:" -ForegroundColor Red
        $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
        $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
        return
    }


    # Return Formatted Function
    return [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FunctionAddress, $FunctionDelegate)
}