function Load-Win32Function {
#.SYNOPSIS
# PowerShell Script to Load Win32 Functions into Session via Function Delegates
# Arbitrary Version Number: v1.0.5
# Author: Tyler C. McCann (@tylerdotrar)
#
#.DESCRIPTION
# This is a streamlined script intended to load Win32 API calls into PowerShell sessions without requiring the
# usage of Add-Type or embedded C# code.  This is done by acquiring raw function pointers, then wrapping them
# with .NET argument delegates.  While Add-Type is a much easier and convenient method of loading native Win32
# API functions into session, the utilization of 'csc.exe' as well as both compiling and leaving files on disk
# make it suboptimal (plus, relying on literal C# code to get a PowerShell script working feels like cheating).
#
# Parameters:
#   -Library       -->  Library/DLL containing the target function.
#   -FunctionName  -->  Target Win32 function to load into session.
#   -ParamTypes    -->  Array of data-types for each function parameter (in order).
#   -ReturnType    -->  Data-type of the return of the function.
#   -Help          -->  Return Get-Help information.
#
# Example Usage:
#  _____________________________________________________________________________________________________________________________________
# |                                                                                                                                     |
# | # Method 1:  Load MessageBoxA() into the current PowerShell session succinctly                                                      |
# | PS> $MessageBoxA = Load-Win32Function -Lib "user32.dll" -Func "MessageBoxA" -Param @([IntPtr],[String],[String],[Int]) -Ret ([Int]) |
# |                                                                                                                                     |
# | # Method 2:  Load MessageBoxA() into the current PowerShell session verbosely                                                       |
# | PS> $MsgArgs = @(                                                                                                                   |
# |         [IntPtr], # hWnd                                                                                                            |
# |         [String], # lpText                                                                                                          |
# |         [String], # lpCaption                                                                                                       |
# |         [Int]     # uType                                                                                                           |
# |     )                                                                                                                               |
# | PS> $MessageBoxA = Load-Win32Function -Library "User32.dll" -FunctionName "MessageBoxA" -ParamTypes $MsgArgs -ReturnType ([Int])    |
# |                                                                                                                                     |
# | # Invoke MessageBoxA()                                                                                                              |
# | PS> $MessageBoxA.Invoke([IntPtr]::Zero, 'Box contents here!', 'Box Title Here', 0)                                                  |
# |_____________________________________________________________________________________________________________________________________|
# 
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS


    Param(
        [string]$Library,
        [string]$FunctionName,
        [type[]]$ParamTypes = @($null),
        [type]  $ReturnType = [Void],
        [switch]$Help
    )


    # Return Get-Help Information
    if ($Help) { return (Get-Help Load-Win32Function) }


    # Minor Error Correction
    if (!$Library)      { return (Write-Host '[!] Error! Missing library (e.g., "user32.dll").' -ForegroundColor Red)          }
    if (!$FunctionName) { return (Write-Host '[!] Error! Missing target function (e.g., "MessageBoxA").' -ForegroundColor Red) }


    # Step 1: Acquire Memory Address of Target Win32 Function

    Try {
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
    Catch {
        # return Generic-Error
        Write-Host "[!] Error acquiring function memory address! Return details:" -ForegroundColor Red
        $Error[0]
        $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
        $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
        return
    } 

    # Step 2: Build Win32 Function Delegate for Parameter Types and Return Types

    # Check if the function delegate already exists in the current session
    foreach ($Assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        $CustomType = $Assembly.GetType($FunctionName, $False)
        if ($CustomType -ne $NULL) {
            $FunctionDelegate = $CustomType
            break
        }
    }

    # Build the function delegate from scratch
    if (!$FunctionDelegate) {

        Try {
            # Define unique .NET assembly in memory to host delegate type
            $DynAssembly        = [System.Reflection.AssemblyName]::new([guid]::NewGuid().ToString())
            $AssemblyBuilder    = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder      = $AssemblyBuilder.DefineDynamicModule([guid]::NewGuid().ToString())

            # Define new delegate type to match unmanaged Win32 function signature
            $TypeBuilder        = $ModuleBuilder.DefineType($FunctionName, 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

            # Define special constructor for the delegate type (required by CLR to instantiate the delegate from a function pointer)
            $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr])) 
            $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')

            # Define 'Invoke' method with the correct function parameter type(s) and return type(s)
            $MethodBuilder      = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $ParamTypes)
            $MethodBuilder.SetImplementationFlags('Runtime, Managed')

            # Return the usable, dynamic delegate type for function pointer invocation
            $FunctionDelegate   = $TypeBuilder.CreateType()
        }
        Catch {
            # return Generic-Error
            Write-Host "[!] Error building function delegate! Return details:" -ForegroundColor Red
            $Error[0]
            $_.Exception | Select-Object -Property ErrorRecord,Source,HResult | Format-List
            $_.InvocationInfo | Select-Object -Property PSCommandPath,ScriptLineNumber,Statement | Format-List
            return
        }
    }

    # Return usable function to session
    return [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FunctionAddress, $FunctionDelegate)
}