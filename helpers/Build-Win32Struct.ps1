function Build-Win32Struct {
#.SYNOPSIS
# PowerShell Script to Create Win32 Data Structures in Memory
# Arbitrary Version Number: v1.0.2
# Author: Tyler C. McCann (@tylerdotrar)
#
#.DESCRIPTION
# This is a streamlined script intended to create Win32 data structures that are usable within PowerShell when
# interacting with the Win32 API, all without the utilization of Add-Type or embedded C# code. While Add-Type
# is a much easier and convenient method of loading native Win32 API functions into session, the utilization
# of 'csc.exe' as well as both compiling and leaving files on disk make it a bit suboptimal.
#
# Plus, relying on literal C# code to get a PowerShell script working feels like cheating.
#
# Parameters:
#   -StructName     -->  Name of the stuct (e.g., "PROCESS_INFORMATION").
#   -MembersObject  -->  Optional: Custom array containing struct member names and types.
#   -MemberNames    -->  Array only containing struct member names.
#   -MemberTypes    -->  Array only containing struct member types.
#   -Help           -->  Return Get-Help information.
#
# Example Usage:
#  ________________________________________________________________________________________________________________________
# |                                                                                                                        |
# | # Method 1:  Create custom struct via simple name & type arrays                                                        |
# | PS> $NameArray   = @('hProcess', 'hThread', 'dwProcessId', 'dwThreadId')                                               |
# | PS> $TypeArray   = @([IntPtr], [IntPtr], [Int], [Int])                                                                 |
# | PS> $CreatedType = Build-Win32Struct -StructName "PROCESS_INFORMATION" -MemberNames $NameArray -MemberTypes $TypeArray |
# |                                                                                                                        |
# | # Method 2:  Create custom struct via an object containing names & types                                               |
# | PS> $StructMembers = @(                                                                                                |
# |         [PSCustomObject]@{ Name = 'hProcess'    ; Type = [IntPtr] },                                                   |
# |         [PSCustomObject]@{ Name = 'hThread'     ; Type = [IntPtr] },                                                   |
# |         [PSCustomObject]@{ Name = 'dwProcessId' ; Type = [Int]    },                                                   |
# |         [PSCustomObject]@{ Name = 'dwThreadId'  ; Type = [Int]    }                                                    |
# |      )                                                                                                                 |
# | PS> $CreatedType = Build-Win32Struct -StructName "PROCESS_INFORMATION" -MembersObject $StructMembers                   |
# |                                                                                                                        |
# | # Load created struct type into the session                                                                            |
# | PS> $ProcessInformationTypeRef = $CreatedType.MakeByRefType() # Used for creating function delegate(s)                 |
# | PS> $ProcessInformation        = [PROCESS_INFORMATION]::new() # Used for Win32 function parameter(s)                   |
# |________________________________________________________________________________________________________________________|
#
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS


    Param (
        [string]$StructName,
        [array] $MembersObject, # MemberNames + MemberTypes
        [array] $MemberNames,   
        [array] $MemberTypes,
        [switch]$Help
    )


    # Return Get-Help Information
    if ($Help) { return (Get-Help Build-Win32Struct) }


    # Minor Error Correction
    if (!$StructName) { return (Write-Host '[!] Error! Missing struct name.' -ForegroundColor Red) }
    if (!$MembersObject) {
        if (!$MemberNames -and !$MemberTypes)            { return (Write-Host '[!] Error! Requires member names AND member types.' -ForegroundColor Red)              }
        if ($MemberNames.Length -ne $MemberTypes.Length) { return (Write-Host '[!] Error! Member names and member types are different lengths.' -ForegroundColor Red) }

        # Build Custom Members Object
        $MembersObject = @()
        for ($i = 0 ; $i -lt $MemberNames.Length ; $i++) {
            $MembersObject += [PSCustomObject]@{ Name = $MemberNames[$i] ; Type = $MemberTypes[$i] }
        }
    }

   
    # Check if the struct type already exists in the current session
    foreach ($Assembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        $CustomType = $Assembly.GetType($StructName, $False)
        if ($CustomType -ne $NULL) { return $CustomType }
    }

    # Generate a unique in-memory .NET assembly name to host delegate type
    $DynAssembly = [System.Reflection.AssemblyName]::new([guid]::NewGuid().ToString())

    # Define non-persistent assembly in memory with execute-only permissions
    $AssemblyBuilder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder   = $AssemblyBuilder.DefineDynamicModule([guid]::NewGuid().ToString())

    # Create a public value type (struct) with sequential memory layout for unmanaged interop
    $Attributes  = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType($StructName, $Attributes, [System.ValueType])

    # Define public fields for each struct member
    foreach ($Member in $MembersObject) {
        [void]$TypeBuilder.DefineField($Member.Name, $Member.Type, 'Public')
    }

    # Return the value type (struct) definition as a usable .NET type
    return $TypeBuilder.CreateType()
}