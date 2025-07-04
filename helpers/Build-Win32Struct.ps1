function Build-Win32Struct {
#.SYNOPSIS
# PowerShell Script to Create Win32 Data Structures without using Add-Type
# Arbitrary Version Number: v1.0.0
# Author: Tyler C. McCann (@tylerdotrar)
#
#.DESCRIPTION
# This is a streamlined script intended to create Win32 data structures that are usable within PowerShell when
# interacting with the Win32 API, all without the usage of C# or Add-Type. While Add-Type is a much easier and
# convenient method of loading Win32 functions into session, the utilization of 'csc.exe' as well as both 
# compiling and leaving files on disk make it a bit suboptimal.  Plus, relying on literal C# code to get a 
# PowerShell script working feels like cheating.
#
# Parameters:
#   -StructName     -->  Name of the stuct (e.g., "PROCESS_INFORMATION").
#   -MembersObject  -->  Optional: Custom array containing struct member names and types.
#   -MemberNames    -->  Array only containing struct member names.
#   -MemberTypes    -->  Array only containing struct member types.
#   -Help           -->  Return Get-Help information.
#
# Example Usage:
#   PS> $StructMembers = @(
#           [PSCustomObject]@{ Name = 'hProcess'    ; Type = [IntPtr] },
#           [PSCustomObject]@{ Name = 'hThread'     ; Type = [IntPtr] },
#           [PSCustomObject]@{ Name = 'dwProcessId' ; Type = [Int]    },
#           [PSCustomObject]@{ Name = 'dwThreadId'  ; Type = [Int]    }
#       )
#   PS> $CreatedType               = Build-Win32Struct -StructName "PROCESS_INFORMATION" -MembersObject $StructMembers
#   PS> $ProcessInformationTypeRef = $CreatedType.MakeByRefType() # Used for creating function delegate
#   PS> $ProcessInformation        = [PROCESS_INFORMATION]::new() # Used as Win32 function parameter
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

    # Create a dynamic in-memory assembly and module to define the struct
    $Domain          = [AppDomain]::CurrentDomain
    $DynAssembly     = [System.Reflection.AssemblyName]::new([guid]::NewGuid().ToString())                              # Generate unique name for the assembly
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run) # Define in-memory assembly (no disk artifacts)
    $ModuleBuilder   = $AssemblyBuilder.DefineDynamicModule([guid]::NewGuid().ToString(), $False)                       # Generate unique name for the in-memory module

    # Create a value type (struct) with public, sequential layout for interop
    $Attributes  = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType($StructName, $Attributes, [System.ValueType])

    # Define public fields for each struct member
    foreach ($Member in $MembersObject) {
        [void]$TypeBuilder.DefineField($Member.Name, $Member.Type, 'Public')
    }

    # Return the type (struct) definition
    return $TypeBuilder.CreateType()
}