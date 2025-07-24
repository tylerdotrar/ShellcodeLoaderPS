function Format-ByteArray {
#.SYNOPSIS
# PowerShell Script to Convert Multi-Language Shellcode Strings into Byte Arrays
# Arbitrary Version Number: v1.0.2
# Author: Tyler C. McCann (@tylerdotrar)
#
#.DESCRIPTION
# The purpose of this tool is to allow for convenient shellcode formatting.  Most shellcode generators
# (understandably) do not format shellcode for PowerShell -- this tool will take shellcode strings
# formatted for other langauges and convert them into byte arrays usable within PowerShell.
#
# The `-Shellcode` parameter is intentionally undeclared and written to accept most shellcode formats.
# Currently supports strings [string] and byte arrays [byte[]].  If a standard array [array] is used,
# the array will be converted to a string prior to language detection. If a byte array is used, no
# formatting will occur.
#
# Supported String Formats:
#   o  Path to Raw Shellcode    --  .\shellcode.bin
#   o  Python Shellcode Format  --  'b"\x45\x78\x61\x6d\x70\x6c\x65"'
#   o  C Shellcode Format       --  '\x45\x78\x61\x6d\x70\x6c\x65'
#   o  C++/C# Shellcode Format  --  '{0x45,0x78,0x61,0x70,0x6c,0x65}'
#
# Parameters:
#   -Shellcode  -->  Target shellcode blob to convert to byte array.
#   -Help       -->  Return Get-Help information.
#
# Example:
#  _________________________________________________________________________
# |                                                                         |
# | # Create a variable containing shellcode in a supported language        |
# | PS> $string = <msfvenom_output>                                         |
# |                                                                         |
# | # Convert shellcode string into a usable byte array                     |
# | PS> $shellcode = Format-ByteArray -Shellcode $string                    |
# |                                                                         |
# | # Optional: Save shellcode to a file                                    |
# | PS> [System.IO.File]::WriteAllBytes("${PWD}\shellcode.bin", $shellcode) |
# |_________________________________________________________________________|
# 
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS
    

    Param(
        $Shellcode,   # Intentionally vague type for maximum compatibility
        [switch]$Help
    )


    # Return Get-Help Information
    if ($Help) { return (Get-Help Format-ByteArray) }


    # Minor Error Correction
    if (!$Shellcode) { return (Write-Host '[!] Error! Missing shellcode.' -ForegroundColor Red) } # OR REMOVE ME


    # Print data type
    Write-Host "[!] Detecting Data Type of Shellcode Parameter:" -ForegroundColor Yellow
    Write-Host " o  BaseType : $($Shellcode.GetType().BaseType)"
    Write-Host " o  Name     : $($Shellcode.GetType().Name)"
        
    # Checking format before parsing
    if ($Shellcode -is [array]) {
            
        # Shellcode is already formatted as a byte array
        if ($Shellcode -is [Byte[]]) {
            Write-Host '[!] Shellcode parameter is already formatted as a [byte[]].' -ForegroundColor Yellow
            Write-Host ' o  --> No formatting required.'
            $shellcodeBuffer = $Shellcode
        }
        # Convert array to a string for attempted parsing
        else {
            Write-Host '[!] Formatting Shellcode for PowerShell:' -ForegroundColor Yellow
            Write-Host ' o  Shellcode parameter is an [array].'
            Write-Host ' o  --> Converting to [string]...'
            $Shellcode = $Shellcode -join ''
        }
    }
    
    # Attempt to determine what language the shellcode is formatted for
    if ($Shellcode -is [String]) {
            
        $Shellcode = $Shellcode.Replace("`r","").Replace("`n",'')

        # Check if $Shellcode is a path to a shellcode file
        #   > Path to Raw Shellcode  :  .\shellcode.bin

        if (Test-Path -LiteralPath $Shellcode 2>$NULL) {
                
            Write-Host '[!] Formatting Shellcode for PowerShell:' -ForegroundColor Yellow
            Write-Host ' o  Shellcode [string] is a path to a file.'

            $ShellcodePath   = (Get-Item -LiteralPath $Shellcode).Fullname
            $shellcodeBuffer = [System.IO.File]::ReadAllBytes($ShellcodePath)

            Write-Host " o  --> Path : $ShellcodePath"
            Write-host ' o  --> Reading file bytes...'
        }

        # Format C or Python formatted shellcode string into PowerShell format
        #   > Python Shellcode Format  :  'b"\x45\x78\x61\x6d\x70\x6c\x65"'
        #   > C Shellcode Format       :  '\x45\x78\x61\x6d\x70\x6c\x65'

        elseif (($Shellcode -like 'b"\x*') -or ($Shellcode -like '\x*')) {
                
            Write-Host '[!] Formatting Shellcode for PowerShell:' -ForegroundColor Yellow
            Write-Host ' o  Shellcode [string] is formatted for C or Python.'
            Write-Host ' o  --> Formatting for PowerShell...'

            # Convert to PowerShell ASCII array
            $Shellcode = $Shellcode.Replace(' ','')
            $psShellcode = ($Shellcode.Replace('b"','').Replace('"','')).Split('\')[1..$Shellcode.Length]

            # Convert Shellcode ASCII array to Byte Array
            $shellcodeBuffer = [byte[]]($psShellcode | % { [convert]::ToByte($_.Replace('x',''),16) })
        }

        # Format C++ or C# formatted shellcode string into PowerShell format
        #   > C++ / C# Shellcode Format  :  '{0x45,0x78,0x61,0x70,0x6c,0x65}'

        elseif (($Shellcode -like '{0x*') -or ($Shellcode -like '{ 0x*')) {
                
            Write-Host '[!] Formatting Shellcode for PowerShell:' -ForegroundColor Yellow
            Write-Host ' o  Shellcode [string] is formatted for C++ or C#.'
            Write-Host ' o  --> Formatting for PowerShell...'

            # Convert to PowerShell ASCII array
            $Shellcode = $Shellcode.Replace(' ','')
            $psShellcode = ($Shellcode.Replace('{0x','').Replace('}','')) -Split ',0x'

            # Convert Shellcode ASCII array to Byte Array
            $shellcodeBuffer = [byte[]]($psShellcode | % { [convert]::ToByte($_,16) })
        }

        else { return (Write-Host '[!] Error! Unable to determine shellcode langauge format.' -ForegroundColor Red) }
    }
        
    # Return shellcode byte array
    if (!$shellcodeBuffer) { return (Write-Host '[!] Error! Unable to determine shellcode type.' -ForegroundColor Red) }
    Write-Host " o  --> Shellcode Length : $($shellcodeBuffer.Length) bytes"
    return ,$shellcodeBuffer
}