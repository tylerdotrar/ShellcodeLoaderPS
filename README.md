# ShellcodeLoaderPS
Predominantly educational shellcode loader with overly verbose comments.  The idea is to be fairly
modular, and documented to be an educational resource for those getting into exploit development.

## Usage
![image](https://github.com/user-attachments/assets/68695346-dd3c-432c-9066-50f4ce493aa2)
```
Parameters:
      -Shellcode  -->  Shellcode to execute; can be a byte array or string containing a file path or formatted bytes.
      -Please     -->  Alternative execution method that will likely bypass Windows Defender (though it is noisy).
      -Help       -->  Return Get-Help information.
```

For supported shellcode, the `-Shellcode` parameter is intentionally undeclared and written to accept most
shellcode formats.  Currently supports strings `[string]` and byte arrays `[byte[]]`.  Below is a table of supported string formats:

| Format | Example |
| --- | --- |
| Path to Raw Shellcode | `.\shellcode.bin` |
| Python Shellcode      | `'b"\x45\x78\x61\x6d\x70\x6c\x65"'` |
| C Shellcode           | `'\x45\x78\x61\x6d\x70\x6c\x65'` |
| C++ / C# Shellcode    | `'{0x45,0x78,0x61,0x70,0x6c,0x65}'` |

Currently, only standard execution via **CreateThread()** is supported -- eventually will implement
remote process injection and other techniques.  EDR evasion is effectively non-existent, though
the `-Please` parameter is goofy enough to bypass Windows Defender.

Works with both Windows PowerShell and PowerShell Core (Pwsh), as well as 64-bit and 32-bit
architectures -- just make sure you are running 32-bit PowerShell if your shellcode is 32-bit.
