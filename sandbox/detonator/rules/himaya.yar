/*
 * Himaya detonation YARA rules — compact, high-signal set for phishing / maldoc
 * / dropper detection. Add more .yar files to this directory to extend coverage.
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test file"
        severity = "malicious"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell
{
    meta:
        description = "Obfuscated / download-and-execute PowerShell"
        severity = "malicious"
    strings:
        $a = "powershell" nocase
        $b1 = "-enc" nocase
        $b2 = "-EncodedCommand" nocase
        $b3 = "FromBase64String" nocase
        $b4 = "DownloadString" nocase
        $b5 = "DownloadFile" nocase
        $b6 = "IEX(" nocase
        $b7 = "Invoke-Expression" nocase
        $b8 = "New-Object Net.WebClient" nocase
    condition:
        $a and 2 of ($b*)
}

rule Office_Macro_AutoExec
{
    meta:
        description = "VBA macro auto-execution / shell primitives"
        severity = "suspicious"
    strings:
        $m1 = "AutoOpen" nocase
        $m2 = "Auto_Open" nocase
        $m3 = "Document_Open" nocase
        $m4 = "Workbook_Open" nocase
        $s1 = "Shell(" nocase
        $s2 = "WScript.Shell" nocase
        $s3 = "CreateObject" nocase
    condition:
        (1 of ($m*)) and (1 of ($s*))
}

rule Script_Dropper_Keywords
{
    meta:
        description = "WSH/JS/VBS dropper primitives"
        severity = "suspicious"
    strings:
        $a1 = "ActiveXObject" nocase
        $a2 = "WScript.Shell" nocase
        $a3 = "ADODB.Stream" nocase
        $a4 = "MSXML2.XMLHTTP" nocase
        $a5 = "cmd.exe /c" nocase
        $a6 = "regsvr32" nocase
        $a7 = "mshta" nocase
        $a8 = "certutil -decode" nocase
    condition:
        2 of ($a*)
}

rule HTML_Smuggling
{
    meta:
        description = "HTML smuggling — embedded base64 blob assembled to a file download"
        severity = "suspicious"
    strings:
        $h1 = "createObjectURL" nocase
        $h2 = "msSaveOrOpenBlob" nocase
        $h3 = "application/octet-stream" nocase
        $h4 = "base64," nocase
        $h5 = "new Blob(" nocase
    condition:
        3 of ($h*)
}

rule Windows_PE_Executable
{
    meta:
        description = "Windows PE executable"
        severity = "suspicious"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and uint32(uint32(0x3C)) == 0x00004550
}
