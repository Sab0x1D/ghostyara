rule netsupport_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects NetSupport Manager remote access behavior via encoded PowerShell stages, INI configs, and default file structure"
        malware_family = "NetSupport Manager"
        mitre_attack = "T1059.001, T1105, T1204.002"
        score = 80
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/netsupport_yara_patterns.md"

    strings:
        $b64ps = "powershell.exe -EncodedCommand" ascii
        $bat = ".bat" ascii
        $ps1 = ".ps1" ascii
        $ini = "client32.ini" ascii
        $exe1 = "client32.exe" ascii
        $dll1 = "client32.dll" ascii
        $zip_marker = "client32.ini" ascii
        $pathhint = "NetSupport\\client32" ascii
        $urlfetch = "Invoke-WebRequest" ascii

    condition:
        5 of them
}
