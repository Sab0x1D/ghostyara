rule lodarat_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects LodaRAT behavior based on AutoIT execution, script chains, and C2 usage"
        malware_family = "LodaRAT"
        mitre_attack = "T1059.001, T1204.002, T1105, T1547.001"
        score = 80
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/lodarat_yara_patterns.md"

    strings:
        $autoit = "AutoIt" ascii
        $exe1 = "Chrome.exe" ascii
        $exe2 = "wscript.exe" ascii
        $net = "WinData" ascii
        $drive = "Google Drive" ascii
        $mr = "Mr. 3amo" ascii
        $ip = "172.111.138.100" ascii

    condition:
        5 of them
}
