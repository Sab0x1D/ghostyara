rule njrat_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects njRAT (Bladabindi) based on static string artifacts"
        malware_family = "njRAT"
        mitre_attack = "T1059, T1105, T1204"
        score = 84
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/njrat_yara_patterns.md"

    strings:
        $s1 = "dwObfuscation" ascii
        $s2 = "Client successfully connected" ascii
        $s3 = "cmd.exe /c start " ascii
        $s4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $s5 = "njRAT" wide ascii

    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}
