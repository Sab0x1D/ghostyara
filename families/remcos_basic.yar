rule remcos_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-10"
        description = "Detects Remcos RAT using static strings from unpacked binaries"
        malware_family = "Remcos"
        mitre_attack = "T1059.003, T1027, T1547.001"
        score = 88
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/remcos_c2_patterns.md"

    strings:
        $s1 = "Remcos.exe" ascii
        $s2 = "Remcos Agent Initialized" ascii
        $s3 = "Remcos restarted by watchdog!" ascii
        $s4 = "Remcos v" ascii
        $s5 = "Remcos Agent" ascii
        $c2 = "duckdns.org" ascii

    condition:
        4 of ($s*) or ($c2 and filesize < 1MB)
}
