rule dcrat_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-10"
        description = "Detects DcRAT payloads using static configuration strings and mutex artifacts"
        malware_family = "DcRAT"
        mitre_attack = "T1059.001, T1027, T1218.005"
        score = 90
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/dcrat_yara_patterns.md"

    strings:
        $s1 = "dcrat" ascii nocase
        $s2 = "Server 1" ascii
        $s3 = "duckdns" ascii nocase
        $s4 = "qwqdanchun" ascii nocase
        $s5 = "InstallUtil" ascii
        $mutex = "MUTEX" ascii

    condition:
        uint16(0) == 0x5A4D and
        3 of ($s*) and $mutex
}
