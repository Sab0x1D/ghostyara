rule pocorat_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects Poco RAT based on static strings and known metadata"
        malware_family = "Poco RAT"
        mitre_attack = "T1059, T1105, T1204"
        score = 81
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/pocorat_yara_patterns.md"

    strings:
        $s1 = "PocoClient" ascii
        $s2 = "PocoRAT" ascii
        $s3 = "startClientSocket" ascii
        $s4 = "ClientCommandDispatcher" ascii
        $s5 = "UpdateConfigFromServer" ascii

    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}
