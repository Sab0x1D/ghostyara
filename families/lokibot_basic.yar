rule lokibot_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects LokiBot payloads using browser profile indicators and static string artifacts"
        malware_family = "LokiBot"
        mitre_attack = "T1056.001, T1555.003, T1203"
        score = 87
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/lokibot_c2_patterns.md"

    strings:
        $s1 = "fre.php" ascii
        $s2 = "profile.php" ascii
        $lib = "aPLib v1.01" ascii

        $p1 = "\\Mozilla\\Firefox\\profiles.ini" ascii
        $p2 = "\\Thunderbird\\profiles.ini" ascii
        $p3 = "\\BlackHawk\\profiles.ini" ascii
        $p4 = "\\SeaMonkey\\profiles.ini" ascii
        $p5 = "\\FossaMail\\profiles.ini" ascii

    condition:
        uint16(0) == 0x5A4D and
        4 of ($*)
}
