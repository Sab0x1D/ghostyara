rule lokibot_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects LokiBot browser profile targeting and C2 beaconing behavior via PHP endpoints"
        malware_family = "LokiBot"
        mitre_attack = "T1059.005, T1005, T1041"
        score = 84
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/lokibot_c2_patterns.md"

    strings:
        $browser = "profiles.ini" ascii
        $php = "/profile.php" ascii
        $drop = "C:\\Users\\%USERNAME%\\AppData\\Local\\Temp" ascii

    condition:
        all of ($*)
}
