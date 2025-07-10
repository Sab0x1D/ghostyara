rule venomrat_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects VenomRAT binaries using config strings, mutex, and common base64/auth artifacts"
        malware_family = "VenomRAT"
        mitre_attack = "T1055.001, T1059, T1113"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/venomrat_c2_patterns.md"

    strings:
        $mutex = "VenomMutex" ascii
        $auth = "Basic " ascii
        $b64_marker = "TVqQAAMAAAAEAAAA" ascii // MZ marker in base64
        $client = "Venom RAT Client" ascii
        $c2url = "/gate.php" ascii
        $login1 = "Username" ascii
        $login2 = "Password" ascii

    condition:
        uint16(0) == 0x5A4D and
        4 of ($mutex, $auth, $b64_marker, $client, $c2url, $login1, $login2)
}
