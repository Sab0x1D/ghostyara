rule guloader_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects GULoader payloads based on string patterns and static unpacked artifacts"
        malware_family = "GULoader"
        mitre_attack = "T1055, T1027, T1059"
        score = 80
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/guloader_c2_patterns.md"

    strings:
        $api1 = "StringFromGUID2" ascii
        $api2 = "CLSIDFromString" ascii
        $api3 = "IsDebuggerPresent" ascii

        $url = "https://www.webutils.pl/index.php?idx=" ascii
        $note = "Once decoded change the file to a .exe" ascii
        $hash = "0293eec0b5432ad092f24065016203b2" ascii

    condition:
        uint16(0) == 0x5A4D and
        3 of ($api*) and 1 of ($url, $note, $hash)
}
