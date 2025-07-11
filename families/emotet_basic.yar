rule emotet_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects Emotet loader binaries via known strings, embedded configuration, and DLL characteristics"
        malware_family = "Emotet"
        mitre_attack = "T1055.001, T1105, T1027, T1071.001"
        score = 90
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/emotet_yara_patterns.md"

    strings:
        $mz = { 4D 5A }
        $dll_marker = "This program cannot be run in DOS mode" ascii
        $config1 = "emotet_loader" ascii
        $config2 = "client_version=" ascii
        $c2_fmt = /\/news\.php\?id=\d+/ ascii
        $mutex = "Global\\EMOTET" ascii
        $srv_id = "srv32" ascii
        $junk = "aaaaaaaaaaaaaaaaaaaaaaaa" ascii

    condition:
        uint16(0) == 0x5A4D and
        4 of ($config1, $config2, $c2_fmt, $mutex, $srv_id, $junk)
}
