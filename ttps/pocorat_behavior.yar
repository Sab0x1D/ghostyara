rule pocorat_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects Poco RAT behavior such as config updates and socket initiation"
        malware_family = "Poco RAT"
        mitre_attack = "T1059, T1105, T1027, T1547"
        score = 84
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/pocorat_yara_patterns.md"

    strings:
        $socket = "startClientSocket" ascii
        $cmd = "ClientCommandDispatcher" ascii
        $cfg = "UpdateConfigFromServer" ascii
        $rat = "PocoRAT" ascii
        $mutex = "PocoClient" ascii

    condition:
        4 of them
}
