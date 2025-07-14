rule nanocore_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-15"
        description = "Detects Nanocore payloads using common mutexes, config strings, and known C2 indicators"
        malware_family = "NanoCore"
        mitre_attack = "T1055, T1027, T1071.001"
        score = 87
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/nanocore_yara_patterns.md"

    strings:
        $mutex = "NanoCore Client" ascii
        $exeName = "RegSvcs.exe" ascii
        $duckdns = "duckdns.org" ascii
        $panel = "login.nanocore.io" ascii
        $pipe = "\\\\.\\pipe\\NanoCore" ascii

    condition:
        uint16(0) == 0x5A4D and
        3 of ($mutex, $exeName, $duckdns, $panel, $pipe)
}
