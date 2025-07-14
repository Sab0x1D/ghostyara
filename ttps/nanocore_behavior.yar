rule nanocore_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-15"
        description = "Detects Nanocore activity via spawned RegSvcs.exe and C2 indicators"
        malware_family = "NanoCore"
        mitre_attack = "T1055.001, T1082, T1016"
        score = 91
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/nanocore_yara_patterns.md"

    strings:
        $regsvc = "RegSvcs.exe" ascii
        $duckdns = "duckdns.org" ascii
        $network_tool = "ProcessHacker" ascii wide
        $pipe = "\\\\.\\pipe\\NanoCore" ascii

    condition:
        all of them
}
