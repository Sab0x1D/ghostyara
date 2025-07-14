rule nanocore_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects Nanocore runtime behavior including plugin loading and RAT traffic"
        malware_family = "Nanocore"
        mitre_attack = "T1059, T1105, T1218, T1547"
        score = 89
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/nanocore_yara_patterns.md"

    strings:
        $plugin_host = "ClientPluginHost" ascii
        $start_module = "StartModule" ascii
        $mutex = "NanoHost" ascii
        $registry = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii
        $dll_load = "LoadLibraryW" ascii

    condition:
        4 of them
}
