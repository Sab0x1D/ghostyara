rule remcos_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-10"
        description = "Detects Remcos RAT behavior via startup execution and C2 artifacts"
        malware_family = "Remcos"
        mitre_attack = "T1059.001, T1057, T1547.001"
        score = 83
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/remcos_c2_patterns.md"

    strings:
        $regkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $ps = "powershell -nop -w hidden -enc" ascii
        $cmd = "cmd.exe /c start" ascii
        $svc = "esentutl.exe" ascii
        $inmem1 = "duckdns.org" ascii
        $inmem2 = "Remcos Agent Initialized" ascii
        $inmem3 = "Remcos restarted by watchdog!" ascii

    condition:
        2 of ($regkey, $ps, $cmd, $svc) or any of ($inmem*)
}
