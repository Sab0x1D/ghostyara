rule agenttesla_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-09"
        description = "Detects AgentTesla based on typical registry and process execution behavior"
        malware_family = "AgentTesla"
        mitre_attack = "T1547.001, T1059.003, T1056.001"
        reference = ""
        score = 80
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/agenttesla_c2_patterns.md"

    strings:
        $reg = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $val = "Windows Update Service" ascii
        $ps_exec = "powershell.exe -nop -w hidden" ascii
        $smtp = "smtp.office365.com" ascii
        $creds = "System.Net.NetworkCredential" ascii wide

    condition:
        2 of ($reg, $val, $ps_exec, $smtp, $creds)
}
