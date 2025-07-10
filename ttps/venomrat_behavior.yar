rule venomrat_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects VenomRAT behavior via registry autoruns, credential access, memory injection, and HTTP C2"
        malware_family = "VenomRAT"
        mitre_attack = "T1055.001, T1547.001, T1555"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/venomrat_c2_patterns.md"

    strings:
        $reg1 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii wide
        $cred1 = "Username" ascii
        $cred2 = "Password" ascii
        $ps1 = "powershell -nop -w hidden" ascii
        $memapi1 = "VirtualAllocEx" ascii
        $memapi2 = "WriteProcessMemory" ascii
        $net1 = "/gate.php" ascii
        $mutex = "VenomMutex" ascii

    condition:
        4 of them
}
