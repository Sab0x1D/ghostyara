rule astaroth_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects Astaroth behavior via LOLBin abuse, memory injection via regsvr32.exe, and credential access techniques"
        malware_family = "Astaroth"
        mitre_attack = "T1059.003, T1218.009, T1055.001, T1555.003"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/astaroth_yara_patterns.md"

    strings:
        $ps_inj = "powershell -windowstyle hidden" ascii
        $reg32 = "regsvr32 /s /n /u /i" ascii
        $dll_inj = "ntdskutl.dll" ascii
        $creds1 = "System.Security.Cryptography" ascii
        $wmic = "wmic process call create" ascii
        $key = "SOFTWARE\\Microsoft\\Cryptography" ascii
        $id = "MachineGuid" ascii
        $decode = "FromBase64String" ascii

    condition:
        4 of them
}
