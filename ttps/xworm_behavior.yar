rule xworm_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects XWorm activity via PowerShell decoding, process spawning (regsvcs.exe), and final stager aspnet_regbrowsers.exe"
        malware_family = "XWorm"
        mitre_attack = "T1059.001, T1140, T1027, T1106"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/xworm_yara_patterns.md"

    strings:
        $ps_exec = "powershell.exe -Command" ascii
        $dec1 = "FromBase64String" ascii
        $dec2 = "reverse" ascii
        $spawn1 = "regsvcs.exe" ascii
        $spawn2 = "aspnet_regbrowsers.exe" ascii
        $marker = "X09ENE.txt" ascii
        $mutex = "Mal_Xwormm" ascii

    condition:
        4 of them
}
