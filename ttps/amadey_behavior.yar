rule amadey_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects behavioral indicators of Amadey malware based on traffic patterns and DLL chain loading"
        malware_family = "Amadey"
        mitre_attack = "T1055.001, T1105, T1027"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/amadey_yara_patterns.md"

    strings:
        $exe1 = ".exe → .dll → .exe" ascii
        $panel = "/index.php" ascii
        $format = "http://" ascii
        $ip_like = /http:\/\/\d{1,3}(\.\d{1,3}){3}\/[a-zA-Z0-9]{6,12}\/index\.php/ ascii
        $dll1 = "cred64.dll" ascii
        $dll2 = "clip64.dll" ascii
        $res_name = "Download history" ascii

    condition:
        4 of them
}
