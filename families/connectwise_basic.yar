rule connectwise_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects ConnectWise RAT binary via embedded strings and versioning"
        malware_family = "ConnectWise"
        mitre_attack = "T1219, T1105"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/connectwise_yara_patterns.md"

    strings:
        $s1 = "ScreenConnect.WindowsClient.exe" wide
        $s2 = "ConnectWiseControl.Client" wide
        $s3 = "SessionManager" wide
        $s4 = "ScreenConnect.ClientService" wide
        $s5 = "ConnectWiseControl" ascii

    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}
