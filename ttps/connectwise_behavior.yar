rule connectwise_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects ConnectWise Control RAT runtime behavior including service installation and beacon patterns"
        malware_family = "ConnectWise"
        mitre_attack = "T1219, T1105"
        score = 87
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/connectwise_yara_patterns.md"

    strings:
        $svcname = "ScreenConnect Client" ascii
        $svcpath = "ConnectWiseControl.ClientService.exe" ascii
        $beacon1 = "/Host" ascii
        $beacon2 = "/Join" ascii
        $registry1 = "SOFTWARE\\ScreenConnect" ascii

    condition:
        4 of them
}
