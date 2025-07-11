rule amadey_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects Amadey loader binaries via known config markers and DLL references"
        malware_family = "Amadey"
        mitre_attack = "T1055.001, T1105, T1027"
        score = 75
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/amadey_yara_patterns.md"

    strings:
        $mz = { 4D 5A }
        $c1 = "cred64.dll" ascii
        $c2 = "clip64.dll" ascii
        $config1 = "soft\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
        $mutex = "Global\\WindowsUpdate" ascii
        $res_panel = "/index.php" ascii

    condition:
        uint16(0) == 0x5A4D and
        3 of ($c1, $c2, $config1, $mutex, $res_panel)
}
