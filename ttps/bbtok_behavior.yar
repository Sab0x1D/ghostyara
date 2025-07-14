rule bbtok_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-14"
        description = "Detects behavioral traits of BBTok via overlay injection and banking portal impersonation"
        malware_family = "BBTok"
        mitre_attack = "T1218, T1055, T1059"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/bbtok_yara_patterns.md"

    strings:
        $overlay = "Captura de Tela" wide
        $launcher = "RegAsm.exe" ascii
        $c2uri = "/bbtok/vnc/index.php" ascii
        $payload_marker = "FakeOverlayBB" ascii
        $brazil_targets = "com.bb.banco" ascii

    condition:
        all of them
}
