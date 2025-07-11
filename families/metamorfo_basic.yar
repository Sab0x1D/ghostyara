rule metamorfo_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects Metamorfo (Mekotio/Casbaneiro) samples via AutoHotKey and payload artifacts"
        malware_family = "Metamorfo"
        mitre_attack = "T1059.007, T1055.001, T1218.011"
        score = 80
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/metamorfo_yara_patterns.md"

    strings:
        $mz = { 4D 5A }
        $ahkmarker = "*AutoHotKey version*" ascii
        $string1 = "InstallUtil.exe" ascii
        $string2 = "c2sock" ascii
        $string3 = "mr.temp" ascii
        $string4 = "TeslaBrowser" ascii
        $string5 = "webcache" ascii
        $json_marker = "{\"r\":[]," ascii
        $dotfun = ".fun" ascii

    condition:
        uint16(0) == 0x5A4D and
        5 of them
}
