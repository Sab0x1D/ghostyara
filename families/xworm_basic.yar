rule xworm_basic
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects XWorm payloads using hardcoded identifiers, strings, and common SMTP/loader infrastructure"
        malware_family = "XWorm"
        mitre_attack = "T1059.001, T1027, T1055, T1566.001"
        score = 90
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/xworm_yara_patterns.md"

    strings:
        $s1 = "Mal_Xwormm" ascii
        $s2 = "aspnet_regbrowsers.exe" ascii
        $s3 = "X09ENE.exe" ascii
        $s4 = "regsvcs.exe" ascii
        $b64marker = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii

    condition:
        uint16(0) == 0x5A4D and
        3 of ($s*)
}
