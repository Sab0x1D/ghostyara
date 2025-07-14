/* ========================= */
/* Static YARA Rule Template */
/* ========================= */

rule NAME_basic
{
    meta:
        author = "Sab0x1D"
        date = "YYYY-MM-DD"
        description = "Detects NAME based on static strings and known metadata"
        malware_family = "NAME"
        mitre_attack = "TXXXX, TYYYY"
        score = NN
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/NAME_yara_patterns.md"

    strings:
        $s1 = "string_one" ascii
        $s2 = "string_two" ascii
        $s3 = "string_three" ascii
        $s4 = "string_four" ascii
        $s5 = "string_five" ascii

    condition:
        uint16(0) == 0x5A4D and 3 of ($s*)
}

