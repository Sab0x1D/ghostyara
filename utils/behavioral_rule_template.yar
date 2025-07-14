/* ============================= */
/* Behavioral YARA Rule Template */
/* ============================= */

rule NAME_behavior
{
    meta:
        author = "Sab0x1D"
        date = "YYYY-MM-DD"
        description = "Detects NAME behavior such as X, Y, and Z"
        malware_family = "NAME"
        mitre_attack = "TXXXX, TYYYY, TZZZZ"
        score = NN
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/NAME_yara_patterns.md"

    strings:
        $key1 = "string_behavior_1" ascii
        $key2 = "string_behavior_2" ascii
        $key3 = "string_behavior_3" ascii
        $key4 = "string_behavior_4" ascii
        $key5 = "string_behavior_5" ascii

    condition:
        4 of them
}
