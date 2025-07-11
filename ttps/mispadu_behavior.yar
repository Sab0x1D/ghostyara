rule mispadu_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects behavioral execution chain of Mispadu (pdf > zip > hta > vbs > AutoIt)"
        malware_family = "Mispadu"
        mitre_attack = "T1204.002, T1059.005, T1055"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/mispadu_c2_patterns.md"

    strings:
        $s1 = ".hta" ascii
        $s2 = ".vbs" ascii
        $s3 = "AutoIt" ascii
        $s4 = "Introduzca la contrasena" ascii
        $s5 = "AutoIt v3 Script has stopped working" ascii
        $s6 = "C:\\Users\\Public" ascii

    condition:
        all of ($s*)
}
