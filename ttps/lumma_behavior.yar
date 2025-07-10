rule lumma_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects Lumma Stealer behavior through bat file spawning InstallUtil.exe and browser credential targeting"
        malware_family = "Lumma Stealer"
        mitre_attack = "T1218.009, T1055.001, T1555.003, T1113"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/lumma_yara_patterns.md"

    strings:
        $bat_spawn = ".bat file spawns InstallUtil.exe" ascii
        $proc1 = "InstallUtil.exe" ascii
        $c2json = "{\"r\":[],\"b\":[],\"g\":0}" ascii
        $target1 = "user data" ascii
        $target2 = "TeslaBrowser" ascii
        $target3 = "webcache" ascii
        $target4 = "wallets" ascii
        $suspend_hint = "recommend suspending before it kills itself" ascii

    condition:
        4 of them
}
