rule metamorfo_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-11"
        description = "Detects Metamorfo behavior via MSI drops, AutoHotKey usage, and export-based rundll32 execution"
        malware_family = "Metamorfo"
        mitre_attack = "T1204.002, T1055.001, T1218.011, T1059.005"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/metamorfo_yara_patterns.md"

    strings:
        $drop_dir = "C:\\Users\\REM\\AppData\\Local\\" ascii
        $uwg_ext = ".uwg" ascii
        $txt_date = "\\\\[0-9]{2}\\\\[0-9]{4}\\.txt" ascii
        $installutil = "InstallUtil.exe" ascii
        $dll_export = "rundll32.exe .*export" ascii
        $watson = "watson.telemetry" ascii
        $payload = "*AutoHotKey version*" ascii
        $ahk = "AHK.exe" ascii
        $staging = "local state" ascii wide

    condition:
        4 of them
}
