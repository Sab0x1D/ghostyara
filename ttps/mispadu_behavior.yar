rule Mispadu_Behavior_Execution_Chain
{
    meta:
        author = "Sab0x1D"
        family = "Mispadu"
        type = "behavioral"
        description = "Detects behavioral execution chain of Mispadu campaign"
        created = "2025-07-11"

    strings:
        $hta = ".hta"
        $vbs = ".vbs"
        $ps1 = ".ps1"
        $exe = ".exe"
        $autoit_error = "AutoIt v3 Script has stopped working"
        $prompt_msg = "Please enter the password"

    condition:
        all of ($hta, $vbs, $ps1, $exe) and any of ($autoit_error, $prompt_msg)
}
