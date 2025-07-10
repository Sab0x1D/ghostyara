rule agenttesla_behavior
{
    meta:
        author = "Sab0x1D"
        date = "2025-07-10"
        description = "Detects Agent Tesla behavior via registry autoruns, SMTP usage, credential access, and PowerShell execution"
        malware_family = "AgentTesla"
        mitre_attack = "T1056.001, T1113, T1059.001, T1547.001"
        score = 85
        crosslink = "https://github.com/Sab0x1D/sigtrack/blob/main/yara_map/agenttesla_yara_patterns.md"

    strings:
        $reg1 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii wide
        $val = "Windows Update Service" ascii
        $smtp1 = "smtp.yandex.com" ascii
        $smtp2 = "smtp.office365.com" ascii
        $ps_exec = "powershell.exe -nop -w hidden" ascii
        $cred1 = "Username =" ascii
        $cred2 = "Password =" ascii
        $net1 = "SmtpClient" ascii
        $net2 = "System.Net.Mail" ascii wide
        $mem1 = "Authorization: Basic" ascii
        $mem2 = "x-smtpapi" ascii
        $creds_obj = "System.Net.NetworkCredential" ascii wide
        $mutex = "Mutex__Agt" ascii

    condition:
        4 of them
}
