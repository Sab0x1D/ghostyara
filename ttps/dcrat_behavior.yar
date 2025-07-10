rule dcrat_behavior
{
    meta:
        author = "Sab0x1D"
        category = "rat"
        family = "DCRat"
        type = "behavior"
        description = "Detects behavioral traits of DCRat (execution, registry, persistence)"
        date = "2025-07-10"
        version = "1.0"

    strings:
        $cmd1 = "cmd.exe /c start" ascii
        $reg1 = "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run" ascii
        $mutex1 = "DCRAT_MUTEX" ascii
        $ps1 = "powershell -nop -w hidden -enc" ascii
        $svc1 = "InstallUtil" ascii
        $mem1 = "dcrat" ascii
        $mem2 = "MUTEX" ascii
        $mem3 = "Server 1" ascii
        $mem4 = "duckdns" ascii
        $mem5 = "qwqdanchun" ascii

    condition:
        2 of ($cmd1, $reg1, $mutex1, $ps1, $svc1) or any of ($mem*)
}
