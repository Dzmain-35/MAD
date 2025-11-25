import "pe"

rule Mal_Connect_Wise_RAT
{
    meta:
        description = "Identifies CWRAT malware"
    strings:
        $str1 = "ScreenConnect"
        $str2 = "ConnectWise" nocase
        $dom1 = "yell64u.top"
        $ip1 = "147.75.84.236"
        $ip3 = "192.16.49.85"
        $ip4 = "147.28.129.58"
    condition:
        2 of them
}

rule Mal_Teramind_RAT
{
    meta:
        description = "Identifies Teramind RAT malware"
    strings:
        $str1 = "rt.teramind.co"
        $str2 = "teramind.proto."
        $str3 = "teramind_agent"
    condition:
        any of them
}

rule Mal_Connect_Wise_IMPHASH
{
    meta:
        description = "Identifies CWRAT malware"
        imphash = "9771ee6344923fa220489ab01239bdfd"
    condition:
        pe.imphash() == "9771ee6344923fa220489ab01239bdfd" and
        filesize > 5MB
}
