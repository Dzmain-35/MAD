import "pe"

rule Mal_Maxthon
{
    meta:
        description = "Identifies Maxthon browser abuse"
    strings:
        $str1 = "MxCrashCatch.dll"
        $str2 = "MxAppLoader" nocase
        $str3 = "Iniciando====> AP ROXU"
        $ip1 = "196.251.69.115"

    condition:
        any of them
}

rule Mal_Connect_Maxthon_IMP
{
    meta:
        description = "Identifies Maxthon imphash"
        imphash = "dd437f45a0a6f3002005d5a5fd9a1b34"
    condition:
        pe.imphash() == "dd437f45a0a6f3002005d5a5fd9a1b34"
}
