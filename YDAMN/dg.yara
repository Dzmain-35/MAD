rule Mal_DarkGate {
    meta:
        description = "Identifies DarkGate malware"
    strings: 
        $str1 = "KeyScramblerLogon.exe"
        $str2 = "KeyScramblerIE.dll"
        $str3 = "darkgate"
        $str5 = "0xDark"
        $str6 = "admin888"
        $str7 = "DarkGate"
        $pl1 = "5.252.178.193" 
        $c21 = "94.228.169.143"
        $c22 = "51.195.49.233"
        $c23 = "88.119.175.199"
        $c24 = "84.246.85.138"
        $c25 = "162.19.130.45"
        $c26 = "84.246.85.121"
        $c27 = "162.33.179.65"
        $c28 = "darkgatepassword0"
        $c29 = "stachmentsuprimeresult.com"
        $c210 = "138.124.183.35"
        $c211 = "klosherskymoneyd.com"
        $c212 = "138.124.183.37"
    condition:
        2 of them
}
