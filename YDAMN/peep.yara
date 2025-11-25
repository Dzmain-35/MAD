rule Mal_PeepingTitle
{
    meta:
        description = "Identifies PeepingTitle malware"

    strings: 
        $str1 = "logintoonlinebanking"
        $str2 = "thomebankinglogin"
        $str3 = "Set objBrow"
        $str4 = "MET O MESMIS"
        $domain1 = "caixabank"
        $domain2 = "PROCURAR POR NOME"
        $domain3 = "activobank"
        $domain4 = "acesso.gov.pt"
        $c21 = "roboticadividaria.s3.us-east-1.amazonaws.com"
        $c22 = "94.241.141.101"

    condition:
        // Match if either one C2 string is found OR any 3 strings from the full set
        1 of ($c21, $c22) or 3 of ($str1, $str2, $str3, $str4, $domain1, $domain2, $domain3, $domain4)
}
