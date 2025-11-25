rule Mal_PikaBot
{
meta:
    description = "Identifies PikaBot malware"
strings:
    $c21 = "51.195.232.97"
    $c23 = "188.26.127.4"
    $c22 = "154.92.19.139"
    $c24 = "149.248.53.65"
    $c25 = "158.247.253.155"
    $c26 = "70.34.209.101"
    $c27 = "139.180.216.25"
    $c28 = "208.76.221.253"
    $str5 = "TrichinopolyUncontriving"
    $str6 = "dll,Limit"
    $str7 = "Pashaship"
    $str8 = /http.+([0-5]|2[0-4][0-9]|[01]?[0-9][0-9]).+\/api\/admin.+/
    $str9 = /http.+([0-5]|2[0-4][0-9]|[01]?[0-9][0-9]).+\/api\/apps.+/

condition:
  any of them
    
}