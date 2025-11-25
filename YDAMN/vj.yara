rule Mal_Vj_Worm
{
meta:
	description = "Identifies Vj-worm malware"
strings: 
    $str1 = "vjw0rm" nocase
	$str2 = "HKCU\\vjw0rm" nocase
	$c2_1 = "12.221.146.138"
	$c2_2 = "enviojs06.kozow.com"
condition:
  any of them

}