rule Mal_LeeMe_Ransomeware
{
meta:
	description = "Identifies Leeme malware"
strings: 
    $str1 = "instrucoes.txt"
	$str2 = "SAP_Ariba_QuoteBuilder_v2.exe"
	$domain1 = "LEEME.txt"
	$domain2 = "bc1qez8r8h99x6n2c57kwmmexafhx0nszhxk0xqq8n"
	$domain3 = "redcobra797@proton.me"

condition:
  any of them
	
}

