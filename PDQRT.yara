rule Mal_PDQ_Connect_RAT
{
meta:
	description = "Identifies PDQ RAT"
strings: 
    $str1 = "PDQConnectAgent"
	$str2 = "pdq-connect-agent.exe"
	$domain1 = "34.54.45.198"
condition:
  any of them
	
}

