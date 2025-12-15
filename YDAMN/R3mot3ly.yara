rule Mal_Remotely
{
meta:
	description = "Identifies RemotelyRMM abused malware"
strings: 
    $str1 = "Remotely_Agent"
	$str2 = "Install-Remotely"
	$domain1 = "remotely.billbutterworth.com"
	$domain2 = "160.153.178.18"

condition:
  any of them
	
}

