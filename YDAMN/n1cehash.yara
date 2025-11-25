rule Mal_ZharkBot
{
meta:
	description = "Identifies NiceHash Miner"
strings: 
    $str1 = "Run NiceHash Miner"
	$str2 = "NiceHash Miner v3.1.1.1"

condition:
  any of them
	
}

