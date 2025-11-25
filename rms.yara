rule Mal_Remote_Manipulator_System
{
meta:
	description = "Identifies RMS malware"
strings: 
    $str1 = "Remote Utilities"
	$str2 = "Panoya kopyala"
	$domain1 = "sreen_record_option"
	$domain2 = "66.23.226.254"
	$domain3 = "TWorkStealingQueue"

condition:
  2 of them
	
}

