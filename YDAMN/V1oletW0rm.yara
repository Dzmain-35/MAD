rule Mal_Violet_Worm
{
meta:
	description = "Identifies VioletWorm malware"
strings: 
    $str1 = "Violet v4.7"
	$str2 = "<Violet>"
	$reg1 = /<Violet>.+<Violet>/ nocase
	$c2_1 = "45.77.138.162"

condition:
  any of them
	
}

