rule Mal_Astaroth
{
meta:
	author = "Dmain"
	description = "Identifies Astaroth/Guildma malware"
strings: 
	$str1 = "\\x73\\x63\\162\\x69\\x70\\x74\\x3a\\x48\\x54\\x74\\x70\\"
	
	
condition:
	  any of them
}

