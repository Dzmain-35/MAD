rule Mal_Obj3ctivity_Info_Stealer
{
meta:
	description = "Identifies Obj3ctivity Info Stealing malware"
strings: 
	$str1 = "whatismyipaddressnow.co"
condition:
  any of them
	
}	