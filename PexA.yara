rule Mal_PXA_Stealer
{
meta:
	description = "Identifies PXA Stealer malware"
strings: 
    $str1 = "lonenone"
	$str2 = "MEXX6toHNBot"
	$str3 = "PXA_PURE_ENC"
	$str4 = "synaptics.zip"
	$str5 = "PXA_BOT "

condition:
  2 of them
	
}

