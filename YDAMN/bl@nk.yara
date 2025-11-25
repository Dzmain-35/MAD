rule Mal_Blank_Grabber
{
meta:
	description = "Identifies Blank Grabber malware"
strings: 
    $name = "BlankGrabber"
	$str2 = "Get-Clipboard"
	$str3 = "StealWallets"
	$str4 = "Stealing system information"
	$str5 = "TakeScreenshot"

condition:
  $name and 1 of ($str*)
	
}

