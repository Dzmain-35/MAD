rule Mal_WebBrowserPassWordView
{
meta:
	description = "Identifies WebBrowserPassWordView malware"
strings: 
    $str1 = "Chrom.exe /stext"
	$str2 = "output.txt"
	$str3 = "Web Browser"
	$str4 = "c:\\Projects\\VS2005\\WebBrowserPassView"

condition:
  2 of them
	
}

