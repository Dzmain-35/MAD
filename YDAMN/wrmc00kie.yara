rule Mal_WhiteSnakeStealer
{
meta:
	description = "Identifies White Snake malware"
strings: 
	$str1 = "repOrt.Lock"
	$str2 = "decr:{0}_{1}@{2}_report.wsr"
	$str3 = "AppW\\SnK"
	$str4 = "%67%6C%42%65%56%5F%49%54%2D%41%64%6D%69%6E%40%41%44%4D%49%4E%5F%72%65%70%6F%72%74.%77%73%72"
	$str5 = "glBeV_IT-Admin@ADMIN_report.wsr"
	$c2_2 = "217.145.238.175"
	$c2_1 = "206.189.109.146"
	$c2_3 = "164.90.185.9"
	$c2_4 = "api.telegram.org/bot6803354203"
	
condition:
  any of them
	
}