rule Mal_LummaStealer
{
meta:
	description = "Identifies Lumma Stealer malware"
strings: 
  	$str1 = "valleydod.fun"
	$str2 = "magaway.fun"
	$str4 = "TeslaBrowser/5.5"
	$str5 = "AutoFillStates"
	$str6 = "c2sock"
	$str7 = "africathrillthes.pw"
	$str8 = ".pw/api"
	$str9 = ".site/api"
	$str10 = ".shop/api"
	$str11 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0"
	$ip1 = "172.67.176.254"
	$ip2 = "188.114.97.7"
	$ip3 = "172.67.136.213"
	$ip4 = "89.23.98.56"
	$ip5 = "91.215.85.210"
	$ip6 = "172.67.171.214"
	$ip7 = "95.164.87.61"
	$ip8 = "104.21.32.39"
	$c21 = "https://secretionsuitcasenioise.shop/api"
	$c22 = "racedsuitreow.shop"
	$wallet1 = "Wallets/Electrum"
	$wallet2 = "Wallets/Bitcoin core"
	$wallet3 = "Wallets/Ethereum"
	$wallet4 = "Wallets/Ledger Live"
	$wallet5 = "Wallets/Authy Desktop"
	
condition:
  any of them

}



