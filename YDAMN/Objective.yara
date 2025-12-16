rule Mal_Obj3ctivity_Info_Stealer
{
meta:
	description = "Identifies Obj3ctivity Info Stealing malware"
strings: 
	$domain = "whatismyipaddressnow.co"
	$card1 = "Maestro Card"
	$card2 = "Solo Card"
	$card3 = "KoreanLocalCard"
	$card4 = "Switch Card"
	$browser1 = "CentBrowser" 
	$browser2 = "Chedot"
	$browser3 = "CocCoc"
	$browser4 = "Elements Browser"
	$wallet1 = "Zcash"
	$wallet2 = "Armory"
	$wallet3 = "Bytecoin"
	$wallet4 = "AtomicWallet"
condition:
  $domain and 1 of($card*, $browser*, $wallet*)
	
}	
