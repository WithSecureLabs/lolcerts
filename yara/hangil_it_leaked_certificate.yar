import "pe"

rule leaked_hangil_it_leaked_certificate {
   meta:
      status = "revoked"
      source = "leaked"
      description = "Leaked Hangil IT Co., Ltd certificate utilised by various malware."
      references = ""
      date = "15-11-2023"
      author = "Riccardo Ancarani"
      
   condition:
      uint16(0) == 0x5a4d and 
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "Sectigo Public Code Signing CA R36" and
         pe.signatures[i].serial == "01:39:dd:e1:19:bb:32:0d:fb:9f:5d:ef:e3:f7:12:45"
      )
}