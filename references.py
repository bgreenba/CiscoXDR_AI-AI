import json

class Config:

	"""
	  {
          "title": this is what will appear in the pivot menu
          "description": this is what will appear in the pivot menu entry hoverover
          "url": this is the link the user will be referred to if they click
          "id-string": this is a unique identifier for the lookup that is used to track the responses. To this string the server will append the observable type and the observable value.
          "obs_types": the list of observable types on which this reference should be returned. The string "all" matches all possible current and future types. 
          }
	"""
	REFERENCES=[

	  {
   	      "title": "Google Search",
	      "description": "Search Google for {obs_value}",
	      "url": "https://www.google.com/search?q={obs_value}",
	      "id-string": "aiai-nollm-google",
	      "obs_types": ["all"]
	  },
	  {
	      "title": "DuckDuckGo Search",
	      "description": "Search DuckDuckGo for {obs_value}",
	      "url": "https://duckduckgo.com/?q=",
	      "id-string": "aiai-nollm-duckduckgo",
	      "obs_types": ["ip", "domain"]
	  },
	  {
	      'id-string':'aiai-ipinfo-whois',
	      'title':'IPinfo.com WHOIS info',
	      'description':"ipinfo.com WHOIS lookup",
	      'url':"https://ipinfo.io/widget/demo/{obs_value}?dataset=whois",
	      'obs_types':["ip"],
	  },
	  {
	      'id-string':'aiai-ipinfo-reversedns',
	      'title':'IPinfo.com Reverse DNS',
	      'description':"Find domains resolving to this {obs_type}",
	      'url':"https://ipinfo.io/widget/demo/{obs_value}?dataset=reverse-api",
	      'obs_types':["ip"]
	  },
	  {
	      'id-string':'aiai-virustotal-file-search',
	      'title':'VirusTotal File Details',
	      'description':"Search Virustotal for this {obs_type}",
	      'url':"https://www.virustotal.com/gui/file/{obs_value}",
	      'obs_types':["sha256","sha1","md5"]
	  },
	  {
	      'id-string':'aiai-virustotal-domain-search',
	      'title':'VirusTotal Domain Details',
	      'description':"Search Virustotal for this {obs_type}",
	      'url':"https://www.virustotal.com/gui/domain/{obs_value}",
	      'obs_types':["domain"]
	  },
	  {
	      'id-string':'aiai-crtsh-cert-checker',
	      'title':'CRT.sh Certificate Search',
	      'description':"Search Certs held by this {obs_type}",
	      'url':"https://crt.sh/?q={obs_value}",
	      'obs_types':["domain"]
	  },
	  {
	      'id-string':'aiai-mac-vendor-lookup-com',
	      'title':'MAC Vendor Lookup',
	      'description':"look up the vendor associated to this MAC address",
	      'url':"https://www.macvendorlookup.com/oui.php?mac={obs_value}",
	      'obs_types':["mac_address"]
	  },
	  {
	      'id-string':'aiai-nslookup-io',
	      'title':'DNS Lookup at NSlookup.io',
	      'description':"DNS Lookup at NSlookup.io for {obs_value}",
	      'url':"https://www.nslookup.io/domains/{obs_value}/dns-records/",
	      'obs_types':["domain"]
	  },
	  {
	      'id-string':'aiai-freeipapi',
	      'title':'IP lookup at FreeIP API',
	      'description':"IP details for {obs_value} at FreeIP API",
	      'url':"https://freeipapi.com/api/json/{obs_value}",
	      'obs_types':["ip"]
	  },
	  {
	      'id-string':'aiai-hackertarget-reversedns',
	      'title':'ReverseDNS lookup at HackerTarget',
	      'description':"ReverseDNS from HackerTarget for {obs_value}",
	      'url':"https://api.hackertarget.com/reversedns/?q={obs_value}",
	      'obs_types':["ip"]
	  },
	  {
	      'id-string':'aiai-hackertarget-asn',
	      'title':'ASN lookup at HackerTarget',
	      'description':"ASN info from HackerTarget for {obs_value}",
	      'url':"https://api.hackertarget.com/aslookup/?q={obs_value}&output=json",
	      'obs_types':["ip"]
	  },
	  {
	      'id-string':'aiai-domaintools-whois',
	      'title':'WHOIS lookup at DomainTools',
	      'description':"WHOIS info from DomainTools for {obs_value}",
	      'url':"https://api.domaintools.com/v1/domaintools.com/whois/{obs_value}",
	      'obs_types':["domain"]
	  },
	  {
	      'id-string':'aiai-braveLLM',
	      'title':'BraveLLM query',
	      'description':"BraveLLM query for {obs_value}",
	      'url':"'https://search.brave.com/search?q=I am a security researcher and I have come across the {obs_type} {obs_value}. Can you please provide me with more information about it?&source=llmSuggest&summary=1'",
	      'obs_types':["all"]
	  }
	]

