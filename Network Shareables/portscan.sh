#!/bin/bash
######################################################################################
#
#   Yet Another Port Scanning Do-hickey on the internet.. but by Sicinthemind
#     Can install to /usr/bin/ and it will run anywhere, saving the files
#     in the current working directory or link it there with ln -s.. 
#	
#   Requires SUDO to Run... Ideal for mostly CTFs as it's a very Noisy
#   and Aggressive Nmap scan.
#
#   Feed it an IP, it'll generate the child folder for you and files 
#     will be saved therein.
#
#   sudo portscan.sh 192.168.1.34
#
#   You can alternatively create a Foldername as an IP and it can 
#     autodetect you want to scan using that folder path IP address.
#
#	mkdir 192.168.1.34 && cd 192.168.1.34
#	sudo portscan.sh 
#
#	Still haven't worked out kinks for all ranges yet... don't have time
#     and I haven't finished all the HTML report content for multi-host xml
#     parsing...
#
######################################################################################
regpat="^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
ip=""
workspace=""
if [ "$(id -u)" -ne 0 ]; then	# check if script is running as root!
    echo "Script must run logged in as Root or with Sudo"
fi

if ! command -v xmlstarlet &> /dev/null; then	# Check if xmlstarlet is installed
    echo "Error: xmlstarlet is not installed. Please install it and try again."
    exit 1
fi

# Function to create a folder workspace for a given IP address
create_workspace(){
	ip_address=$1
	if [ ! -d "${ip_address}" ]; then
		workspace="${ip_address}"
		mkdir -p "${workspace}"
		pretty '+' "Created workspace: ${workspace}"
	else
		pretty '-' "Workspace exists: ${workspace}"
	fi
}

function red(){
    if [ "$#" -eq 0 ]; then
        local str; read str; 
    else
        str=$1
    fi
    echo -en '\e[31;1m'${str}'\e[0m'
}

function green(){
    if [ "$#" -eq 0 ]; then
        local str; read str; 
    else
        str=$1
    fi
    echo -en '\e[32;1m'${str}'\e[0m'
}

function blue(){
    if [ "$#" -eq 0 ]; then
        local str; read str; 
    else
        str=$1
    fi
    echo -en '\e[34;1m'${str}'\e[0m'
}

function yellow(){
    if [ "$#" -eq 0 ]; then
        local str; read str; 
    else
        str=$1
    fi
    echo -en '\e[33;1m'${str}'\e[0m'
}

function pretty() {
    local msgcat=$1
    local message=$2
    case $msgcat in
        "+")
            echo -en '\e[32;1m[+]\e[0m\t'"${message}\n"   #green
            ;;
        "-")
            echo -en '\e[31;1m[-]\e[0m\t'"${message}\n"   #red
            ;;
        "*")
            echo -en '\e[34;1m[*]\e[0m\t'"${message}\n"   #blue
            ;;
        "!")
            echo -en '\e[33;1m[!]\e[0m\t'"${message}\n"   #yellow
            ;;
        *)
            ;;
    esac
}

function trim(){
    str=$1
    local tmpstr=$(echo "${str}" | sed -e 's/^[[:space:]]*//' | sed -e 's/[[:space:]]*$//')
    echo "${tmpstr}"
}

function scantarget(){
	ip="$1"
	if echo ${PWD##*/}| grep -oP $regpat >/dev/null; then
		workspace=$(pwd)
	else
		workspace=$(pwd)/${ip}
	fi  
	scanningops="--max-rtt-timeout 1000ms --min-rate 3500 -Pn " 
	udpscanports="21,22,25,42,53,67,68,88,123,110,111,137,138,139,161,162,194,389,1512,5901,5900,6900"
	tcppreferred="1,7,9,13,19,21,22,23,25,37,42,43,49,53,69,70,79,80,81,82,83,84,85,88,102,105,109,110,111,113,119,123,135,137,139,143,161,179,222,264,384,389,402,407,443,444,445,465,500,502,512,513,515,523,524,540,548,554,587,617,623,631,636,689,705,771,783,873,888,902,903,910,912,921,990,993,995,998,1000,1024,1030,1035,1080,1089,1090,1091,1098,1099,1100,1101,1102,1103,1128,1129,1158,1199,1211,1220,1270,1234,1241,1300,1311,1352,1433,1440,1468,1494,1521,1530,1533,1581,1582,1583,1604,1723,1755,1811,1883,1900,2000,2049,2082,2083,2100,2103,2121,2181,2199,2207,2222,2323,2362,2375,2379,2380,2381,2525,2533,2598,2601,2604,2638,2809,2947,2967,3000,3037,3050,3057,3128,3200,3268,3269,3217,3273,3299,3300,3306,3311,3312,3351,3389,3460,3500,3628,3632,3690,3780,3790,3817,4000,4092,4322,4343,4369,4433,4443,4444,4445,4567,4659,4679,4730,4786,4840,4848,5000,5022,5037,5038,5040,5051,5060,5061,5093,5168,5222,5247,5250,5351,5353,5355,5392,5400,5405,5432,5433,5498,5520,5521,5554,5555,5560,5580,5601,5631,5632,5666,5671,5672,5683,5800,5814,5900,5920,5938,5984,5985,5986,5988,5989,6000,6001,6002,6050,6060,6070,6080,6082,6101,6106,6112,6262,6379,6405,6502,6503,6504,6514,6542,6556,6660,6661,6667,6905,6988,7000,7001,7021,7071,7077,7080,7100,7144,7181,7210,7443,7474,7510,7547,7579,7580,7676,7700,7770,7777,7778,7787,7800,7801,7879,7902,8000,8008,8009,8012,8014,8020,8023,8028,8030,8080,8081,8086,8087,8088,8089,8090,8095,8098,8127,8161,8180,8205,8222,8300,8303,8333,8400,8443,8471,8488,8503,8545,8686,8787,8800,8812,8834,8880,8883,8888,8899,8901,8902,8903,8983,9000,9001,9002,9042,9060,9080,9081,9084,9090,9092,9099,9100,9111,9152,9160,9200,9300,9390,9391,9418,9440,9443,9471,9495,9809,9855,9524,9595,9527,9530,9999,10000,10001,10008,10050,10051,10080,10098,10162,10202,10203,10443,10616,10628,11000,11099,11211,11234,11333,12174,12203,12221,12345,12397,12401,13364,13500,13838,14330,15200,15671,15672,16102,16992,16993,17185,17200,17775,17776,17777,17778,17781,17782,17783,17784,17790,17791,17798,18264,18881,19300,19810,19888,20000,20010,20031,20034,20101,20111,20171,20222,20293,22222,23472,23791,23943,25000,25025,25565,25672,26000,26122,27000,27017,27019,27080,27888,28017,28222,28784,30000,30718,31001,31099,32764,32913,34205,34443,34962,34963,34964,37718,37777,37890,37891,37892,38008,38010,38080,38102,38292,40007,40317,41025,41080,41523,41524,44334,44818,45230,46808,46823,46824,47001,47002,47808,48808,48899,49152,50000,50013,50070,50090,52302,55553,55580,57772,61616,62078,62514,65535"
	scriptopts="default"
	tcpresults="${workspace}/tcp_${ip}"
	udpresults="${workspace}/udp_${ip}"
	defresults="${workspace}/enum_${ip}"
	vulresults="${workspace}/vuln_${ip}"
	opentcpports=""
	portcount=""
	tports=""
	tportsc=""
	openudpports=""
	portcount=""
	uports=""
	uportsc=0
	allopenports=""
	lines=0
	httpset=""
	smtpset=""
	snmpset=""
	dnsset=""
	vncset=""
	msrpc=""
	tftpset=""
	ftpset=""
	mssqlset=""
	smbset=""
	nfsset=""
	mysqlset=""
	#############################################################################
	#	PRELIMINARY TCP SCANNING WITH NO SCRIPTS TO PREVENT SERVICE OUTAGE
	#############################################################################
	pretty '*' "Scanning All TCP Ports"
	if [ -f "${tcpresults}.xml" ]; then
		if [[ $(find "${tcpresults}.xml" -mtime +1 -print) ]]; then
			pretty '+' "Nmap Options: ${scanningops} -p- -sT ${ip} -oN $tcpresults"
			nmap ${scanningops} -p- -sT ${ip} -oX $tcpresults.xml
		else
			pretty '-' "Skipping"
		fi
	else
		pretty '+' "Nmap Options: ${scanningops} -p- -sT ${ip} -oN $tcpresults"
		nmap ${scanningops} -Pn -p- -sT ${ip} -oX $tcpresults.xml
	fi
	opentcpports=$(xmlstarlet sel -t -m "//host/status[@state='up']" -m "../ports/port[state/@state='open']" -v "@portid" -n ${tcpresults}.xml)
	portcount=$(echo -en "${opentcpports}" | wc -l)
	pretty '+' "Found ${portcount} TCP ports open."
	tports=""
	tportsc=0
	if [ $portcount -gt 0 ]; then
		lines=0
		while read -r line; do
			lines=$(($lines + 1))
			if [ $lines -eq 1 ]; then
				tports="$line"
				tportsc=$(($tportsc + 1))
			else
				tports+=",$line"
				tportsc=$(($tportsc + 1))
			fi
		done <<< "$opentcpports"
	else
		echo "Found 0 Ports Open."
	fi
	[ ${tportsc} = 0 ] && pretty '-' "No TCP ports available, skipping host" && return 0;
	
	#############################################################################
	#	UDP SCANNING THE TOP UDP PORTS TO OPTIMIZE TIME
	#############################################################################
	pretty "*" "Scanning UDP Ports"
	if [ -f "${udpresults}.xml" ]; then
		if [[ $(find "${udpresults}.xml" -mtime +1 -print) ]]; then
			pretty '*' "Nmap Options: --max-rtt-timeout 1000ms --min-rate 3500 --max-retries 2 -T3 -p ${udpscanports} -sU ${ip} -oN ${udpresults}"
			nmap --max-rtt-timeout 1000ms --min-rate 3500 --max-retries 2 -p ${udpscanports} -sU ${ip} -oX ${udpresults}.xml
		else
			pretty '-' "Skipping"
		fi
	else
		pretty '*' "Nmap Options: --max-rtt-timeout 1000ms --min-rate 3500 --max-retries 2  -p ${udpscanports} -sU ${ip} -oX ${udpresults}.xml"
		nmap --max-rtt-timeout 1000ms --min-rate 3500 --max-retries 2 -T3 -p ${udpscanports} -sU ${ip} -oX ${udpresults}.xml
	fi
	openudpports=$(xmlstarlet sel -t -m "//host/status[@state='up']" -m "../ports/port[state/@state='open']" -v "@portid" -n ${udpresults}.xml)
	portcount=$(echo -en "${openudpports}" | wc -l)
	uports=""
	uportsc=0
	if [ "$portcount" != "0" ]; then
		echo "$portcount = 0"
		lines=0
		while read -r line; do
			lines=$(($lines + 1))
			if [ $lines -eq 1 ]; then
				uports="$line"
				uportsc=$(($uportsc + 1))
			else
				uports+=",$line"
				uportsc=$(($uportsc + 1))
			fi
		done <<< "$openudpports"
	fi
	echo "${uportsc}"
	echo "${tportsc}"
	if [ $uportsc -eq 0 ]; then
		if [ $tportsc -eq 0 ]; then
			pretty '-' "Something might be wrong..."
			pretty '!' "No ports are open"
			#exit 1;
		else
			pretty '+' "Found ${portcount} UDP ports open. Proceeding with TCP Only."
			allports="T:$tports"
			allflags=" -sT "
		fi
	else
		allports="U:$uports,T:$tports"
		allflags=" -sT -sU "
	fi
	
	#############################################################################
	#	Version Scanning all ports
	#############################################################################
	pretty "+" "Identified ports: ${allports}"
	pretty "*" "Executing Full Enumeration Scan"
	if [ -f $defresults ]; then
		if [[ $(find "$defresults" -mtime +1 -print) ]]; then
			pretty '+' "Nmap Options: ${scanningops} ${allflags} -p ${allports} -sV ${ip} -oN $defresults.xml"
			nmap ${scanningops} ${allports} ${allflags} -sV ${ip} -oN $defresults.xml -oX $defresults.xml
		else
			pretty '-' "Skipping"
		fi
	else
		nmap ${scanningops} -p ${allports} ${allflags} -sV ${ip} -oN $defresults.nmap -oX $defresults.xml
	fi
	httpports=$(xmlstarlet sel -t -m "//host/status[@state='up']" -m "../ports/port[state/@state='open']/service[contains(@name, 'http')]" -v "concat(../@portid, ':', (../service/@tunnel='ssl'))" -n ${defresults}.xml)
	allopenports=$(xmlstarlet sel -t -m "//host/status[@state='up']" -m "../ports/port[state/@state='open']" -v "concat(@protocol, '/', @portid, '	', ../service/@name)" -n ${defresults}.xml)
	lines=0
	httpset="false"
	smtpset="false"
	snmpset="false"
	dnsset="false"
	vncset="false"
	msrpc="false"
	tftpset="false"
	ftpset="false"
	mssqlset="false"
	smbset="false"
	nfsset="false"
	mysqlset="false"
	while read -r line; do
		lines=$(($lines + 1))
		indport=$(echo "$line" | cut -d '/' -f 1)
		if [[ $line == *"http"* ]] && [ $httpset == "false" ]; then
			scriptopts+=",http-vuln*"
			httpset="true"
		fi
		if [[ $line == *"smtp"* ]] && [ $smtpset == "false" ]; then
			scriptopts+=",smtp-vuln*"
		smtpset="true"
		fi
		if [[ $line == *"domain"* ]] && [ $dnsset == "false" ]; then
			scriptopts+=",dns-*"
			dnsset="true"
		fi
		if [[ $line == *"snmp"* ]] && [ $snmpset == "false" ]; then
			scriptopts+=",snmp-info"
			snmpset="true"
		fi
		if [[ $line == *"vnc"* ]] && [ $vncset == "false" ]; then
			scriptopts+=",realvnc-auth-bypass.nse,vnc-info.nse,vnc-title.nse"
			#scriptopts+=",realvnc-auth-bypass.nse,vnc-*"
			vncset="true"
		fi
		if [[ $line == *"msrpc"* ]] && [ $msrpc == "false" ]; then
			scriptopts+=",msrpc-enum.nse"
			msrpc="true"
		fi
		if [[ $line == *"tftp"* ]] && [ $tftpset == "false" ]; then
			scriptopts+=",tftp-enum.nse"
			tftpset="true"
		fi
		if [[ $line == *"ftp"* ]] && [ $ftpset == "false" ]; then
			scriptopts+=",ftp-anon.nse,ftp-bounce.nse,ftp-libopie.nse,ftp-proftpd-backdoor.nse,ftp-syst.nse,ftp-vsftpd-backdoor.nse,ftp-vuln-cve2010-4221.nse"
			ftpset="true"
		fi
		if [[ $line == *"ms-sql"* ]] && [ $mssqlset == "false" ]; then
			scriptopts+=",ms-sql-config.nse,ms-sql-config.nse,ms-sql-dac.nse,ms-sql-dump-hashes.nse,ms-sql-empty-password.nse,ms-sql-hasdbaccess.nse,ms-sql-info.nse,ms-sql-ntlm-info.nse"
			mssqlset="true"
		fi
		if [[ $line == *"microsoft-ds"* ]] || [[ $line == *"netbios-ssn"* ]] && [ $smbset == "false" ]; then
			scriptopts+=",smb-enum-shares.nse,smb-vuln-*,smb-enum-users.nse,smb-system-info.nse,smb-double-pulsar-backdoor.nse,smb2-vuln-uptime.nse,smb2-time.nse,smb-os-discovery.nse,smb-server-stats.nse,smb2-security-mode.nse"
			smbset="true"
		fi
		if [[ $line == *"mysql"* ]] && [ $mysqlset == "false" ]; then
			scriptopts+=",mysql-audit.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse"
			mysqlset="true"	
		fi
		case $indport in
			2049)
				if [ $nfsset == "false" ]; then
					scriptopts+=",nfs-*"
					nfsset="true"
				fi
				;;
			*)
				;;
		esac
	done <<< "$allopenports"
	pretty '*' "Performing aggressive vulnerability scan"
	if [ -f ${vulresults} ]; then
		if [[ $(find "${vulresults}" -mmin +59 -print) ]]; then
		pretty '+' "Nmap Options: -T3 -Pn -p ${allports} ${allflags} -sV --script=${scriptopts} ${ip} -oN ${vulresults}"
			nmap ${scanningops} -O -p ${allports} ${allflags} -sV --script=${scriptopts} ${ip} -oA ${vulresults}
		else
			pretty '-' "Skipping rescan"
		fi
	else
		pretty '+' "Nmap Options: -T3 -Pn -p ${allports} ${allflags} -sV --script=${scriptopts} ${ip} -oN ${vulresults}"
		nmap ${scanningops} -O -p ${allports} ${allflags} -sV --script=${scriptopts} ${ip} -oA ${vulresults}
	fi

	#############################################################################
	#	NMAP Parser Output
	#############################################################################
	cat ${vulresults}.nmap
	pretty "*" "$(printf "%*s" $(($COLUMNS - 5)) | tr ' ' '#')"
	grep -E 'open|STATE' ${vulresults}.nmap | grep -v Warning
	pretty "*" "$(printf "%*s" $(($COLUMNS - 5)) | tr ' ' '#')"
	chksum=$(cat ${vulresults}.xml | md5sum | head -c 8)
	b64xml=$(cat ${vulresults}.xml | base64 -w 0)
	# Its the super virus coming to haxor your pc... 
	#    **WAVES HANDS IN THE AIR MYSTICALLY** 
	#    It's an HTML report parser for the Nmap XML.
	#    As you can see above, the b64xml converted your Nmap result into a base64 payload, it then inserts that payload into the HTML file below.
	#    Then as you render that HTML file in the browser... it magically parses out all the Nmap Script data and open ports into easily readable
	#    information. 
	#
	#	 Insert Jack Sparrow magic finger wiggle here... Spooky code. 
	#
	#	Just run the command below if you want to see what it is as HTML and read it yourself... 
	#
	echo "PCFET0NUWVBFIGh0bWw+DQo8aHRtbD4NCgk8aGVhZD4NCgkJPG1ldGEgY2hhcnNldD0iVVRGLTgiPg0KCQk8dGl0bGU+Tk1BUCBYTUwgUGFyc2VyPC90aXRsZT4NCgkJPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJodHRwczovL2NkbmpzLmNsb3VkZmxhcmUuY29tL2FqYXgvbGlicy9mb250LWF3ZXNvbWUvNC43LjAvY3NzL2ZvbnQtYXdlc29tZS5taW4uY3NzIiBpbnRlZ3JpdHk9InNoYTM4NC13dmZYcHFwWlpWUUdLNlRBaDVQVmxHT2ZRTkhTb0QyeGJFK1FrUHhDQUZsTkVldm9FSDNTbDBzaWJWY09RVm5OIiBjcm9zc29yaWdpbj0iYW5vbnltb3VzIj4NCgkJPGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSJodHRwczovL2NkbmpzLmNsb3VkZmxhcmUuY29tL2FqYXgvbGlicy9ib290c3RyYXAvNS4yLjMvY3NzL2Jvb3RzdHJhcC5taW4uY3NzIiBpbnRlZ3JpdHk9InNoYTUxMi1TYmlSL2V1c3BoS29NVlZYeXNUS0cvN1ZzZVdpaStZM0ZkSHJ0MEVwS2dwVG9aZWVtaHFIZVplTFdMaEp1dHovMnV0MlZ3MXVRRWoyTWJSRitUVkJVQT09IiBjcm9zc29yaWdpbj0iYW5vbnltb3VzIiByZWZlcnJlcnBvbGljeT0ibm8tcmVmZXJyZXIiIC8+DQoJCTxzdHlsZT4NCgkJCWJvZHl7YmFja2dyb3VuZC1jb2xvcjojMDAwO2NvbG9yOiNmZmY7Zm9udC1mYW1pbHk6QXJpYWwsc2Fucy1zZXJpZjtmb250LXNpemU6MTJweDsgbWFyZ2luOiAwIGF1dG87fQ0KCQkJaDF7Zm9udC1zaXplOjMycHg7dGV4dC1hbGlnbjpjZW50ZXJ9DQoJCQlwcmV7YmFja2dyb3VuZC1jb2xvcjojMGMwYzBjOyBjb2xvcjogI2MwYzBjMH0NCgkJCS5iZy12aWt0aGVtZWJsdWU5e2JhY2tncm91bmQtY29sb3I6ICM0ZGIxYzg7fQ0KCQkJLmJnLXZpa3RoZW1lYmx1ZTh7YmFja2dyb3VuZC1jb2xvcjogIzQ1OWZiNDt9DQoJCQkuYmctdmlrdGhlbWVibHVlN3tiYWNrZ3JvdW5kLWNvbG9yOiAjM2U4ZWEwO30NCgkJCS5iZy12aWt0aGVtZWJsdWU2e2JhY2tncm91bmQtY29sb3I6ICMzNjdjOGM7fQ0KCQkJLmJnLXZpa3RoZW1lYmx1ZTV7YmFja2dyb3VuZC1jb2xvcjogIzJlNmE3ODt9DQoJCQkuYmctdmlrdGhlbWVibHVlNHtiYWNrZ3JvdW5kLWNvbG9yOiAjMjc1OTY0O30NCgkJCS5iZy12aWt0aGVtZWJsdWUze2JhY2tncm91bmQtY29sb3I6ICMxZjQ3NTA7fQ0KCQkJLmJnLXZpa3RoZW1lYmx1ZTJ7YmFja2dyb3VuZC1jb2xvcjogIzE3MzUzYzt9DQoJCQkuYmctdmlrdGhlbWVibHVlMXtiYWNrZ3JvdW5kLWNvbG9yOiAjMGYyMzI4O30NCgkJCS5iZy12aWt0aGVtZWJsdWUwe2JhY2tncm91bmQtY29sb3I6ICMwODEyMTQ7fQ0KCQkJLmZnLXZpa3RoZW1lYmx1ZTl7Y29sb3I6ICM0ZGIxYzg7fQ0KCQkJLmZnLXZpa3RoZW1lYmx1ZTh7Y29sb3I6ICM0NTlmYjQ7fQ0KCQkJLmZnLXZpa3RoZW1lYmx1ZTd7Y29sb3I6ICMzZThlYTA7fQ0KCQkJLmZnLXZpa3RoZW1lYmx1ZTZ7Y29sb3I6ICMzNjdjOGM7fQ0KCQkJLmZnLXZpa3RoZW1lYmx1ZTV7Y29sb3I6ICMyZTZhNzg7fQ0KCQkJLmZnLXZpa3RoZW1lYmx1ZTR7Y29sb3I6ICMyNzU5NjQ7fQ0KCQkJLmZnLXZpa3RoZW1lYmx1ZTN7Y29sb3I6ICMxZjQ3NTA7fQ0KCQkJLmZnLXZpa3RoZW1lYmx1ZTJ7Y29sb3I6ICMxNzM1M2M7fQ0KCQkJLmZnLXZpa3RoZW1lYmx1ZTF7Y29sb3I6ICMwZjIzMjg7fQ0KCQkJLmZnLXZpa3RoZW1lYmx1ZTB7Y29sb3I6ICMwODEyMTQ7fQ0KCQk8L3N0eWxlPg0KCTwvaGVhZD4NCgk8Ym9keSA+DQoJCTxkaXYgY2xhc3M9ImNvbnRhaW5lciI+DQoJCQk8ZGl2IGNsYXNzPSJyb3cganVzdGlmeS1jb250ZW50LWNlbnRlciBiZy1kYXJrIj4NCgkJCQk8ZGl2IGlkPSJob3N0cHJvZmlsZW5hbWUiIGNsYXNzPSJoMSBwYWdlLWhlYWRlciBiZy1kYXJrIGZnLXZpa3RoZW1lYmx1ZTkgZm9udC13ZWlnaHQtYm9sZCB0ZXh0LWxlZnQiPg0KCQkJCQlUZXN0DQoJCQkJPC9kaXY+DQoJCQkJPGRpdiBjbGFzcz0iY29udGFpbmVyIGNhcmQtbWV0YSBkLWZsZXgganVzdGlmeS1jb250ZW50LWJldHdlZW4iPg0KCQkJCQk8ZGl2IGlkPSJzeXN0ZW0tcHJvZmlsZSIgY2xhc3M9InRleHQtaW5mbyBjb2wtNCBib3JkZXItaW5mbyI+dGVzdDwvZGl2Pg0KCQkJCQk8ZGl2IGlkPSJvcGVuLXBvcnRzIiBjbGFzcz0idGV4dC1saWdodCBjb2wtOCI+dGVzdDwvZGl2Pg0KCQkJCTwvZGl2Pg0KCQkJPC9kaXY+DQoJCTwvZGl2Pg0KCTwvYm9keT4NCgk8c2NyaXB0IHNyYz0iaHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvanF1ZXJ5LzMuNi40L2pxdWVyeS5taW4uanMiIGludGVncml0eT0ic2hhNTEyLXB1bUJzak5SR0dxa1B6S0huZFpNYUFHK2JpcjM3NHNPUnl6TTN1dWxMVjE0bE41THl5a3FOazhlRWVVbFVrQjNVME00RkFweWFIcmFUNjVpaEpoRHBRPT0iIGNyb3Nzb3JpZ2luPSJhbm9ueW1vdXMiIHJlZmVycmVycG9saWN5PSJuby1yZWZlcnJlciI+PC9zY3JpcHQ+DQoJPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuanMuY2xvdWRmbGFyZS5jb20vYWpheC9saWJzL2Jvb3RzdHJhcC81LjIuMy9qcy9ib290c3RyYXAubWluLmpzIiBpbnRlZ3JpdHk9InNoYTUxMi0xL1J2WlRjQ0RFVWpZL0N5cGlNeitpcXF0YW9RZkFJVG1OU0pZMTdNeXA0TXM1bWR4UFM1VVY3aU9mZFpveGNHaHpGYk9tNnNudFRLSnBwanZ1aGc0Zz09IiBjcm9zc29yaWdpbj0iYW5vbnltb3VzIiByZWZlcnJlcnBvbGljeT0ibm8tcmVmZXJyZXIiPjwvc2NyaXB0Pg0KCTxzY3JpcHQ+DQoJCXZhciBubWFwc2NhbnMgPSBbXTsNCgkJbm1hcGZpbGVuYW1lID0gIm5tYXBfb3V0cHV0LnhtbCINCgkJJChkb2N1bWVudCkucmVhZHkoZnVuY3Rpb24oKSB7DQoJCQlpZiAobm1hcHNjYW5zLmxlbmd0aCA+IDEpIHsNCgkJCQlubWFwc2NhbnMuZm9yRWFjaCh4bWx2YXIgPT4gew0KCQkJCQljb25zdCB4bWxTdHIgPSBldmFsKHhtbHZhcikNCgkJCQkJY29uc3QgeG1sT2JqID0gJC5wYXJzZVhNTCh4bWxTdHIpOw0KCQkJCQlyZW5kZXJzY2Fucyh4bWxPYmopOw0KCQkJCX0pOw0KCQkJfSBlbHNlIHsNCgkJCQlubWFwc2NhbnMuZm9yRWFjaCh4bWx2YXIgPT4gew0KCQkJCQljb25zdCB4bWxTdHIgPSBldmFsKHhtbHZhcikNCgkJCQkJY29uc3QgeG1sT2JqID0gJC5wYXJzZVhNTCh4bWxTdHIpOw0KCQkJCQlyZW5kZXJzY2Fucyh4bWxPYmopOw0KCQkJCX0pOw0KCQkJfQ0KCQl9KTsNCgkJZnVuY3Rpb24gcmVuZGVyc2NhbnMoeG1sKXsNCgkJCXZhciBob3N0bmFtZSA9ICQoeG1sKS5maW5kKCJob3N0bmFtZSIpLmF0dHIoIm5hbWUiKTsNCgkJCXZhciBpcHY0ID0gJCh4bWwpLmZpbmQoImFkZHJlc3NbYWRkcnR5cGU9J2lwdjQnXSIpLmF0dHIoImFkZHIiKTsNCgkJCSQoIiNob3N0cHJvZmlsZW5hbWUiKS5odG1sKGlwdjQgKyAiIE5NQVAgU2NhbiBSZXN1bHRzIik7DQoJCQl2YXIgdHJhY2Vyb3V0ZSA9ICQoeG1sKS5maW5kKCJkaXZhY2Vyb3V0ZSIpLnRleHQoKTsNCgkJCS8vIFNDQU4gVElNRVMgDQoJCQljb25zdCBzdGFydHRpbWUgPSAkKHhtbCkuZmluZCgiaG9zdCIpLmF0dHIoInN0YXJ0dGltZSIpOw0KCQkJY29uc3Qgc3QgPSBuZXcgRGF0ZSgwKTsgDQoJCQlzdC5zZXRVVENTZWNvbmRzKHN0YXJ0dGltZSk7DQoJCQljb25zdCBlbmR0aW1lID0gJCh4bWwpLmZpbmQoImhvc3QiKS5hdHRyKCJlbmR0aW1lIik7DQoJCQljb25zdCBldCA9IG5ldyBEYXRlKDApOyANCgkJCWV0LnNldFVUQ1NlY29uZHMoZW5kdGltZSk7DQoJCQl2YXIgcnVudGltZSA9IHRobShlbmR0aW1lIC0gc3RhcnR0aW1lKTsNCgkJCXZhciBkbnMgPSAiIjsNCgkJCXZhciBkbnMgPSAiIjsNCgkJCSQoeG1sKS5maW5kKCJob3N0bmFtZXMgaG9zdG5hbWUiKS5lYWNoKGZ1bmN0aW9uKCkgew0KCQkJCXZhciBuYW1lID0gJCh0aGlzKS5hdHRyKCJuYW1lIik7DQoJCQkJZG5zICs9IG5hbWUgKyAiLCAiOw0KCQkJfSk7DQoJCQlpZiAoZG5zKSB7DQoJCQkJZG5zID0gZG5zLnNsaWNlKDAsIC0yKTsNCgkJCX0NCgkJCXBvcnRzPSIiDQoJCQl2YXIgcG9ydHN1bW0gPSBbXTsNCgkJCXZhciBwcm9kdWN0cyA9IFtdOw0KCQkJJCh4bWwpLmZpbmQoInBvcnQiKS5lYWNoKGZ1bmN0aW9uKCkgew0KCQkJCXZhciBzdGF0ZSA9ICQodGhpcykuZmluZCgic3RhdGUiKS5hdHRyKCJzdGF0ZSIpOw0KCQkJCWlmIChzdGF0ZSA9PT0gIm9wZW4iKSB7DQoJCQkJCXZhciBwb3J0aWQgPSAkKHRoaXMpLmF0dHIoInBvcnRpZCIpOw0KCQkJCQl2YXIgcHJvdG9jb2wgPSAkKHRoaXMpLmF0dHIoInByb3RvY29sIik7DQoJCQkJCXZhciBzZXJ2aWNlID0gJCh0aGlzKS5maW5kKCJzZXJ2aWNlIikuYXR0cigibmFtZSIpOw0KCQkJCQl2YXIgc3ZjcHJvZCA9ICQodGhpcykuZmluZCgic2VydmljZSIpLmF0dHIoInByb2R1Y3QiKTsNCgkJCQkJaWYgKCFzdmNwcm9kKSB7IHN2Y3Byb2QgPSBzZXJ2aWNlIH07DQoJCQkJCXZhciB2ZXJzaW9uID0gJCh0aGlzKS5maW5kKCJzZXJ2aWNlIikuYXR0cigidmVyc2lvbiIpOw0KCQkJCQlpZiAodmVyc2lvbikgeyANCgkJCQkJCXZlcnNpb24gPSB2ZXJzaW9uOyANCgkJCQkJCXZlcnNpb25kaXNwbGF5ID0gIlZlcnNpb246ICIgKyB2ZXJzaW9uOw0KCQkJCQl9IGVsc2UgeyANCgkJCQkJCXZlcnNpb24gPSAiIiANCgkJCQkJCXZlcnNpb25kaXNwbGF5ID0gIiI7DQoJCQkJCX0NCgkJCQkJcG9ydHN1bW12YWw9Ijx0cj48dGggc2NvcGU9XCJyb3dcIj4iK3BvcnRpZCsiIC8gIitwcm90b2NvbCsiPC90aD48dGQ+IitzZXJ2aWNlKyI8L3RkPjx0ZD4iK3N2Y3Byb2QrIjwvdGQ+PC90cj4iDQoJCQkJCWlmIChwb3J0c3VtbXZhbCAmJiAhcG9ydHN1bW0uaW5jbHVkZXMocG9ydHN1bW12YWwpKSB7IHBvcnRzdW1tLnB1c2gocG9ydHN1bW12YWwpOyB9IA0KCQkJCQlwb3J0c3VtbXZhbD0iIjsNCgkJCQkJLy88c2NyaXB0PjwhLS0gd2VpcmQgYnVnIGluIElERSBkb2Vzbid0IHJlY29nbml6ZSB0ZW1wbGF0ZSBsaXRlcmFscyAtLT4NCgkJCQkJc2NyaXB0b3V0cHV0ID0gIiI7DQoJCQkJCWtleWRhdGEgPSAiIjsNCgkJCQkJLy8gUE9SVCAvIFNDUklQVCAvIEVMRU0NCgkJCQkJc2NyaXB0Y291bnQgPSAkKHRoaXMpLmZpbmQoInNjcmlwdCIpLmxlbmd0aA0KCQkJCQkvL2NvbnNvbGUubG9nKCJQb3J0OiAiICsgcG9ydGlkICsgIiByYW4gIiArIHNjcmlwdGNvdW50ICsgIiBzY3JpcHRzLiIpOw0KCQkJCQkkKHRoaXMpLmZpbmQoInNjcmlwdCIpLmVhY2goZnVuY3Rpb24oKSB7DQoJCQkJCQl2YXIgc2NyaXB0aWQgPSAkKHRoaXMpLmF0dHIoImlkIik7DQoJCQkJCQl2YXIgbm1zb3V0cCA9ICQodGhpcykuYXR0cigib3V0cHV0Iik7DQoJCQkJCQl2YXIgbm1zb3V0cGNsZWFuID0gbm1zb3V0cC5yZXBsYWNlKC9eXG5ccyovLCAiIik7DQoJCQkJCQkkKHRoaXMpLmZpbmQoInRhYmxlIikuZWFjaChmdW5jdGlvbigpIHsNCgkJCQkJCQl2YXIgc2NyaXB0dGFibGUgPSAkKHRoaXMpLmF0dHIoImtleSIpOw0KCQkJCQkJCWlmIChzY3JpcHR0YWJsZSkgew0KCQkJCQkJCQlrZXlkYXRhICs9ICI8c3Ryb25nPiIgKyBzY3JpcHR0YWJsZSArICI8L3N0cm9uZz5cbiI7DQoJCQkJCQkJfSBlbHNlIHsNCgkJCQkJCQkJa2V5ZGF0YSA9ICJcbiI7DQoJCQkJCQkJfQ0KCQkJCQkJCS8va2V5ZGF0YSArPSAiPHRhYmxlPlxuIjsNCgkJCQkJCQkkKHRoaXMpLmZpbmQoImVsZW0iKS5lYWNoKGZ1bmN0aW9uKCkgew0KCQkJCQkJCQl2YXIgZWtuID0gJCh0aGlzKS5hdHRyKCJrZXkiKTsNCgkJCQkJCQkJaWYgKCFla24pIHsgZWtuID0gc2NyaXB0dGFibGU7IH0NCgkJCQkJCQkJdmFyIGVrZCA9ICQodGhpcykudGV4dCgpOw0KCQkJCQkJCQlrZXlkYXRhICs9ICI8ZGl2IGNsYXNzPVwiY29udGFpbmVyIGNhcmQtbWV0YSBkLWZsZXgganVzdGlmeS1jb250ZW50LWJldHdlZW5cIj5cbiI7DQoJCQkJCQkJCWtleWRhdGEgKz0gIjxkaXYgY2xhc3M9J2NvbC0yJz4iICsgZWtuICsgIjwvZGl2PlxuIjsNCgkJCQkJCQkJa2V5ZGF0YSArPSAiPGRpdiBzdHlsZT1cIm1heC13aWR0aDogIDU1MHB4IWltcG9ydGFudDtcIj48cHJlIHN0eWxlPVwid2hpdGUtc3BhY2U6IHByZS13cmFwOyB3b3JkLXdyYXA6IGJyZWFrLXdvcmQ7XCI+PGNvZGU+IiArIGVrZCArICI8L2NvZGU+PC9wcmU+PC9kaXY+XG4iOw0KCQkJCQkJCQlrZXlkYXRhICs9ICI8L2Rpdj5cbiI7DQoJCQkJCQkJCWVrZCA9ICIiOyBla24gPSAiIjsNCgkJCQkJCQl9KTsNCgkJCQkJCX0pOw0KCQkJCQkJc2NyaXB0b3V0cHV0ICs9ICI8aDY+PHN0cm9uZz4iICsgc2NyaXB0aWQgKyAiPC9zdHJvbmc+PC9oNj48cHJlPjxjb2RlPiIgKyBubXNvdXRwY2xlYW4gKyAiPC9jb2RlPjwvcHJlPiIgKyBrZXlkYXRhICsgIlxuIjsNCgkJCQkJCW5tc25hbWUgPSAiIjsgbm1zb3V0cCA9ICIiOyBrZXlkYXRhID0gIiI7DQoJCQkJCX0pOw0KCQkJCQkvKiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyANCgkJCQkJICAjDQoJCQkJCSAgIwlUSElTIElTIFdIRVJFIFBPUlRTIENPTUUgVE9HRVRIRVIgQVMgQSBXSE9MRSBIVE1MIEVMRU1FTlQgQU5EIEdFVCBJTlNFUlRFRCBBUyBBIEJPT1RTVFJBUCBBQ0NPUkRJT04gSVRFTQ0KCQkJCQkgICMJDQoJCQkJCSAgIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyovDQoJCQkJCWlmIChzY3JpcHRjb3VudCA+IDApIA0KCQkJCQkJcG9ydHMgKz0gYA0KCQkJCQkJCTxkaXYgY2xhc3M9ImFjY29yZGlvbi1pdGVtIj4NCgkJCQkJCQkJPGRpdiBjbGFzcz0iY2FyZCBiZy12aWt0aGVtZWJsdWUyIHRleHQtbGlnaHQgYm9yZGVyLWluZm8iPg0KCQkJCQkJCQkJPGgyIGNsYXNzPSJjYXJkLWhlYWRlciI+DQoJCQkJCQkJCQkJPGJ1dHRvbiBjbGFzcz0iYWNjb3JkaW9uLWJ1dHRvbiBjb2xsYXBzZWQiIHR5cGU9ImJ1dHRvbiIgZGF0YS1icy10b2dnbGU9ImNvbGxhcHNlIiBkYXRhLWJzLXRhcmdldD0iI2NvbGxhcHNlLSR7cG9ydGlkfSIgYXJpYS1leHBhbmRlZD0iZmFsc2UiIGFyaWEtY29udHJvbHM9ImNvbGxhcHNlLSR7cG9ydGlkfSI+DQoJCQkJCQkJCQkJCTxkaXYgY2xhc3M9ImNvbnRhaW5lciBkLWZsZXgganVzdGlmeS1jb250ZW50LWJldHdlZW4iPg0KCQkJCQkJCQkJCQk8ZGl2PjxzdHJvbmc+ICR7cG9ydGlkfS8ke3Byb3RvY29sfSAtICR7c2VydmljZX08L3N0cm9uZz48L2Rpdj48ZGl2PjxzdHJvbmc+UHJvZHVjdDogJHtzdmNwcm9kfSAke3ZlcnNpb25kaXNwbGF5fTwvc3Ryb25nPjwvZGl2Pg0KCQkJCQkJCQkJCQk8L2Rpdj4NCgkJCQkJCQkJCQk8L2J1dHRvbj4NCgkJCQkJCQkJCTwvaDI+DQoJCQkJCQkJCQk8ZGl2IGlkPSJjb2xsYXBzZS0ke3BvcnRpZH0iIGNsYXNzPSJhY2NvcmRpb24tY29sbGFwc2UgY29sbGFwc2UiIGFyaWEtbGFiZWxsZWRieT0iaGVhZGluZy0ke3BvcnRpZH0iIGRhdGEtYnMtcGFyZW50PSIjYWNjb3JkaW9uIj4NCgkJCQkJCQkJCQk8ZGl2IGNsYXNzPSJjYXJkLWJvZHkiPg0KCQkJCQkJCQkJCQkke3NjcmlwdG91dHB1dH0NCgkJCQkJCQkJCQk8L2Rpdj4NCgkJCQkJCQkJCTwvZGl2Pg0KCQkJCQkJCQk8L2Rpdj4NCgkJCQkJCQk8L2Rpdj4NCgkJCQkJCWANCgkJCQkJLy88c2NyaXB0PjwhLS0gd2VpcmQgYnVnIGluIElERSBkb2Vzbid0IHJlY29nbml6ZSB0ZW1wbGF0ZSBsaXRlcmFscyAtLT4NCgkJCQkJcG9ydGlkID0gIiI7IHByb3RvY29sID0gIiI7IHNlcnZpY2UgPSAiIjsgc3ZjcHJvZCA9ICIiOyB2ZXJzaW9uID0gIiI7IHNjcmlwdG91dHB1dCA9ICIiOw0KCQkJCX0NCgkJCX0pOw0KCQkJaG9zdHNjcmlwdHMgPSAiIg0KCQkJJCh4bWwpLmZpbmQoImhvc3RzY3JpcHQiKS5lYWNoKGZ1bmN0aW9uKCkgew0KCQkJCSQodGhpcykuZmluZCgic2NyaXB0IikuZWFjaChmdW5jdGlvbigpIHsNCgkJCQkJdmFyIHNjcmlwdGlkID0gJCh0aGlzKS5hdHRyKCJpZCIpOw0KCQkJCQl2YXIgbm1zb3V0cCA9ICQodGhpcykuYXR0cigib3V0cHV0Iik7DQoJCQkJCXZhciBubXNvdXRwY2xlYW4gPSBubXNvdXRwLnJlcGxhY2UoL15cblxzKi8sICIiKTsNCgkJCQkJJCh0aGlzKS5maW5kKCJ0YWJsZSIpLmVhY2goZnVuY3Rpb24oKSB7DQoJCQkJCQl2YXIgc2NyaXB0dGFibGUgPSAkKHRoaXMpLmF0dHIoImtleSIpOw0KCQkJCQkJaWYgKHNjcmlwdHRhYmxlKSB7DQoJCQkJCQkJa2V5ZGF0YSArPSAiPHN0cm9uZz4iICsgc2NyaXB0dGFibGUgKyAiPC9zdHJvbmc+XG4iOw0KCQkJCQkJfSBlbHNlIHsNCgkJCQkJCQlrZXlkYXRhID0gIlxuIjsNCgkJCQkJCX0NCgkJCQkJCS8va2V5ZGF0YSArPSAiPHRhYmxlPlxuIjsNCgkJCQkJCSQodGhpcykuZmluZCgiZWxlbSIpLmVhY2goZnVuY3Rpb24oKSB7DQoJCQkJCQkJdmFyIGVrbiA9ICQodGhpcykuYXR0cigia2V5Iik7DQoJCQkJCQkJaWYgKCFla24pIHsgZWtuID0gc2NyaXB0dGFibGU7IH0NCgkJCQkJCQl2YXIgZWtkID0gJCh0aGlzKS50ZXh0KCk7DQoJCQkJCQkJa2V5ZGF0YSArPSAiPGRpdiBjbGFzcz1cImNvbnRhaW5lciBjYXJkLW1ldGEgZC1mbGV4IGp1c3RpZnktY29udGVudC1iZXR3ZWVuXCI+XG4iOw0KCQkJCQkJCWtleWRhdGEgKz0gIjxkaXYgY2xhc3M9J2NvbC0yJz4iICsgZWtuICsgIjwvZGl2PlxuIjsNCgkJCQkJCQlrZXlkYXRhICs9ICI8ZGl2IHN0eWxlPVwibWF4LXdpZHRoOiAgNTUwcHghaW1wb3J0YW50O1wiPjxwcmUgc3R5bGU9XCJ3aGl0ZS1zcGFjZTogcHJlLXdyYXA7IHdvcmQtd3JhcDogYnJlYWstd29yZDtcIj48Y29kZT4iICsgZWtkICsgIjwvY29kZT48L3ByZT48L2Rpdj5cbiI7DQoJCQkJCQkJa2V5ZGF0YSArPSAiPC9kaXY+XG4iOw0KCQkJCQkJCWVrZCA9ICIiOyBla24gPSAiIjsNCgkJCQkJCX0pOw0KCQkJCQl9KTsNCgkJCQkJc2NyaXB0b3V0cHV0ICs9ICI8cHJlPjxjb2RlPiIgKyBubXNvdXRwY2xlYW4gKyAiPC9jb2RlPjwvcHJlPiIgKyBrZXlkYXRhICsgIlxuIjsNCgkJCQkJaG9zdHNjcmlwdHMgKz0gYA0KCQkJCQkJPGRpdiBjbGFzcz0iYWNjb3JkaW9uLWl0ZW0iPg0KCQkJCQkJCTxkaXYgY2xhc3M9ImNhcmQgYmctZGFyayB0ZXh0LWxpZ2h0IGJvcmRlci1pbmZvIj4NCgkJCQkJCQkJPGgyIGNsYXNzPSJjYXJkLWhlYWRlciI+DQoJCQkJCQkJCQk8YnV0dG9uIGNsYXNzPSJhY2NvcmRpb24tYnV0dG9uIiB0eXBlPSJidXR0b24iIGRhdGEtYnMtdG9nZ2xlPSJjb2xsYXBzZSIgZGF0YS1icy10YXJnZXQ9IiNjb2xsYXBzZS0ke3NjcmlwdGlkfSIgYXJpYS1leHBhbmRlZD0iZmFsc2UiIGFyaWEtY29udHJvbHM9ImNvbGxhcHNlLSR7c2NyaXB0aWR9Ij4NCgkJCQkJCQkJCQk8c3Ryb25nPk5NQVAgU2NhbiBTY3JpcHQ6ICR7c2NyaXB0aWR9PC9zdHJvbmc+DQoJCQkJCQkJCQk8L2J1dHRvbj4NCgkJCQkJCQkJPC9oMj4NCgkJCQkJCQkJPGRpdiBpZD0iY29sbGFwc2UtJHtzY3JpcHRpZH0iIGNsYXNzPSJhY2NvcmRpb24tY29sbGFwc2UgY29sbGFwc2UiIGFyaWEtbGFiZWxsZWRieT0iaGVhZGluZy0ke3NjcmlwdGlkfSIgZGF0YS1icy1wYXJlbnQ9IiNhY2NvcmRpb24iPg0KCQkJCQkJCQkJPGRpdiBjbGFzcz0iY2FyZC1ib2R5Ij4NCgkJCQkJCQkJCQkke3NjcmlwdG91dHB1dH0NCgkJCQkJCQkJCTwvZGl2Pg0KCQkJCQkJCQk8L2Rpdj4NCgkJCQkJCQk8L2Rpdj4NCgkJCQkJCTwvZGl2Pg0KCQkJCQlgOw0KCQkJCQkvLzxzY3JpcHQ+PCEtLSB3ZWlyZCBidWcgaW4gSURFIGRvZXNuJ3QgcmVjb2duaXplIHRlbXBsYXRlIGxpdGVyYWxzIC0tPg0KCQkJCQlubXNuYW1lID0gIiI7IG5tc291dHAgPSAiIjsga2V5ZGF0YSA9ICIiOw0KCQkJCX0pOw0KCQkJfSk7DQoJCQkvLyBEaXNwbGF5IGRpdmUgc3lzdGVtIHByb2ZpbGUgZGF0YQ0KCQkJdmFyIHNwaGVhZCA9ICI8ZGl2IGNsYXNzPSdzeXN0ZW0tcHJvZmlsZS1jb250YWluZXIgY29udGFpbmVyIGNhcmQtbWV0YSBqdXN0aWZ5LWNvbnRlbnQtYmV0d2Vlbic+IjsNCgkJCXZhciBzeXN0ZW1Qcm9maWxlID0gIiI7DQoJCQl2YXIgb3MgPSAkKHhtbCkuZmluZCgib3MiKTsNCgkJCS8vY29uc29sZS5sb2cob3NsaWtlbHkoeG1sKSk7DQoJCQlpZiAoaG9zdG5hbWUpIHsNCgkJCQlzeXN0ZW1Qcm9maWxlICs9ICI8ZGl2IGNsYXNzPVwiY29udGFpbmVyIGNhcmQtbWV0YSBkLWZsZXgganVzdGlmeS1jb250ZW50LWJldHdlZW5cIiBzdHlsZT1cInBhZGRpbmctdG9wOjEwcHg7IHBhZGRpbmctYm90dG9tOjEwcHhcIj48ZGl2PjxzdHJvbmc+SG9zdG5hbWU6PC9zdHJvbmc+PC9kaXY+PGRpdj4iICsgaG9zdG5hbWUgKyAiPC9kaXY+PC9kaXY+IjsNCgkJCX0NCgkJCWlmIChpcHY0KSB7DQoJCQkJc3lzdGVtUHJvZmlsZSArPSAiPGRpdiBjbGFzcz1cImNvbnRhaW5lciBjYXJkLW1ldGEgZC1mbGV4IGp1c3RpZnktY29udGVudC1iZXR3ZWVuXCIgc3R5bGU9XCJwYWRkaW5nLXRvcDoxMHB4OyBwYWRkaW5nLWJvdHRvbToxMHB4XCI+PGRpdj48c3Ryb25nPklQIEFkZHJlc3M6PC9zdHJvbmc+PC9kaXY+PGRpdj4iICsgaXB2NCArICI8L2Rpdj48L2Rpdj4iOw0KCQkJfQ0KCQkJaWYgKHRyYWNlcm91dGUpIHsNCgkJCQlzeXN0ZW1Qcm9maWxlICs9ICI8ZGl2IGNsYXNzPVwiY29udGFpbmVyIGNhcmQtbWV0YSBkLWZsZXgganVzdGlmeS1jb250ZW50LWJldHdlZW5cIiBzdHlsZT1cInBhZGRpbmctdG9wOjEwcHg7IHBhZGRpbmctYm90dG9tOjEwcHhcIj48ZGl2PjxzdHJvbmc+VHJhY2Vyb3V0ZTo8L3N0cm9uZz48L2Rpdj48ZGl2PiIgKyB0cmFjZXJvdXRlICsgIjwvZGl2PjwvZGl2PiI7DQoJCQl9DQoJCQlpZiAoZG5zKSB7DQoJCQkJc3lzdGVtUHJvZmlsZSArPSAiPGRpdiBjbGFzcz1cImNvbnRhaW5lciBjYXJkLW1ldGEgZC1mbGV4IGp1c3RpZnktY29udGVudC1iZXR3ZWVuXCIgc3R5bGU9XCJwYWRkaW5nLXRvcDoxMHB4OyBwYWRkaW5nLWJvdHRvbToxMHB4XCI+PGRpdj48c3Ryb25nPkROUyBSZWNvcmRzOjwvc3Ryb25nPjwvZGl2PjxkaXY+IiArIGRucyArICI8L2Rpdj48L2Rpdj4iOw0KCQkJfQ0KCQkJaWYgKHN0KSB7DQoJCQkJc3lzdGVtUHJvZmlsZSArPSAiPGRpdiBjbGFzcz1cImNvbnRhaW5lciBjYXJkLW1ldGEgZC1mbGV4IGp1c3RpZnktY29udGVudC1iZXR3ZWVuXCIgc3R5bGU9XCJwYWRkaW5nLXRvcDoxMHB4OyBwYWRkaW5nLWJvdHRvbToxMHB4XCI+PGRpdj48c3Ryb25nPlNjYW4gU3RhcnQgRGF0ZS9UaW1lOjwvc3Ryb25nPjwvZGl2PjxkaXY+IiArIHN0LnRvTG9jYWxlU3RyaW5nKCkgKyAiPC9kaXY+PC9kaXY+IjsNCgkJCX0NCgkJCWlmIChldCkgew0KCQkJCXN5c3RlbVByb2ZpbGUgKz0gIjxkaXYgY2xhc3M9XCJjb250YWluZXIgY2FyZC1tZXRhIGQtZmxleCBqdXN0aWZ5LWNvbnRlbnQtYmV0d2VlblwiIHN0eWxlPVwicGFkZGluZy10b3A6MTBweDsgcGFkZGluZy1ib3R0b206MTBweFwiPjxkaXY+PHN0cm9uZz5TY2FubmVyIFJ1bnRpbWU6PC9zdHJvbmc+PC9kaXY+PGRpdj4iICsgcnVudGltZS50b1N0cmluZygpICsgIjwvZGl2PjwvZGl2PiI7DQoJCQl9DQoJCQlpZiAob3MpIHsNCgkJCQlzeXN0ZW1Qcm9maWxlICs9ICI8ZGl2IGNsYXNzPVwiY29udGFpbmVyIGNhcmQtbWV0YSBkLWZsZXgganVzdGlmeS1jb250ZW50LWJldHdlZW5cIiBzdHlsZT1cInBhZGRpbmctdG9wOjEwcHg7IHBhZGRpbmctYm90dG9tOjEwcHhcIj48ZGl2PjxzdHJvbmc+T3BlcmF0aW5nIFN5c3RlbTo8L3N0cm9uZz48L2Rpdj48ZGl2PiIgKyBvc2xpa2VseSh4bWwpICsgIjwvZGl2PjwvZGl2PiI7DQoJCQl9DQoJCQlpZiAocG9ydHN1bW0pIHsNCgkJCQlwcm9kdWN0SHRtbCA9ICI8ZGl2IGNsYXNzPVwiY29udGFpbmVyIGNhcmQtbWV0YSBkLWZsZXgganVzdGlmeS1jb250ZW50LWJldHdlZW5cIiBzdHlsZT1cInBhZGRpbmctdG9wOjEwcHg7IHBhZGRpbmctYm90dG9tOjEwcHhcIj4gPHRhYmxlIGNsYXNzPVwidGFibGUgdGFibGUtc20gdGFibGUtYm9yZGVybGVzcyB0YWJsZS1kYXJrIGZnLXZpa3RoZW1lYmx1ZTkgdGFibGUtaG92ZXJcIj48dGhlYWQ+PHRyPjx0aCBzY29wZT1cImNvbFwiPlBvcnQjPC90aD48dGggc2NvcGU9XCJjb2xcIj5TZXJ2aWNlPC90aD48dGggc2NvcGU9XCJjb2xcIj5TZXJ2aWNlIE5hbWU8L3RoPjwvdHI+PC90aGVhZD48dGJvZHk+IjsNCgkJCQlpZiAocG9ydHN1bW0ubGVuZ3RoID4gMCkgew0KCQkJCQlwb3J0c3VtbS5mb3JFYWNoKHBvcnRpbmZvID0+IHsNCgkJCQkJCXByb2R1Y3RIdG1sICs9ICIiICsgcG9ydGluZm8gKyAiXG4iOw0KCQkJCQl9KTsNCgkJCQl9DQoJCQkJcHJvZHVjdEh0bWwgKz0gIjwvdGJvZHk+PC90YWJsZT48L2Rpdj4iOw0KCQkJCS8vc3lzdGVtUHJvZmlsZSArPSBwcm9kdWN0SHRtbDsNCgkJCX0NCg0KCQkJZnVsbHN5c3RlbXByb2ZpbGUgPSBzcGhlYWQgKyBzeXN0ZW1Qcm9maWxlICsgIjwvZGl2PiIgKyBzcGhlYWQgKyBwcm9kdWN0SHRtbCArICI8L2Rpdj4iOyANCgkJCSQoJyNzeXN0ZW0tcHJvZmlsZScpLmh0bWwoZnVsbHN5c3RlbXByb2ZpbGUpOw0KCQkJLy8gRGlzcGxheSBkaXZlIG9wZW4gcG9ydHMgZGF0YQ0KCQkJdmFyIG9wZW5Qb3J0cyA9ICI8ZGl2IGNsYXNzPSdvcGVuLXBvcnRzJz4iOw0KCQkJb3BlblBvcnRzICs9IHBvcnRzOw0KCQkJb3BlblBvcnRzICs9ICI8L2Rpdj4iOw0KCQkJJCgnI29wZW4tcG9ydHMnKS5odG1sKG9wZW5Qb3J0cyArIGhvc3RzY3JpcHRzKTsNCgkJDQoJCX0NCgkJZnVuY3Rpb24gdGhtKHRvdGFsU2Vjb25kcykgew0KCQkJY29uc3QgdG90YWxNaW51dGVzID0gTWF0aC5mbG9vcih0b3RhbFNlY29uZHMgLyA2MCk7DQoJCQljb25zdCBzZWNvbmRzID0gdG90YWxTZWNvbmRzICUgNjA7DQoJCQljb25zdCBob3VycyA9IE1hdGguZmxvb3IodG90YWxNaW51dGVzIC8gNjApOw0KCQkJY29uc3QgbWludXRlcyA9IHRvdGFsTWludXRlcyAlIDYwOw0KCQkJdGltZXN0cmluZyA9ICIiOw0KCQkJaWYgKGhvdXJzID4gMCkgeyB0aW1lc3RyaW5nID0gaG91cnMgKyAiaG91cnMsICIgKyBtaW51dGVzICsgIiBtaW4uLCAiICsgc2Vjb25kcyArICIgc2VjLiI7IH0gZWxzZSB7IGlmIChtaW51dGVzID4gMCkgewl0aW1lc3RyaW5nID0gbWludXRlcyArICIgbWluLiwgIiArIHNlY29uZHMgKyAiIHNlYy4iOyB9IGVsc2UgeyB0aW1lc3RyaW5nID0gc2Vjb25kcyArICIgc2VjLiI7fQkJCX0NCgkJCXJldHVybiB0aW1lc3RyaW5nOw0KCQl9DQoJCWZ1bmN0aW9uIG1vZGUoYXJyYXkpIHsNCgkJCWlmKGFycmF5LmxlbmdkaXYgPT0gMCkgeyByZXR1cm4gbnVsbDsgfQ0KCQkJdmFyIG1vZGVNYXAgPSB7fTsNCgkJCXZhciBtYXhFbCA9IGFycmF5WzBdLCBtYXhDb3VudCA9IDE7DQoJCQlmb3IodmFyIGkgPSAwOyBpIDwgYXJyYXkubGVuZ2RpdjsgaSsrKSB7DQoJCQkJdmFyIGVsID0gYXJyYXlbaV07DQoJCQkJaWYobW9kZU1hcFtlbF0gPT0gbnVsbCkgew0KCQkJCQltb2RlTWFwW2VsXSA9IDE7DQoJCQkJfSBlbHNlIHsNCgkJCQkJbW9kZU1hcFtlbF0rKzsNCgkJCQl9DQoJCQkJaWYobW9kZU1hcFtlbF0gPiBtYXhDb3VudCkgew0KCQkJCQltYXhFbCA9IGVsOw0KCQkJCQltYXhDb3VudCA9IG1vZGVNYXBbZWxdOw0KCQkJCX0NCgkJCX0NCgkJCXJldHVybiBtYXhFbDsNCgkJfQ0KCQlmdW5jdGlvbiBvc2xpa2VseSh4bWwpew0KCQkJdmFyIG9zbWF0Y2hOb2RlcyA9ICQoeG1sKS5maW5kKCJvc21hdGNoIik7DQoJCQl2YXIgb3NtYXRjaEFycmF5ID0gW107DQoJCQlpZiAob3NtYXRjaE5vZGVzLmxlbmd0aCA+IDEpIHsNCgkJCQlvc21hdGNoTm9kZXMuZWFjaChmdW5jdGlvbigpIHsNCgkJCQkJdmFyIG9zZmFtaWx5ID0gJCh0aGlzKS5maW5kKCJvc2NsYXNzIikuYXR0cigib3NmYW1pbHkiKTsNCgkJCQkJdmFyIGFjY3VyYWN5ID0gJCh0aGlzKS5hdHRyKCJhY2N1cmFjeSIpOw0KCQkJCQlvc21hdGNoQXJyYXkucHVzaCh7IG9zZmFtaWx5OiBvc2ZhbWlseSwgYWNjdXJhY3k6IGFjY3VyYWN5IH0pOw0KCQkJCX0pOw0KCQkJCW9zbWF0Y2hBcnJheS5zb3J0KGZ1bmN0aW9uKGEsIGIpIHsNCgkJCQkJcmV0dXJuIGIuYWNjdXJhY3kgLSBhLmFjY3VyYWN5Ow0KCQkJCX0pOw0KCQkJCXZhciBoaWdoZXN0QWNjdXJhY3kgPSBvc21hdGNoQXJyYXlbMF0uYWNjdXJhY3k7DQoJCQkJdmFyIGhpZ2hlc3RPU0ZhbWlseSA9ICIiOw0KCQkJCXZhciBvc2ZhbWlsaWVzID0gW107DQoJCQkJZm9yICh2YXIgaSA9IDA7IGkgPCBvc21hdGNoQXJyYXkubGVuZ2RpdjsgaSsrKSB7DQoJCQkJCWlmIChvc21hdGNoQXJyYXlbaV0uYWNjdXJhY3kgPT0gaGlnaGVzdEFjY3VyYWN5KSB7DQoJCQkJCQlvc2ZhbWlsaWVzLnB1c2gob3NtYXRjaEFycmF5W2ldLm9zZmFtaWx5KTsNCgkJCQkJfSBlbHNlIHsNCgkJCQkJCWJyZWFrOw0KCQkJCQl9DQoJCQkJfQ0KCQkJCW9zZmFtaWxpZXMgPSBbLi4ubmV3IFNldChvc2ZhbWlsaWVzKV07DQoJCQkJaWYgKG9zZmFtaWxpZXMubGVuZ2RpdiA9PSAxKSB7DQoJCQkJCWhpZ2hlc3RPU0ZhbWlseSA9IG9zZmFtaWxpZXNbMF07DQoJCQkJfQ0KCQkJfSBlbHNlIHsNCgkJCQl2YXIgb3NmYW1pbHkgPSAkKG9zbWF0Y2hOb2RlcykuZmluZCgib3NjbGFzcyIpLmF0dHIoIm9zZmFtaWx5Iik7DQoJCQkJaGlnaGVzdE9TRmFtaWx5ID0gb3NmYW1pbHk7DQoJCQl9DQoJCQljb25zb2xlLmxvZygiSGlnaGVzdCBsaWtlbHkgT1MgZmFtaWx5OiAiICsgaGlnaGVzdE9TRmFtaWx5KTsNCgkJCXJldHVybiBoaWdoZXN0T1NGYW1pbHk7DQoJCX0NCgk8L3NjcmlwdD4NCjwvaHRtbD4NCg0KPHNjcmlwdD4NCgl2YXIgeG1sMjAyNjcwNDkgPSBhdG9iKCJQRDk0Yld3Z2RtVnljMmx2YmowaU1TNHdJaUJsYm1OdlpHbHVaejBpVlZSR0xUZ2lQejRLUENGRVQwTlVXVkJGSUc1dFlYQnlkVzQrQ2p3L2VHMXNMWE4wZVd4bGMyaGxaWFFnYUhKbFpqMGlabWxzWlRvdkx5OTFjM0l2WW1sdUx5NHVMM05vWVhKbEwyNXRZWEF2Ym0xaGNDNTRjMndpSUhSNWNHVTlJblJsZUhRdmVITnNJajgrQ2p3aExTMGdUbTFoY0NBM0xqa3pJSE5qWVc0Z2FXNXBkR2xoZEdWa0lFMXZiaUJCY0hJZ01UY2dNVEk2TkRNNk5UWWdNakF5TXlCaGN6b2dibTFoY0NBdEppTTBOVHR0WVhndGNuUjBMWFJwYldWdmRYUWdNVEF3TUcxeklDMG1JelExTzIxcGJpMXlZWFJsSURNMU1EQWdMVkJ1SUMxUElDMXdJRlE2T0RBc01UTTFMREV6T1N3ME5EVXNOVGs0TlN3ME56QXdNU3cwT1RZMk5DdzBPVFkyTlN3ME9UWTJOaXcwT1RZMk55dzBPVFkyT0N3ME9UWTJPU3cwT1RZM01DdzBPVFkzTVNBdGMxUWdMWE5XSUMwbUl6UTFPM05qY21sd2REMWtaV1poZFd4MExHaDBkSEF0ZG5Wc2Jpb3NiWE55Y0dNdFpXNTFiUzV1YzJVc2MyMWlMV1Z1ZFcwdGMyaGhjbVZ6TG01elpTeHpiV0l0ZG5Wc2JpMHFMSE50WWkxbGJuVnRMWFZ6WlhKekxtNXpaU3h6YldJdGMzbHpkR1Z0TFdsdVptOHVibk5sTEhOdFlpMWtiM1ZpYkdVdGNIVnNjMkZ5TFdKaFkydGtiMjl5TG01elpTeHpiV0l5TFhaMWJHNHRkWEIwYVcxbExtNXpaU3h6YldJeUxYUnBiV1V1Ym5ObExITnRZaTF2Y3kxa2FYTmpiM1psY25rdWJuTmxMSE50WWkxelpYSjJaWEl0YzNSaGRITXVibk5sTEhOdFlqSXRjMlZqZFhKcGRIa3RiVzlrWlM1dWMyVWdMVzlCSUM5b2IyMWxMMnRoYkdrdlVGZExMMUJYU3kxTVFVSXRNakF5TXk5TlpXUjBaV05vTHpFNU1pNHhOamd1TVRrd0xqRXlNUzkyZFd4dVh6RTVNaTR4TmpndU1Ua3dMakV5TVNBeE9USXVNVFk0TGpFNU1DNHhNakVnTFMwK0NqeHViV0Z3Y25WdUlITmpZVzV1WlhJOUltNXRZWEFpSUdGeVozTTlJbTV0WVhBZ0xTWWpORFU3YldGNExYSjBkQzEwYVcxbGIzVjBJREV3TURCdGN5QXRKaU0wTlR0dGFXNHRjbUYwWlNBek5UQXdJQzFRYmlBdFR5QXRjQ0JVT2pnd0xERXpOU3d4TXprc05EUTFMRFU1T0RVc05EY3dNREVzTkRrMk5qUXNORGsyTmpVc05EazJOallzTkRrMk5qY3NORGsyTmpnc05EazJOamtzTkRrMk56QXNORGsyTnpFZ0xYTlVJQzF6VmlBdEppTTBOVHR6WTNKcGNIUTlaR1ZtWVhWc2RDeG9kSFJ3TFhaMWJHNHFMRzF6Y25CakxXVnVkVzB1Ym5ObExITnRZaTFsYm5WdExYTm9ZWEpsY3k1dWMyVXNjMjFpTFhaMWJHNHRLaXh6YldJdFpXNTFiUzExYzJWeWN5NXVjMlVzYzIxaUxYTjVjM1JsYlMxcGJtWnZMbTV6WlN4emJXSXRaRzkxWW14bExYQjFiSE5oY2kxaVlXTnJaRzl2Y2k1dWMyVXNjMjFpTWkxMmRXeHVMWFZ3ZEdsdFpTNXVjMlVzYzIxaU1pMTBhVzFsTG01elpTeHpiV0l0YjNNdFpHbHpZMjkyWlhKNUxtNXpaU3h6YldJdGMyVnlkbVZ5TFhOMFlYUnpMbTV6WlN4emJXSXlMWE5sWTNWeWFYUjVMVzF2WkdVdWJuTmxJQzF2UVNBdmFHOXRaUzlyWVd4cEwxQlhTeTlRVjBzdFRFRkNMVEl3TWpNdlRXVmtkR1ZqYUM4eE9USXVNVFk0TGpFNU1DNHhNakV2ZG5Wc2JsOHhPVEl1TVRZNExqRTVNQzR4TWpFZ01Ua3lMakUyT0M0eE9UQXVNVEl4SWlCemRHRnlkRDBpTVRZNE1UYzBPVGd6TmlJZ2MzUmhjblJ6ZEhJOUlrMXZiaUJCY0hJZ01UY2dNVEk2TkRNNk5UWWdNakF5TXlJZ2RtVnljMmx2YmowaU55NDVNeUlnZUcxc2IzVjBjSFYwZG1WeWMybHZiajBpTVM0d05TSStDanh6WTJGdWFXNW1ieUIwZVhCbFBTSmpiMjV1WldOMElpQndjbTkwYjJOdmJEMGlkR053SWlCdWRXMXpaWEoyYVdObGN6MGlNVFFpSUhObGNuWnBZMlZ6UFNJNE1Dd3hNelVzTVRNNUxEUTBOU3cxT1RnMUxEUTNNREF4TERRNU5qWTBMVFE1TmpjeElpOCtDangyWlhKaWIzTmxJR3hsZG1Wc1BTSXdJaTgrQ2p4a1pXSjFaMmRwYm1jZ2JHVjJaV3c5SWpBaUx6NEtQR2h2YzNRZ2MzUmhjblIwYVcxbFBTSXhOamd4TnpRNU9ETTJJaUJsYm1SMGFXMWxQU0l4TmpneE56UTVPVEkySWo0OGMzUmhkSFZ6SUhOMFlYUmxQU0oxY0NJZ2NtVmhjMjl1UFNKMWMyVnlMWE5sZENJZ2NtVmhjMjl1WDNSMGJEMGlNQ0l2UGdvOFlXUmtjbVZ6Y3lCaFpHUnlQU0l4T1RJdU1UWTRMakU1TUM0eE1qRWlJR0ZrWkhKMGVYQmxQU0pwY0hZMElpOCtDanhvYjNOMGJtRnRaWE0rQ2p3dmFHOXpkRzVoYldWelBnbzhjRzl5ZEhNK1BIQnZjblFnY0hKdmRHOWpiMnc5SW5SamNDSWdjRzl5ZEdsa1BTSTRNQ0krUEhOMFlYUmxJSE4wWVhSbFBTSnZjR1Z1SWlCeVpXRnpiMjQ5SW5ONWJpMWhZMnNpSUhKbFlYTnZibDkwZEd3OUlqQWlMejQ4YzJWeWRtbGpaU0J1WVcxbFBTSm9kSFJ3SWlCd2NtOWtkV04wUFNKTmFXTnliM052Wm5RZ1NVbFRJR2gwZEhCa0lpQjJaWEp6YVc5dVBTSXhNQzR3SWlCdmMzUjVjR1U5SWxkcGJtUnZkM01pSUcxbGRHaHZaRDBpY0hKdlltVmtJaUJqYjI1bVBTSXhNQ0krUEdOd1pUNWpjR1U2TDJFNmJXbGpjbTl6YjJaME9tbHVkR1Z5Ym1WMFgybHVabTl5YldGMGFXOXVYM05sY25acFkyVnpPakV3TGpBOEwyTndaVDQ4WTNCbFBtTndaVG92YnpwdGFXTnliM052Wm5RNmQybHVaRzkzY3p3dlkzQmxQand2YzJWeWRtbGpaVDQ4YzJOeWFYQjBJR2xrUFNKb2RIUndMWE5sY25abGNpMW9aV0ZrWlhJaUlHOTFkSEIxZEQwaVRXbGpjbTl6YjJaMExVbEpVeTh4TUM0d0lqNDhaV3hsYlQ1TmFXTnliM052Wm5RdFNVbFRMekV3TGpBOEwyVnNaVzArQ2p3dmMyTnlhWEIwUGp4elkzSnBjSFFnYVdROUltaDBkSEF0YldWMGFHOWtjeUlnYjNWMGNIVjBQU0ltSTNoaE95QWdVRzkwWlc1MGFXRnNiSGtnY21semEza2diV1YwYUc5a2N6b2dWRkpCUTBVaVBqeDBZV0pzWlNCclpYazlJbEJ2ZEdWdWRHbGhiR3g1SUhKcGMydDVJRzFsZEdodlpITWlQZ284Wld4bGJUNVVVa0ZEUlR3dlpXeGxiVDRLUEM5MFlXSnNaVDRLUEM5elkzSnBjSFErUEhOamNtbHdkQ0JwWkQwaWFIUjBjQzEwYVhSc1pTSWdiM1YwY0hWMFBTSk5aV1JVWldOb0lqNDhaV3hsYlNCclpYazlJblJwZEd4bElqNG1JM2hrT3lZamVHRTdKaU40T1R0TlpXUlVaV05vSmlONFpEc21JM2hoT3p3dlpXeGxiVDRLUEM5elkzSnBjSFErUEM5d2IzSjBQZ284Y0c5eWRDQndjbTkwYjJOdmJEMGlkR053SWlCd2IzSjBhV1E5SWpFek5TSStQSE4wWVhSbElITjBZWFJsUFNKdmNHVnVJaUJ5WldGemIyNDlJbk41YmkxaFkyc2lJSEpsWVhOdmJsOTBkR3c5SWpBaUx6NDhjMlZ5ZG1salpTQnVZVzFsUFNKdGMzSndZeUlnY0hKdlpIVmpkRDBpVFdsamNtOXpiMlowSUZkcGJtUnZkM01nVWxCRElpQnZjM1I1Y0dVOUlsZHBibVJ2ZDNNaUlHMWxkR2h2WkQwaWNISnZZbVZrSWlCamIyNW1QU0l4TUNJK1BHTndaVDVqY0dVNkwyODZiV2xqY205emIyWjBPbmRwYm1SdmQzTThMMk53WlQ0OEwzTmxjblpwWTJVK1BDOXdiM0owUGdvOGNHOXlkQ0J3Y205MGIyTnZiRDBpZEdOd0lpQndiM0owYVdROUlqRXpPU0krUEhOMFlYUmxJSE4wWVhSbFBTSnZjR1Z1SWlCeVpXRnpiMjQ5SW5ONWJpMWhZMnNpSUhKbFlYTnZibDkwZEd3OUlqQWlMejQ4YzJWeWRtbGpaU0J1WVcxbFBTSnVaWFJpYVc5ekxYTnpiaUlnY0hKdlpIVmpkRDBpVFdsamNtOXpiMlowSUZkcGJtUnZkM01nYm1WMFltbHZjeTF6YzI0aUlHOXpkSGx3WlQwaVYybHVaRzkzY3lJZ2JXVjBhRzlrUFNKd2NtOWlaV1FpSUdOdmJtWTlJakV3SWo0OFkzQmxQbU53WlRvdmJ6cHRhV055YjNOdlpuUTZkMmx1Wkc5M2N6d3ZZM0JsUGp3dmMyVnlkbWxqWlQ0OEwzQnZjblErQ2p4d2IzSjBJSEJ5YjNSdlkyOXNQU0owWTNBaUlIQnZjblJwWkQwaU5EUTFJajQ4YzNSaGRHVWdjM1JoZEdVOUltOXdaVzRpSUhKbFlYTnZiajBpYzNsdUxXRmpheUlnY21WaGMyOXVYM1IwYkQwaU1DSXZQanh6WlhKMmFXTmxJRzVoYldVOUltMXBZM0p2YzI5bWRDMWtjeUlnYldWMGFHOWtQU0owWVdKc1pTSWdZMjl1WmowaU15SXZQand2Y0c5eWRENEtQSEJ2Y25RZ2NISnZkRzlqYjJ3OUluUmpjQ0lnY0c5eWRHbGtQU0kxT1RnMUlqNDhjM1JoZEdVZ2MzUmhkR1U5SW05d1pXNGlJSEpsWVhOdmJqMGljM2x1TFdGamF5SWdjbVZoYzI5dVgzUjBiRDBpTUNJdlBqeHpaWEoyYVdObElHNWhiV1U5SW1oMGRIQWlJSEJ5YjJSMVkzUTlJazFwWTNKdmMyOW1kQ0JJVkZSUVFWQkpJR2gwZEhCa0lpQjJaWEp6YVc5dVBTSXlMakFpSUdWNGRISmhhVzVtYnowaVUxTkVVQzlWVUc1UUlpQnZjM1I1Y0dVOUlsZHBibVJ2ZDNNaUlHMWxkR2h2WkQwaWNISnZZbVZrSWlCamIyNW1QU0l4TUNJK1BHTndaVDVqY0dVNkwyODZiV2xqY205emIyWjBPbmRwYm1SdmQzTThMMk53WlQ0OEwzTmxjblpwWTJVK1BITmpjbWx3ZENCcFpEMGlhSFIwY0MxelpYSjJaWEl0YUdWaFpHVnlJaUJ2ZFhSd2RYUTlJazFwWTNKdmMyOW1kQzFJVkZSUVFWQkpMekl1TUNJK1BHVnNaVzArVFdsamNtOXpiMlowTFVoVVZGQkJVRWt2TWk0d1BDOWxiR1Z0UGdvOEwzTmpjbWx3ZEQ0OGMyTnlhWEIwSUdsa1BTSm9kSFJ3TFhScGRHeGxJaUJ2ZFhSd2RYUTlJazV2ZENCR2IzVnVaQ0krUEdWc1pXMGdhMlY1UFNKMGFYUnNaU0krVG05MElFWnZkVzVrUEM5bGJHVnRQZ284TDNOamNtbHdkRDQ4TDNCdmNuUStDanh3YjNKMElIQnliM1J2WTI5c1BTSjBZM0FpSUhCdmNuUnBaRDBpTkRjd01ERWlQanh6ZEdGMFpTQnpkR0YwWlQwaWIzQmxiaUlnY21WaGMyOXVQU0p6ZVc0dFlXTnJJaUJ5WldGemIyNWZkSFJzUFNJd0lpOCtQSE5sY25acFkyVWdibUZ0WlQwaWFIUjBjQ0lnY0hKdlpIVmpkRDBpVFdsamNtOXpiMlowSUVoVVZGQkJVRWtnYUhSMGNHUWlJSFpsY25OcGIyNDlJakl1TUNJZ1pYaDBjbUZwYm1adlBTSlRVMFJRTDFWUWJsQWlJRzl6ZEhsd1pUMGlWMmx1Wkc5M2N5SWdiV1YwYUc5a1BTSndjbTlpWldRaUlHTnZibVk5SWpFd0lqNDhZM0JsUG1Od1pUb3ZienB0YVdOeWIzTnZablE2ZDJsdVpHOTNjend2WTNCbFBqd3ZjMlZ5ZG1salpUNDhjMk55YVhCMElHbGtQU0pvZEhSd0xYUnBkR3hsSWlCdmRYUndkWFE5SWs1dmRDQkdiM1Z1WkNJK1BHVnNaVzBnYTJWNVBTSjBhWFJzWlNJK1RtOTBJRVp2ZFc1a1BDOWxiR1Z0UGdvOEwzTmpjbWx3ZEQ0OGMyTnlhWEIwSUdsa1BTSm9kSFJ3TFhObGNuWmxjaTFvWldGa1pYSWlJRzkxZEhCMWREMGlUV2xqY205emIyWjBMVWhVVkZCQlVFa3ZNaTR3SWo0OFpXeGxiVDVOYVdOeWIzTnZablF0U0ZSVVVFRlFTUzh5TGpBOEwyVnNaVzArQ2p3dmMyTnlhWEIwUGp3dmNHOXlkRDRLUEhCdmNuUWdjSEp2ZEc5amIydzlJblJqY0NJZ2NHOXlkR2xrUFNJME9UWTJOQ0krUEhOMFlYUmxJSE4wWVhSbFBTSnZjR1Z1SWlCeVpXRnpiMjQ5SW5ONWJpMWhZMnNpSUhKbFlYTnZibDkwZEd3OUlqQWlMejQ4YzJWeWRtbGpaU0J1WVcxbFBTSnRjM0p3WXlJZ2NISnZaSFZqZEQwaVRXbGpjbTl6YjJaMElGZHBibVJ2ZDNNZ1VsQkRJaUJ2YzNSNWNHVTlJbGRwYm1SdmQzTWlJRzFsZEdodlpEMGljSEp2WW1Wa0lpQmpiMjVtUFNJeE1DSStQR053WlQ1amNHVTZMMjg2YldsamNtOXpiMlowT25kcGJtUnZkM004TDJOd1pUNDhMM05sY25acFkyVStQQzl3YjNKMFBnbzhjRzl5ZENCd2NtOTBiMk52YkQwaWRHTndJaUJ3YjNKMGFXUTlJalE1TmpZMUlqNDhjM1JoZEdVZ2MzUmhkR1U5SW05d1pXNGlJSEpsWVhOdmJqMGljM2x1TFdGamF5SWdjbVZoYzI5dVgzUjBiRDBpTUNJdlBqeHpaWEoyYVdObElHNWhiV1U5SW0xemNuQmpJaUJ3Y205a2RXTjBQU0pOYVdOeWIzTnZablFnVjJsdVpHOTNjeUJTVUVNaUlHOXpkSGx3WlQwaVYybHVaRzkzY3lJZ2JXVjBhRzlrUFNKd2NtOWlaV1FpSUdOdmJtWTlJakV3SWo0OFkzQmxQbU53WlRvdmJ6cHRhV055YjNOdlpuUTZkMmx1Wkc5M2N6d3ZZM0JsUGp3dmMyVnlkbWxqWlQ0OEwzQnZjblErQ2p4d2IzSjBJSEJ5YjNSdlkyOXNQU0owWTNBaUlIQnZjblJwWkQwaU5EazJOallpUGp4emRHRjBaU0J6ZEdGMFpUMGliM0JsYmlJZ2NtVmhjMjl1UFNKemVXNHRZV05ySWlCeVpXRnpiMjVmZEhSc1BTSXdJaTgrUEhObGNuWnBZMlVnYm1GdFpUMGliWE55Y0dNaUlIQnliMlIxWTNROUlrMXBZM0p2YzI5bWRDQlhhVzVrYjNkeklGSlFReUlnYjNOMGVYQmxQU0pYYVc1a2IzZHpJaUJ0WlhSb2IyUTlJbkJ5YjJKbFpDSWdZMjl1WmowaU1UQWlQanhqY0dVK1kzQmxPaTl2T20xcFkzSnZjMjltZERwM2FXNWtiM2R6UEM5amNHVStQQzl6WlhKMmFXTmxQand2Y0c5eWRENEtQSEJ2Y25RZ2NISnZkRzlqYjJ3OUluUmpjQ0lnY0c5eWRHbGtQU0kwT1RZMk55SStQSE4wWVhSbElITjBZWFJsUFNKdmNHVnVJaUJ5WldGemIyNDlJbk41YmkxaFkyc2lJSEpsWVhOdmJsOTBkR3c5SWpBaUx6NDhjMlZ5ZG1salpTQnVZVzFsUFNKdGMzSndZeUlnY0hKdlpIVmpkRDBpVFdsamNtOXpiMlowSUZkcGJtUnZkM01nVWxCRElpQnZjM1I1Y0dVOUlsZHBibVJ2ZDNNaUlHMWxkR2h2WkQwaWNISnZZbVZrSWlCamIyNW1QU0l4TUNJK1BHTndaVDVqY0dVNkwyODZiV2xqY205emIyWjBPbmRwYm1SdmQzTThMMk53WlQ0OEwzTmxjblpwWTJVK1BDOXdiM0owUGdvOGNHOXlkQ0J3Y205MGIyTnZiRDBpZEdOd0lpQndiM0owYVdROUlqUTVOalk0SWo0OGMzUmhkR1VnYzNSaGRHVTlJbTl3Wlc0aUlISmxZWE52YmowaWMzbHVMV0ZqYXlJZ2NtVmhjMjl1WDNSMGJEMGlNQ0l2UGp4elpYSjJhV05sSUc1aGJXVTlJbTF6Y25CaklpQndjbTlrZFdOMFBTSk5hV055YjNOdlpuUWdWMmx1Wkc5M2N5QlNVRU1pSUc5emRIbHdaVDBpVjJsdVpHOTNjeUlnYldWMGFHOWtQU0p3Y205aVpXUWlJR052Ym1ZOUlqRXdJajQ4WTNCbFBtTndaVG92YnpwdGFXTnliM052Wm5RNmQybHVaRzkzY3p3dlkzQmxQand2YzJWeWRtbGpaVDQ4TDNCdmNuUStDanh3YjNKMElIQnliM1J2WTI5c1BTSjBZM0FpSUhCdmNuUnBaRDBpTkRrMk5qa2lQanh6ZEdGMFpTQnpkR0YwWlQwaWIzQmxiaUlnY21WaGMyOXVQU0p6ZVc0dFlXTnJJaUJ5WldGemIyNWZkSFJzUFNJd0lpOCtQSE5sY25acFkyVWdibUZ0WlQwaWJYTnljR01pSUhCeWIyUjFZM1E5SWsxcFkzSnZjMjltZENCWGFXNWtiM2R6SUZKUVF5SWdiM04wZVhCbFBTSlhhVzVrYjNkeklpQnRaWFJvYjJROUluQnliMkpsWkNJZ1kyOXVaajBpTVRBaVBqeGpjR1UrWTNCbE9pOXZPbTFwWTNKdmMyOW1kRHAzYVc1a2IzZHpQQzlqY0dVK1BDOXpaWEoyYVdObFBqd3ZjRzl5ZEQ0S1BIQnZjblFnY0hKdmRHOWpiMnc5SW5SamNDSWdjRzl5ZEdsa1BTSTBPVFkzTUNJK1BITjBZWFJsSUhOMFlYUmxQU0p2Y0dWdUlpQnlaV0Z6YjI0OUluTjViaTFoWTJzaUlISmxZWE52Ymw5MGRHdzlJakFpTHo0OGMyVnlkbWxqWlNCdVlXMWxQU0p0YzNKd1l5SWdjSEp2WkhWamREMGlUV2xqY205emIyWjBJRmRwYm1SdmQzTWdVbEJESWlCdmMzUjVjR1U5SWxkcGJtUnZkM01pSUcxbGRHaHZaRDBpY0hKdlltVmtJaUJqYjI1bVBTSXhNQ0krUEdOd1pUNWpjR1U2TDI4NmJXbGpjbTl6YjJaME9uZHBibVJ2ZDNNOEwyTndaVDQ4TDNObGNuWnBZMlUrUEM5d2IzSjBQZ284Y0c5eWRDQndjbTkwYjJOdmJEMGlkR053SWlCd2IzSjBhV1E5SWpRNU5qY3hJajQ4YzNSaGRHVWdjM1JoZEdVOUltOXdaVzRpSUhKbFlYTnZiajBpYzNsdUxXRmpheUlnY21WaGMyOXVYM1IwYkQwaU1DSXZQanh6WlhKMmFXTmxJRzVoYldVOUltMXpjbkJqSWlCd2NtOWtkV04wUFNKTmFXTnliM052Wm5RZ1YybHVaRzkzY3lCU1VFTWlJRzl6ZEhsd1pUMGlWMmx1Wkc5M2N5SWdiV1YwYUc5a1BTSndjbTlpWldRaUlHTnZibVk5SWpFd0lqNDhZM0JsUG1Od1pUb3ZienB0YVdOeWIzTnZablE2ZDJsdVpHOTNjend2WTNCbFBqd3ZjMlZ5ZG1salpUNDhMM0J2Y25RK0Nqd3ZjRzl5ZEhNK0NqeHZjejQ4Y0c5eWRIVnpaV1FnYzNSaGRHVTlJbTl3Wlc0aUlIQnliM1J2UFNKMFkzQWlJSEJ2Y25ScFpEMGlPREFpTHo0S1BIQnZjblIxYzJWa0lITjBZWFJsUFNKamJHOXpaV1FpSUhCeWIzUnZQU0oxWkhBaUlIQnZjblJwWkQwaU16STBOalVpTHo0S1BHOXpiV0YwWTJnZ2JtRnRaVDBpVFdsamNtOXpiMlowSUZkcGJtUnZkM01nVTJWeWRtVnlJREl3TVRZaUlHRmpZM1Z5WVdONVBTSTROU0lnYkdsdVpUMGlOell4T1RVaVBnbzhiM05qYkdGemN5QjBlWEJsUFNKblpXNWxjbUZzSUhCMWNuQnZjMlVpSUhabGJtUnZjajBpVFdsamNtOXpiMlowSWlCdmMyWmhiV2xzZVQwaVYybHVaRzkzY3lJZ2IzTm5aVzQ5SWpJd01UWWlJR0ZqWTNWeVlXTjVQU0k0TlNJK1BHTndaVDVqY0dVNkwyODZiV2xqY205emIyWjBPbmRwYm1SdmQzTmZjMlZ5ZG1WeVh6SXdNVFk4TDJOd1pUNDhMMjl6WTJ4aGMzTStDand2YjNOdFlYUmphRDRLUEM5dmN6NEtQSFZ3ZEdsdFpTQnpaV052Ym1SelBTSXhNVGMwTkNJZ2JHRnpkR0p2YjNROUlrMXZiaUJCY0hJZ01UY2dNRGs2TWprNk5ESWdNakF5TXlJdlBnbzhaR2x6ZEdGdVkyVWdkbUZzZFdVOUlqTWlMejRLUEhSamNITmxjWFZsYm1ObElHbHVaR1Y0UFNJeU5UZ2lJR1JwWm1acFkzVnNkSGs5SWtkdmIyUWdiSFZqYXlFaUlIWmhiSFZsY3owaU1qTXpSVFJFTnpFc01UZzNSRFV6TlVFc1JUVTVORFpDTVRrc09UUXlSVE5DT1RVc1JqRXpPRGRCUVRVc1FqUkRRelJHTTBZaUx6NEtQR2x3YVdSelpYRjFaVzVqWlNCamJHRnpjejBpU1c1amNtVnRaVzUwWVd3aUlIWmhiSFZsY3owaU1UQkdOaXd4TUVZM0xERXdSamdzTVRCR09Td3hNRVpCTERFd1JrSWlMejRLUEhSamNIUnpjMlZ4ZFdWdVkyVWdZMnhoYzNNOUlqRXdNREJJV2lJZ2RtRnNkV1Z6UFNKQ01rSTVNalFzUWpKQ09UZzVMRUl5UWpsRlJTeENNa0pCTlRJc1FqSkNRVUkyTEVJeVFrSXhRU0l2UGdvOGFHOXpkSE5qY21sd2RENDhjMk55YVhCMElHbGtQU0p6YldJdGRuVnNiaTF0Y3pFd0xUQTJNU0lnYjNWMGNIVjBQU0pEYjNWc1pDQnViM1FnYm1WbmIzUnBZWFJsSUdFZ1kyOXVibVZqZEdsdmJqcFRUVUk2SUVaaGFXeGxaQ0IwYnlCeVpXTmxhWFpsSUdKNWRHVnpPaUJGVWxKUFVpSStabUZzYzJVOEwzTmpjbWx3ZEQ0OGMyTnlhWEIwSUdsa1BTSnpiV0l5TFhObFkzVnlhWFI1TFcxdlpHVWlJRzkxZEhCMWREMGlKaU40WVRzZ0lETXhNVG9nSmlONFlUc2dJQ0FnVFdWemMyRm5aU0J6YVdkdWFXNW5JR1Z1WVdKc1pXUWdZblYwSUc1dmRDQnlaWEYxYVhKbFpDSStQSFJoWW14bElHdGxlVDBpTXpFeElqNEtQR1ZzWlcwK1RXVnpjMkZuWlNCemFXZHVhVzVuSUdWdVlXSnNaV1FnWW5WMElHNXZkQ0J5WlhGMWFYSmxaRHd2Wld4bGJUNEtQQzkwWVdKc1pUNEtQQzl6WTNKcGNIUStQSE5qY21sd2RDQnBaRDBpYzIxaU1pMTBhVzFsSWlCdmRYUndkWFE5SWlZamVHRTdJQ0JrWVhSbE9pQXlNREl6TFRBMExURTNWREUyT2pRMU9qQXlKaU40WVRzZ0lITjBZWEowWDJSaGRHVTZJRTR2UVNJK1BHVnNaVzBnYTJWNVBTSmtZWFJsSWo0eU1ESXpMVEEwTFRFM1ZERTJPalExT2pBeVBDOWxiR1Z0UGdvOFpXeGxiU0JyWlhrOUluTjBZWEowWDJSaGRHVWlQazR2UVR3dlpXeGxiVDRLUEM5elkzSnBjSFErUEhOamNtbHdkQ0JwWkQwaWMyMWlMWFoxYkc0dGJYTXhNQzB3TlRRaUlHOTFkSEIxZEQwaVptRnNjMlVpUG1aaGJITmxQQzl6WTNKcGNIUStQSE5qY21sd2RDQnBaRDBpYlhOeWNHTXRaVzUxYlNJZ2IzVjBjSFYwUFNKRGIzVnNaQ0J1YjNRZ2JtVm5iM1JwWVhSbElHRWdZMjl1Ym1WamRHbHZianBUVFVJNklFWmhhV3hsWkNCMGJ5QnlaV05sYVhabElHSjVkR1Z6T2lCRlVsSlBVaUkrWm1Gc2MyVThMM05qY21sd2RENDhMMmh2YzNSelkzSnBjSFErUEhScGJXVnpJSE55ZEhROUlqWXhOVE16SWlCeWRIUjJZWEk5SWpNeE5DSWdkRzg5SWpFd01EQXdNQ0l2UGdvOEwyaHZjM1ErQ2p4eWRXNXpkR0YwY3o0OFptbHVhWE5vWldRZ2RHbHRaVDBpTVRZNE1UYzBPVGt5TmlJZ2RHbHRaWE4wY2owaVRXOXVJRUZ3Y2lBeE55QXhNam8wTlRveU5pQXlNREl6SWlCemRXMXRZWEo1UFNKT2JXRndJR1J2Ym1VZ1lYUWdUVzl1SUVGd2NpQXhOeUF4TWpvME5Ub3lOaUF5TURJek95QXhJRWxRSUdGa1pISmxjM01nS0RFZ2FHOXpkQ0IxY0NrZ2MyTmhibTVsWkNCcGJpQTRPUzQ0TlNCelpXTnZibVJ6SWlCbGJHRndjMlZrUFNJNE9TNDROU0lnWlhocGREMGljM1ZqWTJWemN5SXZQanhvYjNOMGN5QjFjRDBpTVNJZ1pHOTNiajBpTUNJZ2RHOTBZV3c5SWpFaUx6NEtQQzl5ZFc1emRHRjBjejRLUEM5dWJXRndjblZ1UGdvPSIpOw0KCW5tYXBzY2Fucy5wdXNoKCJ4bWwyMDI2NzA0OSIpOw0KPC9zY3JpcHQ+DQo=" | base64 -d > ${vulresults}.html
	echo -en "<script>\n" >> ${vulresults}.html
	echo -en "\tvar xml${chksum} = atob(\"${b64xml}\");\n" >> ${vulresults}.html
	echo -en "\tnmapscans.push(\"xml${chksum}\");\n" >> ${vulresults}.html
	echo -en "</script>\n" >> ${vulresults}.html
	chmod 755 ${vulresults}.html
	if [ ! -z "$DISPLAY" ]; then
		envpassdisplay="$DISPLAY"
		envpassxauthority="${XAUTHORITY:-/home/${SUDO_USER}/.Xauthority}"
		su - "${SUDO_USER}" -c "DISPLAY='$envpassdisplay' XAUTHORITY='$envpassxauthority' chromium file://${vulresults}.html" 2>&1 > /dev/null &
	else
		echo "You must open the HTML file manually."
		exit 0
	fi
	
}


if [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then # Check if the input is an IP address
	ip="$1"
	if [ "$1" != "${PWD##*/}" ]; then #use pwd as workspace
		create_workspace "$1"
		workspace=$(pwd)/${ip}
	else
		echo "Using Current Directory as Workspace"
		workspace=${PWD##*/}
	fi
	scantarget "${ip}" "${workspace}"
elif [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then # Check if the input is a CIDR range
    ips=$(nmap -sn -n -iL <(echo $1) | grep "Nmap scan report for" | awk '{print $5}')
    for ip in $ips; do
        create_workspace "${ip}"
		workspace=$(pwd)/${ip}
		scantarget "${ip}" "${workspace}"
    done
elif [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}-[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then # Check if the input is an IP range
    start_ip=$(echo $1 | awk -F- '{print $1}')
    end_ip=$(echo $1 | awk -F- '{print $2}')
    ips=$(nmap -sn -n --range "$start_ip"-"$end_ip" | grep "Nmap scan report for" | awk '{print $5}')
    for ip in $ips; do
        create_workspace "${ip}"
		workspace=$(pwd)/${ip}
		scantarget "${ip}" "${workspace}"
    done
elif [ -f "$1" ]; then # Check if the input is a filename with an IP list
    while read -r line; do
        if [[ $line =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
			pretty '+' "Processing: ${line}"
			ip=${line}
            create_workspace "${ip}"
			workspace=$(pwd)/${ip}
			scantarget "${ip}" "${workspace}"
        fi
    done < "$1"
else
    if echo ${PWD##*/}| grep -oP $regpat >/dev/null; then
        echo "Using Directory as argument"
		scantarget "${PWD##*/}"
		workspace=$(pwd)
		scantarget "${ip}" "${workspace}"
    else
        echo "fail... add an argument"
        echo "Usage: $0 <ip_address|cidr_range|ip_range|filename>"
		exit 1
    fi
fi
