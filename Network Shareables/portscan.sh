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
create_workspace() {
	local ip_address="$1"
	workspace="${ip_address}"
	if [ ! -d "${workspace}" ]; then
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
	udpscanports="21,22,25,42,53,67,68,88,123,110,111,137,138,139,161,162,194,389,500,1194,1512,1701,4500,5901,5900,6900,51820"
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
	opentcpports=$(xmlstarlet sel -t \
		-m "//host/status[@state='up']" \
		-m "../ports/port[state/@state='open']" \
		-v "@portid" -n "${tcpresults}.xml")
	mapfile -t tcp_arr < <(printf '%s\n' "$opentcpports" | sed '/^$/d')
	tportsc=${#tcp_arr[@]}
	if (( tportsc > 0 )); then
		IFS=, tports="${tcp_arr[*]}"
		unset IFS
		pretty '+' "Found ${tportsc} TCP ports open."
	else
		pretty '-' "No TCP ports available, skipping host"
		return 0
	fi
	#############################################################################
	#	UDP SCANNING THE TOP UDP PORTS TO OPTIMIZE TIME
	#############################################################################
	pretty "*" "Scanning UDP Ports"
	if [ -f "${udpresults}.xml" ]; then
		if [[ $(find "${udpresults}.xml" -mtime +1 -print) ]]; then
			pretty '*' "Nmap Options: --max-rtt-timeout 2000ms --min-rate 3500 --max-retries 2 -T3 -p ${udpscanports} -sU ${ip} -oN ${udpresults}"
			nmap --max-rtt-timeout 2000ms --min-rate 3500 --max-retries 2 -p ${udpscanports} -sU ${ip} -oX ${udpresults}.xml
		else
			pretty '-' "Skipping"
		fi
	else
		pretty '*' "Nmap Options: --max-rtt-timeout 2000ms --min-rate 3500 --max-retries 2  -p ${udpscanports} -sU ${ip} -oX ${udpresults}.xml"
		nmap --max-rtt-timeout 2000ms --min-rate 3500 --max-retries 2 -T3 -p ${udpscanports} -sU ${ip} -oX ${udpresults}.xml
	fi
	openudpports=$(xmlstarlet sel -t \
		-m "//host/status[@state='up']" \
		-m "../ports/port[state/@state='open']" \
		-v "@portid" -n "${udpresults}.xml")
	mapfile -t udp_arr < <(printf '%s\n' "$openudpports" | sed '/^$/d')
	uportsc=${#udp_arr[@]}
	uports=""
	if (( uportsc > 0 )); then
		IFS=, uports="${udp_arr[*]}"
		unset IFS
	fi
	allports=""
	allflags=""
	if (( uportsc > 0 )); then
		allports="U:${uports}"
		allflags+=" -sU "
	fi
	if (( tportsc > 0 )); then
		allports="${allports:+${allports},}T:${tports}"
		allflags+=" -sT "
	fi
	if (( tportsc == 0 && uportsc == 0 )); then
		pretty '!' "No ports are open"
		exit 1
	fi
	#############################################################################
	#	Version Scanning all ports
	#############################################################################
	pretty "+" "Identified ports: ${allports}"
	pretty "*" "Executing Full Enumeration Scan"
	if [ -f "${defresults}.xml" ]; then
		if [[ $(find "${defresults}.xml" -mtime +1 -print) ]]; then
			pretty '+' "Nmap Options: ${scanningops} -p ${allports} ${allflags} -sV ${ip}"
			nmap ${scanningops} -p "${allports}" ${allflags} -sV "${ip}" -oN "${defresults}.nmap" -oX "${defresults}.xml"
		else
			pretty '-' "Skipping"
		fi
	else
		nmap ${scanningops} -p "${allports}" ${allflags} -sV "${ip}" -oN "${defresults}.nmap" -oX "${defresults}.xml"
	fi
	httpports=$(xmlstarlet sel -t -m "//host/status[@state='up']" -m "../ports/port[state/@state='open']/service[contains(@name, 'http')]" -v "concat(../@portid, ':', (../service/@tunnel='ssl'))" -n ${defresults}.xml)
	#allopenports=$(xmlstarlet sel -t -m "//host/status[@state='up']" -m "../ports/port[state/@state='open']" -v "concat(@protocol, '/', @portid, '	', ../service/@name)" -n ${defresults}.xml)
	allopenports=$(xmlstarlet sel -t \
		-m "//host/status[@state='up']" \
		-m "../ports/port[state/@state='open']" \
		-v "concat(@protocol, '/', @portid, '	', service/@name)" -n "${defresults}.xml")
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
		indport=$(echo "$line" | cut -d '/' -f 2 | awk '{print $1}')
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
		#if [[ $line == *"microsoft-ds"* ]] || [[ $line == *"netbios-ssn"* ]] && [ $smbset == "false" ]; then
		if ( [[ $line == *"microsoft-ds"* ]] || [[ $line == *"netbios-ssn"* ]] ) && [ "$smbset" == "false" ]; then
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
	echo "PCFET0NUWVBFIGh0bWw+DQo8aHRtbCBsYW5nPSJlbiI+DQo8aGVhZD4NCjxtZXRhIGNoYXJzZXQ9IlVURi04Ij4NCjx0aXRsZT5ObWFwIFNjYW4gUmVzdWx0czwvdGl0bGU+DQo8bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9Imh0dHBzOi8vY2RuanMuY2xvdWRmbGFyZS5jb20vYWpheC9saWJzL2Jvb3RzdHJhcC81LjIuMy9jc3MvYm9vdHN0cmFwLm1pbi5jc3MiPg0KPHN0eWxlPg0KOnJvb3R7LS1iZzojMDAwOy0tZmc6I2U1ZTdlYjstLW11dGVkOiM5Y2EzYWY7LS1jYXJkOiMxMTE7LS1ib3JkZXI6IzIyMjstLWFjY2VudDojODhjMGQwOy0tZGVlcDojMDIwNjE3Oy0tZGVlcC1ib3JkZXI6IzFmMjkzNztmb250LWZhbWlseTpzeXN0ZW0tdWksLWFwcGxlLXN5c3RlbSxCbGlua01hY1N5c3RlbUZvbnQsIlNlZ29lIFVJIixzYW5zLXNlcmlmfQ0KKntib3gtc2l6aW5nOmJvcmRlci1ib3h9DQpib2R5e21hcmdpbjowO3BhZGRpbmc6MS41cmVtO2JhY2tncm91bmQ6dmFyKC0tYmcpO2NvbG9yOnZhcigtLWZnKTtmb250LXNpemU6MTJweH0NCmgxe21hcmdpbjowIDAgLjc1cmVtO2ZvbnQtc2l6ZToxLjVyZW07Y29sb3I6dmFyKC0tYWNjZW50KX0NCi5jYXJke2JhY2tncm91bmQ6dmFyKC0tY2FyZCk7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2JvcmRlci1yYWRpdXM6Ljc1cmVtO3BhZGRpbmc6MXJlbTtib3gtc2hhZG93OjAgOHB4IDI0cHggcmdiYSgwLDAsMCwuMzUpfQ0KLm1ldGEtcm93e2Rpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjtwYWRkaW5nOjRweCAwO2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcil9DQoubWV0YS1yb3c6bGFzdC1jaGlsZHtib3JkZXItYm90dG9tOjB9DQoubm1hcC1sYXlvdXR7ZGlzcGxheTpmbGV4O2dhcDoxcmVtO2FsaWduLWl0ZW1zOmZsZXgtc3RhcnR9DQoubm1hcC1sZWZ0e2ZsZXg6MCAwIDUwMHB4fQ0KLm5tYXAtcmlnaHR7ZmxleDoxO21pbi13aWR0aDowfQ0KLnNlY3Rpb24tdGl0bGV7bWFyZ2luOi41cmVtIDAgLjI1cmVtO3BhZGRpbmctYm90dG9tOi4yNXJlbTtib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2ZvbnQtd2VpZ2h0OjYwMH0NCnRhYmxle3dpZHRoOjEwMCU7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlO2ZvbnQtc2l6ZTouOHJlbX0NCnRoLHRke3BhZGRpbmc6LjM1cmVtIC40cmVtO2JvcmRlci1ib3R0b206MXB4IHNvbGlkIHZhcigtLWJvcmRlcik7dGV4dC1hbGlnbjpsZWZ0O3ZlcnRpY2FsLWFsaWduOnRvcH0NCnRoe2NvbG9yOnZhcigtLW11dGVkKTtmb250LXdlaWdodDo1MDB9DQp0ZDpudGgtY2hpbGQoMSksdGQ6bnRoLWNoaWxkKDIpe3doaXRlLXNwYWNlOm5vd3JhcH0NCnRkOm50aC1jaGlsZCgzKXt3aGl0ZS1zcGFjZTpub3JtYWw7d29yZC1icmVhazpicmVhay13b3JkO2NvbG9yOnZhcigtLW11dGVkKX0NCnRib2R5IHRyOmhvdmVye2JhY2tncm91bmQ6IzBiMTIyMH0NCi5hY2NvcmRpb24taXRlbXttYXJnaW4tYm90dG9tOi41cmVtfQ0KLmFjY29yZGlvbi1idXR0b257YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTgwZGVnLCMxNDE0MTQsIzEwMTAxMCk7Y29sb3I6dmFyKC0tZmcpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tYm9yZGVyKTtwYWRkaW5nOi42cmVtIC43NXJlbX0NCi5hY2NvcmRpb24tYnV0dG9uOmhvdmVye2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDE4MGRlZywjMWExYTFhLCMxMzEzMTMpfQ0KLyouYWNjb3JkaW9uLWJ1dHRvbjpub3QoLmNvbGxhcHNlZCl7YmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTgwZGVnLCMxYjI0MzAsIzE0MWIyNCk7Y29sb3I6dmFyKC0tYWNjZW50KX0qLw0KLmFjY29yZGlvbi1idXR0b246bm90KC5jb2xsYXBzZWQpe2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDE4MGRlZywjMmUzNDQwLCMyNTJhMzMpO2NvbG9yOiM4OGMwZDA7Ym9yZGVyLWNvbG9yOiMzYjQyNTI7fQ0KLmFjY29yZGlvbi1jb2xsYXBzZXtiYWNrZ3JvdW5kOiMwZjE0MWI7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1ib3JkZXIpO2JvcmRlci10b3A6MH0NCi5jYXJkLWJvZHl7cGFkZGluZzouNXJlbSAuNzVyZW07Y29sb3I6dmFyKC0tZmcpfQ0KLyoudHJlZXtiYWNrZ3JvdW5kOnZhcigtLWRlZXApO2JvcmRlcjoxcHggc29saWQgdmFyKC0tZGVlcC1ib3JkZXIpO2JvcmRlci1yYWRpdXM6LjVyZW07cGFkZGluZzouNXJlbTttYXJnaW4tdG9wOi40cmVtO2ZvbnQtc2l6ZTouNzVyZW19Ki8NCi50cmVle2JhY2tncm91bmQ6IzJlMzQ0MDtib3JkZXI6MXB4IHNvbGlkICMzYjQyNTI7Y29sb3I6I2U1ZTdlYjt9DQpwcmV7bWFyZ2luOjA7d2hpdGUtc3BhY2U6cHJlLXdyYXA7d29yZC1icmVhazpicmVhay13b3JkfQ0KQG1lZGlhKG1heC13aWR0aDo5MDBweCl7Lm5tYXAtbGF5b3V0e2ZsZXgtZGlyZWN0aW9uOmNvbHVtbn0ubm1hcC1sZWZ0e3dpZHRoOjEwMCV9fQ0KPC9zdHlsZT4NCjwvaGVhZD4NCjxib2R5Pg0KPGgxIGlkPSJob3N0cHJvZmlsZW5hbWUiPk5tYXAgU2NhbiBSZXN1bHRzPC9oMT4NCjxkaXYgY2xhc3M9Im5tYXAtbGF5b3V0Ij4NCgk8ZGl2IGNsYXNzPSJubWFwLWxlZnQiPg0KCQk8ZGl2IGNsYXNzPSJjYXJkIj4NCgkJCTxkaXYgaWQ9InN5c3RlbS1wcm9maWxlIj48L2Rpdj4NCgkJCTxkaXYgY2xhc3M9InNlY3Rpb24tdGl0bGUiPk9wZW4gUG9ydHM8L2Rpdj4NCgkJCTx0YWJsZT4NCgkJCTx0aGVhZD4NCgkJCQk8dHI+DQoJCQkJCTx0aD5Qb3J0PC90aD4NCgkJCQkJPHRoPlByb3RvPC90aD4NCgkJCQkJPHRoPlN2YzwvdGg+DQoJCQkJCTx0aD5Qcm9kdWN0PC90aD4NCgkJCQk8L3RyPg0KCQkJPC90aGVhZD4NCgkJCTx0Ym9keSBpZD0icG9ydC1zdW1tYXJ5LWJvZHkiPjwvdGJvZHk+DQoJCQk8L3RhYmxlPg0KCQk8L2Rpdj4NCgk8L2Rpdj4NCg0KCTxkaXYgY2xhc3M9Im5tYXAtcmlnaHQiPg0KCQk8ZGl2IGlkPSJvcGVuLXBvcnRzIiBjbGFzcz0iYWNjb3JkaW9uIj48L2Rpdj4NCgk8L2Rpdj4NCjwvZGl2Pg0KPHNjcmlwdCBzcmM9Imh0dHBzOi8vY2RuanMuY2xvdWRmbGFyZS5jb20vYWpheC9saWJzL2pxdWVyeS8zLjYuNC9qcXVlcnkubWluLmpzIj48L3NjcmlwdD4NCjxzY3JpcHQgc3JjPSJodHRwczovL2NkbmpzLmNsb3VkZmxhcmUuY29tL2FqYXgvbGlicy9ib290c3RyYXAvNS4yLjMvanMvYm9vdHN0cmFwLm1pbi5qcyI+PC9zY3JpcHQ+DQo8c2NyaXB0Pg0KY29uc3Qgbm1hcHNjYW5zPVtdOw0KJChkb2N1bWVudCkucmVhZHkoKCk9Pm5tYXBzY2Fucy5mb3JFYWNoKHY9PnJlbmRlcigkLnBhcnNlWE1MKGV2YWwodikpKSkpOw0KZnVuY3Rpb24gcmVuZGVyKHgpe2xldCBwPSIiLHM9IiIsZD0iIixwbT17fTtjb25zdCBpPSQoeCkuZmluZCgiYWRkcmVzc1thZGRydHlwZT0naXB2NCddIikuYXR0cigiYWRkciIpLGg9JCh4KS5maW5kKCJob3N0bmFtZSIpLmF0dHIoIm5hbWUiKTskKCIjaG9zdHByb2ZpbGVuYW1lIikudGV4dChgJHtpfHwiSG9zdCJ9IOKAlCBObWFwIFNjYW4gUmVzdWx0c2ApO20oIklQIixpKTtoJiZtKCJIb3N0bmFtZSIsaCk7Y29uc3Qgc3Q9KyQoeCkuZmluZCgiaG9zdCIpLmF0dHIoInN0YXJ0dGltZSIpLGV0PSskKHgpLmZpbmQoImhvc3QiKS5hdHRyKCJlbmR0aW1lIik7c3QmJmV0JiYobSgiU2NhbiBTdGFydCIsbmV3IERhdGUoMWUzKnN0KS50b0xvY2FsZVN0cmluZygpKSxtKCJSdW50aW1lIix0KGV0LXN0KSkpO20oIk9TIixvKHgpKTskKCIjc3lzdGVtLXByb2ZpbGUiKS5odG1sKHApOw0KJCh4KS5maW5kKCJwb3J0IikuZWFjaChmdW5jdGlvbigpew0KaWYoJCh0aGlzKS5maW5kKCJzdGF0ZSIpLmF0dHIoInN0YXRlIikhPT0ib3BlbiIpcmV0dXJuOw0KY29uc3QgcHQ9JCh0aGlzKS5hdHRyKCJwb3J0aWQiKSxwcj0kKHRoaXMpLmF0dHIoInByb3RvY29sIiksc3Y9JCh0aGlzKS5maW5kKCJzZXJ2aWNlIikuYXR0cigibmFtZSIpfHwiIixwZD0kKHRoaXMpLmZpbmQoInNlcnZpY2UiKS5hdHRyKCJwcm9kdWN0Iil8fHN2LHZyPSQodGhpcykuZmluZCgic2VydmljZSIpLmF0dHIoInZlcnNpb24iKXx8IiI7DQpwbVtwdF18fChwbVtwdF09e3N2Yzpzdixwcm9kOnBkLHByb3RvOltdfSk7DQpwbVtwdF0ucHJvdG8uaW5jbHVkZXMocHIpfHxwbVtwdF0ucHJvdG8ucHVzaChwcik7DQpsZXQgbzI9IiI7DQokKHRoaXMpLmZpbmQoInNjcmlwdCIpLmVhY2goZnVuY3Rpb24oKXsNCmNvbnN0IG90PSQodGhpcykuYXR0cigib3V0cHV0Iik7DQpvdCYmb3QudHJpbSgpJiYobzIrPWA8c3Ryb25nPiR7JCh0aGlzKS5hdHRyKCJpZCIpfTwvc3Ryb25nPjxkaXYgY2xhc3M9InRyZWUiPjxwcmU+JHtvdH08L3ByZT48L2Rpdj5gKTsNCn0pOw0KaWYoIW8yLnRyaW0oKSlyZXR1cm47DQpjb25zdCBpZD1gcC0ke3B0fS0ke3ByfWA7DQpkKz1gPGRpdiBjbGFzcz0iYWNjb3JkaW9uLWl0ZW0gY2FyZCI+PGJ1dHRvbiBjbGFzcz0iYWNjb3JkaW9uLWJ1dHRvbiBjb2xsYXBzZWQiIGRhdGEtYnMtdG9nZ2xlPSJjb2xsYXBzZSIgZGF0YS1icy10YXJnZXQ9IiMke2lkfSI+PGRpdiBjbGFzcz0iZC1mbGV4IGp1c3RpZnktY29udGVudC1iZXR3ZWVuIHctMTAwIj48c3Ryb25nPiR7cHR9LyR7cHJ9IOKAlCAke3N2fTwvc3Ryb25nPjxzcGFuIGNsYXNzPSJ0ZXh0LW11dGVkIj4ke3BkfSAke3ZyfTwvc3Bhbj48L2Rpdj48L2J1dHRvbj48ZGl2IGlkPSIke2lkfSIgY2xhc3M9ImFjY29yZGlvbi1jb2xsYXBzZSBjb2xsYXBzZSI+PGRpdiBjbGFzcz0iY2FyZC1ib2R5Ij4ke28yfTwvZGl2PjwvZGl2PjwvZGl2PmA7DQp9KTsNCk9iamVjdC5rZXlzKHBtKS5zb3J0KChhLGIpPT5hLWIpLmZvckVhY2gocHQ9PnsNCnMrPWA8dHI+PHRkPiR7cHR9PC90ZD48dGQ+JHtwbVtwdF0ucHJvdG8uam9pbigiLCAiKX08L3RkPjx0ZD4ke3BtW3B0XS5zdmN9PC90ZD48dGQ+JHtwbVtwdF0ucHJvZH08L3RkPjwvdHI+YDsNCn0pOw0KJCgiI3BvcnQtc3VtbWFyeS1ib2R5IikuaHRtbChzKTsNCiQoIiNvcGVuLXBvcnRzIikuaHRtbChkKTsNCmZ1bmN0aW9uIG0oayx2KXt2JiYocCs9YDxkaXYgY2xhc3M9Im1ldGEtcm93Ij48c3Ryb25nPiR7a308L3N0cm9uZz48c3Bhbj4ke3Z9PC9zcGFuPjwvZGl2PmApfQ0KfQ0KZnVuY3Rpb24gdChzKXtjb25zdCBoPU1hdGguZmxvb3Iocy8zNjAwKSxtPU1hdGguZmxvb3IocyUzNjAwLzYwKTtyZXR1cm5gJHtofWggJHttfW0gJHtzJTYwfXNgfQ0KZnVuY3Rpb24gbyh4KXtsZXQgYj1udWxsOyQoeCkuZmluZCgib3NtYXRjaCIpLmVhY2goZnVuY3Rpb24oKXtjb25zdCBhPSskKHRoaXMpLmF0dHIoImFjY3VyYWN5IiksZj0kKHRoaXMpLmZpbmQoIm9zY2xhc3MiKS5hdHRyKCJvc2ZhbWlseSIpOyghYnx8YT5iLmEpJiYoYj17YSxmfSl9KTtyZXR1cm4gYj9iLmY6IlVua25vd24ifQ0KPC9zY3JpcHQ+DQo8L2JvZHk+DQo8L2h0bWw+DQoNCg" | base64 -d > ${vulresults}.html
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
	chown -R "${SUDO_USER}":"${SUDO_USER}" "${workspace}"
	
}


if [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
	# Check if the input is an IP address
	ip="$1"
	if [ "$1" != "${PWD##*/}" ]; then
		create_workspace "$1"
		workspace=$(pwd)/${ip}
	else
		echo "Using Current Directory as Workspace"
		workspace=${PWD##*/}
	fi
	scantarget "${ip}" "${workspace}"
elif [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; then
	# Check if the input is a CIDR range
	ips=$(nmap -sn -n -iL <(echo $1) | grep "Nmap scan report for" | awk '{print $5}')
	for ip in $ips; do
		create_workspace "${ip}"
		workspace=$(pwd)/${ip}
		scantarget "${ip}" "${workspace}"
	done
elif [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}-[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
	# Check if the input is an IP range
	start_ip=$(echo $1 | awk -F- '{print $1}')
	end_ip=$(echo $1 | awk -F- '{print $2}')
	ips=$(nmap -sn -n --range "$start_ip"-"$end_ip" | grep "Nmap scan report for" | awk '{print $5}')
	for ip in $ips; do
		create_workspace "${ip}"
		workspace=$(pwd)/${ip}
		scantarget "${ip}" "${workspace}"
	done
elif [ -f "$1" ]; then
	# Check if the input is a filename with an IP list
	while read -r line; do
		if [[ $line =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
			pretty '+' "Processing: ${line}"
			ip=${line}
			create_workspace "${ip}"
			workspace=$(pwd)/${ip}
			scantarget "${ip}" "${workspace}"
		fi
	done < "$1"
elif host "$1" &>/dev/null || getent hosts "$1" &>/dev/null; then
	# If none of the above, try a DNS lookup for the string argument (silently)
	# Using 'host' command to resolve the DNS; adjust if you prefer 'dig' or 'nslookup'
	resolved_ip=$(host "$1" 2>/dev/null | awk '/has address/ { print $4; exit }')
	# If host didn’t work, fall back to getent (which checks /etc/hosts)
	if [ -z "$resolved_ip" ]; then
		resolved_ip=$(getent hosts "$1" | awk '{ print $1; exit }')
	fi
	if [ -n "$resolved_ip" ]; then
		# Optionally, uncomment next line to display resolution details.
		# echo "Resolved $1 to $resolved_ip"
		create_workspace "${resolved_ip}"
		workspace=$(pwd)/"$1"
		scantarget "${resolved_ip}" "${workspace}"
	else
		echo "Lookup failed for $1"
		exit 1
	fi
else
	# Potential issue: the variable 'ip' might not be defined here.
	if echo ${PWD##*/} | grep -oP $regpat >/dev/null; then
		echo "Using Directory as argument"
		# 'ip' is not set; you may want to adjust this
		workspace=$(pwd)
		scantarget "${PWD##*/}" "${workspace}"
	else
		echo "fail... add an argument"
		echo "Usage: $0 <ip_address|cidr_range|ip_range|filename|hostname>"
		exit 1
	fi
fi
