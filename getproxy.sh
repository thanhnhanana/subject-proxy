#!/bin/bash
# Create Date Wed Sep  4 04:56:31 UTC 2024
# Partner Nguyen Ha My
# Charity!, do not sell it in any form
options=$1
case $options in
--help)
	echo "
Usage: getproxy --get <timeout>
  --get | Get the free proxies scraper list
  --download-filter | Download free proxy filtering tool using nodejs
"
;;
--download-filter)
curl -o 'scan.js' 'https://raw.githubusercontent.com/ngthnhan212/leak_host/main/scan.js'
echo "Successfully"
;;
--get)
	out=$2
	if [[ "$out" =~ ^[0-9]+$ ]]
	then
		:
	else
		echo "Timeout is an int, not a string!"
		exit
	fi
	if [[ "$out" -gt 10000 ]]
	then
		echo "The smallest timeout is 1000 and the largest is 10000!"
		exit
	fi
	if [[ "$out" -lt 1000 ]]
	then
		echo "The smallest timeout is 1000 and the largest is 10000!"
		exit
	fi
	curl -L -o 'proxy_scraper.txt' "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=$out&country=all&ssl=all&anonymity=all" > /dev/null 2>&1
	echo "Successfully obtained proxy scraper!"
	echo "Timeout: $out"
;;
*)
	echo "getproxy: invalid options $options
try 'getproxy --help' for more information"
esac
