import requests
import json

def download():
    url = 'https://access.redhat.com/labs/securitydataapi/cve.json?per_page=100000'
    req = requests.get(url)
    filename = "cve.json"
    if req.status_code != 200:
        print('下载异常')
        return
    try:
        with open(filename, 'wb') as f:
            f.write(req.content)
            print('下载成功')
    except Exception as e:
        print(e)

def json_read():
    s=[]
    with open("cve.json",'r') as f:
        jsonData=json.load(f)
    for row in jsonData:
        s.append(row['CVE']+"\n")
    print("json的行数为： ",len(s))
    with open("cve.list",'w+') as d:
        d.writelines(s)
    print("CVE已输出至 cve.list 中"）
    d.close()

if __name__ == '__main__':
    download()
    json_read()
