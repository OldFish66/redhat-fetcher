#!/usr/bin/python3
#This script constructs the data into json format, If necessary, coule be modified into other formats.

import aiohttp
import asyncio
import json
import re
import datetime

global resList
resList=[]
index=0
global kernel_list
global problem_list
problem_list=[]

class AsnycGrab(object):

    def __init__(self, url_list, max_threads):
        self.urls = cve_list

        self.max_threads = max_threads
        self.headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "keep-alive",
            "Host": "access.redhat.com",
            "Origin": "https://access.redhat.com",
            "Referer": "https://access.redhat.com/security/security-updates/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36"
        }

    async def main(self,url):

        async def fetch(session, url):
            async with session.get(url) as response:
                return await response.json()

        async with aiohttp.ClientSession(headers=self.headers) as session:
            json_body = await fetch(session, url)
            

            cve_id=json_body['name']
            redhat_errata=''
            redhat_buster_status=''
            upstream_fixed_version=''
            package=''
            status=''
            exact_status=''
            
            #If there are multiple packages, match multiple states. only one final state is reserved according to the priority of the states.
            priority_level=['Not affected','Fixed','Fix deferred','Fixed deferred','Will not fix','Out of support scope','Under investigation','Affected']
            
            if ('affected_release' in json_body):
                obj=json_body['affected_release']
                for i in range(len(obj)):
                    if "Red Hat Enterprise Linux 7" == obj[i]['product_name']:
                        redhat_errata= 'Red Hat Enterprise Linux 7'
                        if 'package' in obj[i]:
                            pre_package=obj[i]['package'].split(':',1)[0]
                            upstream_fixed_version=obj[i]['package']
                            #upstream_fixed_version=re.sub('.:','',upstream_fixed_version,1)

                        else:
                            pre_package=''
                            upstream_fixed_version=''
                        if pre_package.find('-') > -1:
                            pre_package=pre_package[:pre_package.rfind('-')]
                        if package=='':
                            package = pre_package
                        elif len(package)>200:
                            package=package
                        else:
                            package=package+", "+pre_package
                        redhat_buster_status="Fixed"

            if ('package_state' in json_body):
                obj=json_body['package_state']
                for i in range(len(obj)):
                    if "Red Hat Enterprise Linux 7" == obj[i]['product_name']:
                        redhat_errata= 'Red Hat Enterprise Linux 7'

                        if package=='':
                            package = obj[i]['package_name']
                        elif len(package)>200:
                            package=package
                        else:
                            package=package+", "+obj[i]['package_name']
                        package=package.replace('/',':')

                        if redhat_buster_status=='':
                            redhat_buster_status=obj[i]['fix_state']
                        else:
                            old=priority_level.index(redhat_buster_status)
                            new=priority_level.index(obj[i]['fix_state'])
                            if new > old:
                                redhat_buster_status=obj[i]['fix_state']

            if upstream_fixed_version is None :
                if ('upstream_fix' in json_body):
                    upstream_fixed_version = json_body['upstream_fix']

            if redhat_errata == "" or package=="":
                return
            cve_description=json_body['details'][0].strip().replace("'","").replace("&","").replace("\\","").replace("\"","")
            if len(cve_description) >= 10000:
                cve_description=cve_description[:10000]
            cvss='3'
            if 'cvss3' in json_body:
                score=json_body['cvss3']['cvss3_base_score']
            else:
                score=0
            published_at=json_body['public_date'][:10]
            if float(score)>9.0:
                ended_at=str(datetime.datetime.strptime(published_at,'%Y-%m-%d')+datetime.timedelta(days=7))[:10]
            elif float(score)>7.0:
                ended_at=str(datetime.datetime.strptime(published_at,'%Y-%m-%d')+datetime.timedelta(days=10))[:10]
            else:
                ended_at=str(datetime.datetime.strptime(published_at,'%Y-%m-%d')+datetime.timedelta(days=30))[:10]

            if redhat_buster_status == "Not affected":
                status="postpone"
                exact_status="no effect"

            cveinfo={}
            cveinfo["cve_id"]=cve_id
            cveinfo["package"]=package
            cveinfo["cve_description"]=cve_description
            cveinfo["redhat_errata"]=redhat_errata
            cveinfo["redhat_buster_status"]=redhat_buster_status
            cveinfo["status"]=status
            cveinfo["exact_status"]=exact_status
            cveinfo["upstream_fixed_version"]=upstream_fixed_version
            cveinfo["cvss"]=cvss
            cveinfo["score"]=score
            cveinfo["published_at"]=published_at
            cveinfo["ended_at"]=ended_at
            resList.append(cveinfo)
            logging.basicConfig(level=logging.DEBUG)
            logging.info(f'  | {url}')


    async def handle_tasks(self, task_id, work_queue):
        while not work_queue.empty():
            current_url = await work_queue.get()
            url="https://access.redhat.com/hydra/rest/securitydata/cve/"+current_url+".json"
            try:
                task_status = await self.main(url)
            except Exception as e:
                problem_list.append(current_url+"\n")
                logging.exception('Error for {}'.format(current_url), exc_info=True)

    def eventloop(self):
        q = asyncio.Queue()
        [q.put_nowait(url.strip()) for url in self.urls]
        loop = asyncio.get_event_loop()
        tasks = [self.handle_tasks(task_id, q, ) for task_id in range(max_threads)]
        loop.run_until_complete(asyncio.wait(tasks))
        loop.close()
        with open('cve-redhat-7.json','w') as f:
            json_info=json.dumps(resList)
            f.write(json_info)
            f.close()
            print("redhat enterprise linux 7 fetch successful！")



if __name__ == '__main__':
    with open("cve.list", "r") as f:
        cve_list = f.readlines()

    starttime=datetime.datetime.now()
    async_example = AsnycGrab(cve_list, 100)   #the value of max thread shouldn't too high
    async_example.eventloop()
    endtime=datetime.datetime.now()
    print("Program was executed at:",starttime)
    print("Program was executed for ",(endtime - starttime).seconds," seconds")
