# coding=utf-8
import random
import requests
import re
import urllib
import time
import random
import pandas as pd
import csv
import requests
import time


from bs4 import BeautifulSoup
from html2text import html2text

requests.adapters.DEFAULT_RETRIES = 10 # 增加重连次数
ls = requests.session()
ls.keep_alive = False # 关闭多余连接

ua_list = [
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36",
    "Dalvik/1.6.0 (Linux; U; Android 4.2.1; 2013022 MIUI/JHACNBL30.0)",
    "Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10"

]


# count=230 535 799
# csvFile = open("sfnew.csv", 'w', newline='',encoding='utf-8')
storepath='unavailablenew.txt'
csvFile = open("sf6.csv", 'w',encoding='utf-8', newline='')
writer = csv.writer(csvFile)
writer.writerow(('BUGTRAQ_ID' ,'TITLE','CVES','EXPLOIT','REMOTE','LOCAL','PUBLISH','UPDATED','PRODUCTS','CLASS','url','DISCUSSION'))
for i in range(3000, 3100):
    count=i*30
    print(count)
    bug_url = "https://www.securityfocus.com/cgi-bin/index.cgi?o="+str(count)+"&l=30&c=12&op=display_list&vendor=&version&title=&CVE="
    print(bug_url)
    # 对每页直接正则将url全部匹配出来之后开始循环请求。
    user_agent = random.choice(ua_list)
    headers = {"User-Agent": user_agent}
    # print("222")
    #
    page_text=[]
    taglist = []
    while(1):

        try:
            response = ls.get(bug_url,headers=headers,timeout=(50,310))
            page = response.text

            soup = BeautifulSoup(page, 'html.parser')  # 第一层过滤

            taglist = soup.find_all('div', attrs={'id':'article_list'})
            # print(taglist)
            # print(taglist)
            #
            if (len(taglist) == 0):
                time.sleep(0.4 + random.random() / 5)

                print(taglist)

            else:
                pattern = re.compile('<a href="/.*?">', re.S)
                page_text = re.findall(pattern, str(taglist[0]))
                print(len(page_text))
                break
        except:
            time.sleep(0.4 + random.random() / 5)
            print("failed")


    # 去除重复URL。
    page_list = list(page_text)
    page_url=list(set(page_list))
    # print(page_url)
    print(page_url)
    length = len(page_url)
    url=[]

    urllen = len(url)

    time.sleep(0.1+random.random()/10)
    for h in range(len(page_url)):
        listurl = re.split('href="', page_url[h])
        listurl2 = re.split('"', listurl[1])
        nexturl = listurl2[0]
        finalurl = "https://www.securityfocus.com" + nexturl
        print(finalurl)
        finalurl1=finalurl+"/info"
        finalurl2=finalurl+"/discuss"
        finalurl3=finalurl+"/exploit"
        finalurl4=finalurl+"/solution"
        finalurl5=finalurl+"/references"
        user_agent = random.choice(ua_list)
        headers = {"User-Agent": user_agent}
        # htmls = ls.get(finalurl1,headers=headers)
        remote=[]
        flag=0
        time_start = time.time()
        while(len(remote)==0):

            try:
                htmls = ls.get(finalurl1, headers=headers,timeout=9)
                htmls.encoding = htmls.apparent_encoding
                s = []
                soup = BeautifulSoup(htmls.text, 'html.parser')
                # print(type(htmls.text))
                infotaglist = []
                infotaglist = soup.find_all('div', attrs={'id': 'vulnerability'})
                title = soup.find('span', attrs={'class': 'title'})
                title = html2text(str(title))
                title=title.replace("\n"," ")
                # print(title, end='\n\n\n')

                s = html2text(str(infotaglist))
                h = s.replace("|", "")
                # print(h)

                pattern1 = re.compile('.*' + "Remote:" + '.*')
                remote = re.findall(pattern1, h)
                time_end = time.time()
                waste_time = time_end - time_start
                if (waste_time > 130):
                    with open(storepath, "a", encoding="utf-8") as cf:
                        cf.write(finalurl + "\n")
                    flag = 1
                    break
                if (len(remote) == 0):
                    time.sleep(0.2 + random.random() / 5)
            except:
                time.sleep(0.2 + random.random() / 5)
        if(flag==1):
            continue
        # print(remote)
        remote = remote[0].split(":")
        r = remote[1]
        # print(remote[1])
        pattern2 = re.compile('.*' + "Local:" + '.*')
        l = re.findall(pattern2, h)
        l = l[0].split(":")
        local = l[1]
        # print(l)

        pattern3 = re.compile('.*' + "Bugtraq ID: " + '.*')
        Bug = re.findall(pattern3, h)
        Bug = Bug[0].split(":")
        Bugtraq = Bug[1]

        soupsub = BeautifulSoup(str(infotaglist[0]), 'html.parser')
        CVE = soupsub.find('tr', attrs={'valign': 'top'})
        # print(CVE)
        CVE = html2text(str(CVE))
        CVE = CVE.replace("|", "")
        CVE = CVE.replace("\n", "")
        CVE = CVE.split("  ")
        CVE = CVE[1:-1]
        # print(CVE)
        cve = str(CVE)
        # print(cve)



        pattern5 = re.compile('.*' + "Published: " + '.*')
        Pub = re.findall(pattern5, h)
        Pub = Pub[0].split(":")
        pubish = Pub[1]
        pubish = pubish.split(" ")
        pubish = pubish[:-1]
        pubish = " ".join(pubish)

        pattern6 = re.compile('.*' + "Updated: " + '.*')
        Up = re.findall(pattern6, h)
        Up = Up[0].split(":")
        update = Up[1]
        update = update.split(" ")
        update = update[:-1]
        update = " ".join(update)
        # print(update)

        pattern7 = re.compile('.*' + "Class: " + '.*')
        cl = re.findall(pattern7, h)
        cl = cl[0].split(":")
        Class = cl[1]

        pattern8 = re.compile("Vulnerable:" + "(?:.|\n)*")
        Vuln = re.findall(pattern8, h)
        Vuln = Vuln[0].split(":")
        vuln = Vuln[1]
        vulnability = vuln.replace("\n", "  ")
        vulnability = vulnability.split("  ")
        vulnability = vulnability[:-1]
        vulnabilitylast = [x for x in vulnability if x != '']
        time.sleep(0.1+random.random()/20)
        dis = str([12])
        while(len(dis)==4):
            try:
                # htmls = ls.get(finalurl2,headers=headers)
                htmls= ls.get(finalurl2,headers=headers,timeout=9)
                htmls.encoding = htmls.apparent_encoding

                soup = BeautifulSoup(htmls.text, 'html.parser')
                # print(htmls.text)

                infotaglist = []
                infotaglist = soup.find_all('div', attrs={'id': 'vulnerability'})
                # print(infotaglist)
                time_end = time.time()
                waste_time = time_end - time_start
                if (waste_time > 200):
                    with open(storepath, "a", encoding="utf-8") as cf:
                        cf.write(finalurl + "\n")
                    flag = 1
                    break
                dis = html2text(str(infotaglist))
                if (len(dis) == 4):
                    time.sleep(0.3 + random.random() / 10)
            except:
                time.sleep(0.3 + random.random() / 10)
        if(flag==1):
            continue
        dis = dis.replace("\n", " ")
        # print(s)
        dis = dis.replace("   ", "\n")
        # print(s)
        dis = dis.split("\n")
        # print(dis)
        dis = dis[1:]
        dis1 = "".join(dis)
        time.sleep(0.1 + random.random() / 10)
        exp = str([12])
        while(len(exp)==4):
            htmls = ls.get(finalurl3,headers=headers)
            htmls.encoding = htmls.apparent_encoding
            exp = []
            soup = BeautifulSoup(htmls.text, 'html.parser')
            # print(htmls.text)
            infotaglist = []
            time_end = time.time()
            waste_time = time_end - time_start
            if (waste_time > 260):
                with open(storepath, "a", encoding="utf-8") as cf:
                    cf.write(finalurl + "\n")
                flag = 1
                break
            infotaglist = soup.find_all('div', attrs={'id': 'vulnerability'})
            exp = html2text(str(infotaglist))
            if (len(exp) == 4):
                time.sleep(0.2 + random.random() / 10)
        if(flag==1):
            continue
        exp = exp.replace("\n", " ")

        exp = exp.replace("   ", "\n")

        exp = exp.split("\n")

        exp = exp[1:]
        exp1 = "".join(exp)

        writer.writerow((Bugtraq, title, cve,exp1, r, local, pubish, update, vulnabilitylast, Class,finalurl,dis1))

        time.sleep(0.7+random.random()/2)



