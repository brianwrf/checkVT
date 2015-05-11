#!/usr/bin/env python
# -*- coding:utf8 -*-

# Description: check Hashes in VirusTotal.com
# Author: avfisher
# Date: 2015.05.11

import urllib2
import re
import json
import sys
import smtplib
import os
import time
import ssl
import hashlib

# Ignore SSL error when accessing a HTTPS website
ssl._create_default_https_context = ssl._create_unverified_context

reload(sys)
sys.setdefaultencoding( "utf-8" )

from bs4 import BeautifulSoup

def sha256(filename):
    f = open(filename, 'rb')
    sh = hashlib.sha256()
    sh.update(f.read())
    fhash = sh.hexdigest()+","+filename
    f.close()
    return fhash

def get_all_file(path):
    file_list = []
    #print path
    if path is None:
        raise Exception("floder_path is None")
    for dirpath, dirnames, filenames in os.walk(path):
        for name in filenames:
            file_list.append(dirpath + '\\' + name)
    return file_list

def get_file_hash(path):

    #f = open('hash_sha256.txt','w')
    hashlist=[]
    list1=get_all_file(path)
    #print list1
    for i in range(0,len(list1)):
        if (os.path.isfile(list1[i]) == True ):
            fhash = sha256(list1[i])
            hashlist.append(fhash)
            #f.write(fhash+'\n')
    #f.close
    return hashlist

def errorlog(log):
    f=open('errorlog.txt','a')
    now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    f.write(now+': '+log+'\n')
    f.close

def getUrlRespHtml(url):
    heads = {'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 
             'Accept-Charset':'GB2312,utf-8;q=0.7,*;q=0.7', 
             'Accept-Language':'zh-cn,zh;q=0.5', 
             'Cache-Control':'max-age=0', 
             'Connection':'keep-alive', 
             'Keep-Alive':'115',
             'User-Agent':'Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.14) Gecko/20110221 Ubuntu/10.10 (maverick) Firefox/3.6.14'}
 
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
    urllib2.install_opener(opener) 
    req = urllib2.Request(url)
    opener.addheaders = heads.items()
    respHtml = opener.open(req).read()
    return respHtml

def getResultFromVirusTotal(html,url, file_hash,file_path):  
    soup = BeautifulSoup(html)
    html_doc=soup.find_all('tr')
    #if html_doc is None:
    #    print 'Error: Nothing can be grapped!'
    #else:
    #    print 'Done: News info was grapped with success!'
    result=""
    try:
        ratio=html_doc[2].find_all('td')[1].find_all(text=True)[0].strip()
        result=file_hash+","+file_path+","+ratio+","+url+"\n"
        print file_hash+","+ratio
    except Exception:
        result=file_hash+","+file_path+",File not found,"+url+"\n"
        print file_hash+",File not found"
    return result

def virustotal(file_hash, file_path):
    url='https://www.virustotal.com/en/file/'+file_hash+'/analysis/'
    html = getUrlRespHtml(url)
    #print "Done: Html response was grapped with success!"
    html=html.decode('utf-8','ignore')
    res=getResultFromVirusTotal(html, url, file_hash, file_path)
    return res

def main():
    f = open('result_VT.txt','w') # Open log file
    # set up file path to scan on VirusTotal
    path = r'C:\Users\123\Desktop\alertMon'
    file_hash = get_file_hash(path)
    #print file_hash
    for eachhash in file_hash:
        file_hash = eachhash.split(',')[0]
        file_path = eachhash.split(',')[1]
        result = virustotal(file_hash,file_path)
        f.write(result)
    f.close()
    
if __name__ == "__main__":
    main()
