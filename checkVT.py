#!/usr/bin/env python
# -*- coding:utf8 -*-

# Description: calculate and check Hashes of multi-files on VirusTotal.com
# Author: Avfisher
# Email: security_alert@126.com
# Date: 2015.06.30

import urllib2
import re
import json
import sys
import smtplib
import os
import time
import ssl
import hashlib
import argparse
import getopt 

# Ignore SSL error when accessing a HTTPS website
# ssl._create_default_https_context = ssl._create_unverified_context

reload(sys)
sys.setdefaultencoding( "utf-8" )

from email.mime.text import MIMEText
from bs4 import BeautifulSoup

def sha256(filename):
    f = open(filename, 'rb')
    sh = hashlib.sha256()
    sh.update(f.read())
    fhash = sh.hexdigest()+","+filename
    now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    print "["+str(now)+"]: "+sh.hexdigest()
    f.close()
    return fhash

def get_all_file(path):
    file_list = []
    if path is None:
        raise Exception("folder_path is None")
    for dirpath, dirnames, filenames in os.walk(path):
        for name in filenames:
            file_list.append(dirpath + '\\' + name)
    return file_list

def get_file_hash(path):

    f = open('hash_sha256.txt','w')
    hashlist=[]
    list1=get_all_file(path)
    for i in range(0,len(list1)):
        if (os.path.isfile(list1[i]) == True ):
            fhash = sha256(list1[i])
            hashlist.append(fhash)
            f.write(fhash+'\n')
    f.close
    return hashlist

def errorlog(log):
    f=open('errorlog.txt','a')
    now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    f.write(now+': '+log+'\n')
    f.close

def getUrlRespHtml(url):
    try:
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
    except Exception:
        respHtml = ""
    return respHtml

def getResultFromVirusTotal(html,url, file_hash,file_path):  
    result=""
    try:
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        soup = BeautifulSoup(html)
        html_doc=soup.find_all('tr')
        if 'Detection ratio' in html_doc[2].find_all('td')[0].find_all(text=True)[0]:
            ratio=html_doc[2].find_all('td')[1].find_all(text=True)[0].strip()
            result=file_hash+","+ratio+","+url+","+file_path
            print "["+now+"]: "+file_hash+","+ratio
        elif 'Detection ratio' in html_doc[1].find_all('td')[0].find_all(text=True)[0]:
            ratio=html_doc[1].find_all('td')[1].find_all(text=True)[0].strip()
            result=file_hash+","+ratio+","+url+","+file_path
            print "["+now+"]: "+file_hash+","+ratio
        else:
            result=file_hash+",File not found,"+url+","+file_path
            print "["+now+"]: "+file_hash+",File not found"   
    except Exception:
        result=file_hash+",File not found,"+url+","+file_path
        print "["+now+"]: "+file_hash+",File not found"
    return result

def virustotal(file_hash, file_path):
    url='https://www.virustotal.com/en/file/'+file_hash+'/analysis/'
    html = getUrlRespHtml(url)
    #print "Done: Html response was grapped with success!"
    html=html.decode('utf-8','ignore')
    res=getResultFromVirusTotal(html, url, file_hash, file_path)
    return res

def calcHash(path):
    now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    if os.path.exists(path):
        print "["+now+"]: "+"Hash value calculation for file(s) is starting..."
        file_hash = get_file_hash(path)
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        print "["+now+"]: "+"Hash value calculation for file(s) is done\n"
        print "Analysis Result(SHA256):"
        print "Input Path: "+path
        print "Output File: "+os.path.dirname(os.path.realpath(__file__))+"\hash_sha256.txt"
    else:
        print "["+now+"]: "+"Error! The path is not existed"
        print "\n[!] to see help message of options run with '-h'"

def subVT(path):
    if os.path.exists(path):
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        print "["+now+"]: "+"VT analysis for hash value(s) is starting..."
        f = open('result_VT.txt','w') # Open log file
        file_hash = open(path,'r')
        for eachhash in file_hash:
            file_hash = eachhash.split(',')[0]
            file_path = eachhash.split(',')[1]
            result = virustotal(file_hash,file_path)
            f.write(result)
        f.close()
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        print "["+now+"]: "+"VT analysis for hash value(s) is done\n"
        print "Analysis Result(VT):"
        print "Input File: "+path
        print "Output File: "+os.path.dirname(os.path.realpath(__file__))+"\\result_VT.txt"
    else:
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        print "["+now+"]: "+"Error! The file is not existed"
        print "\n[!] to see help message of options run with '-h'"

def myhelp():
    print "Usage: checkVT.py [options]\n"
    print "Options:"
    print "  -h, --help                           Show basic help message and exit"
    print "  -s path, --sha256=path               Show hash(SHA256) values for file(s) to be analyzed"
    print "  -v file, --vt=file                   Show VT results for hash value(s) to be analyzed"
    print "  -c path, --checkVT=path              Show VT results for file(s) to be analyzed"
    print "\nExamples:"
    print "  checkVT.py -s c:\windows"
    print "  checkVT.py -v c:\users\\administrator\desktop\hash_sha256.txt"
    print "  checkVT.py -c c:\windows"
    print "\n[!] to see help message of options run with '-h'"

def checkVT(path):
    if os.path.exists(path):
        f = open('result_VT.txt','w') # Open log file
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        print "["+now+"]: "+"Hash value calculation for file(s) is starting..."
        file_hash = get_file_hash(path)
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        print "["+now+"]: "+"Hash value calculation for file(s) is done\n"
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        print "["+now+"]: "+"VT analysis for file(s) is starting..."
        for eachhash in file_hash:
            file_hash = eachhash.split(',')[0]
            file_path = eachhash.split(',')[1]
            result = virustotal(file_hash,file_path)+"\n"
            f.write(result)
        f.close()
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        print "["+now+"]: "+"VT analysis for file(s) is done\n"
        print "Analysis Result:"
        print "Input Path: "+path
        print "Output File(SHA256): "+os.path.dirname(os.path.realpath(__file__))+"\hash_sha256.txt"
        print "Output File(VT): "+os.path.dirname(os.path.realpath(__file__))+"\\result_VT.txt"
    else:
        now = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        print "["+now+"]: "+"Error! The path is not existed"
        print "\n[!] to see help message of options run with '-h'"


def main():
    try:
        options,args = getopt.getopt(sys.argv[1:],"hs:v:c:",["help","sha256=","vt=","checkVT="])
    except getopt.GetoptError:
        sys.exit()

    for name,value in options:
        if name in ("-h","--help"):
            myhelp()
        if name in ("-s","--sha256"):
            calcHash(value)
        if name in ("-v","--vt"):
            subVT(value)
        if name in ("-c","--checkVT"):
            checkVT(value)

if __name__ == "__main__":
    main()
