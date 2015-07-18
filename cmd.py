#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
	This script is meant to scrape url, name and location of linkedin users. This script
	is capable enough to dodge linkedin security and send more than half million(tested no
	 can go further more) requests continously and scrape the data.

	1. user needs to install tor first on their pc using "sudo apt-get install tor".
	2. user needs to install used library in the script.
	3. user has two options.
		a)you can save scrapped data in database or 
		b)you can save query in file. 
	and later execute it in MySql database (this script generates the query for you).
	4. I have used two library for getting response one is requests and one is urlib2. 
	(requests is more trusted one as urlib2 has some bugs internally).
	5. If this script crashes you can start from the same point where you stopped by 
	copying the content of copy.txt(available in folder) to paste.txt and change the 
	value of flag in dig function to 1(Initially flag will be 0).
	6. To run this code use commands in run.txt. 
"""


import requests
import re
import codecs
from bs4 import BeautifulSoup
import httplib
import sys
from contextlib import closing
import colorama  # $ pip install colorama
import docopt  # $ pip install docopt
import socks  # $ pip install PySocks
import stem.process  # $ pip install stem
from sockshandler import SocksiPyHandler  # see pysocks repository
from stem.util import term

"""For binding it to the tor port"""
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, '127.0.0.1', 9051, True)
socket.socket = socks.socksocket

import urllib2


"""Database connection"""
"""If you want to store data in database uncomment the following line of code and create
a database called linkedin"""

"""con = mdb.connect('localhost', 'root', 'ambuj', 'linkedin');
cur = con.cursor()
try:
	cur.execute("CREATE TABLE users (url VARCHAR(500) PRIMARY KEY , Name VARCHAR(500), Location VARCHAR(500))")
except:
	pass"""



"""Global Variables"""
root_url=str(sys.argv[1])
depth=0
restore_array={}



"""This identifies user profile"""
def link_contains_public_profile_url(res):
	soup = BeautifulSoup(res.decode('utf-8'))
	for i in soup.find_all('a'):
		x=i.get('href')
		#print(x)
		try:
			if(re.match(str(sys.argv[2]),str(x))):
				print(x)
				return True
		except:
			pass
	else:
		print('returning false')
		return False


"""Parse the webpage and returns list of url"""
def parse_and_return_list(url,res):
	url_list=[]
	soup = BeautifulSoup(res.decode('utf-8'))
	for i in soup.find_all('a'):
		x=i.get('href')
		if(re.match(url[:-1],str(x))):
			url_list.append(x)
	return url_list

"""Ping with urllib2"""
def ping(url):
	try:
		res = urllib2.urlopen(str(url)).read()
  	except:
  		res = 'Error : Unknown error'
  	return res

"""Ping with urllib2 for getting user profile"""
def public_ping(url):
	try:
		res = urllib2.urlopen(str(url)).read()
  	except:
  		res = 'Error : Unknown error'
  	return res
    	


"""Ping to the url and return response with requests"""
"""def ping(url):
	try:
		headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.130 Safari/537.36'}
		s = requests.session()
		r = s.get(url,headers=headers,verify=False)
		res=r.content
		s.close()
	except requests.exceptions.RequestException as e:
		res = 'Error : ' + str(e)
	except requests.exceptions.ConnectionError as e:
		res = 'Error : ' + str(e)
	except requests.exceptions.HTTPError as e:
		res = 'Error : ' + str(e)
	except requests.exceptions.URLRequired as e:
		res = 'Error : ' + str(e)
	except requests.exceptions.TooManyRedirects as e:
		res = 'Error : ' + str(e)
	except:
		res = 'Error : Unknown error'
	return res"""


"""This returns user profile urls"""
def parse_and_return_publicurl(res):
	public_url_list=[]
	soup = BeautifulSoup(res.decode('utf-8'))
	for i in soup.find_all('a'):
		x=i.get('href')
		try:
			if(re.match(str(sys.argv[2]),str(x))):
				public_url_list.append(x)
		except:
			pass
	return public_url_list

""""To Ping Public Urls"""
"""def public_ping(url):
	try:
		headers = {'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.130 Safari/537.36'}
		s = requests.session()
		r = s.get(url,headers=headers,verify=False)
		res=r.content
		s.close()
	except requests.exceptions.RequestException as e:
		res = 'Error : ' + str(e)
	except requests.exceptions.ConnectionError as e:
		res = 'Error : ' + str(e)
	except requests.exceptions.HTTPError as e:
		res = 'Error : ' + str(e)
	except requests.exceptions.URLRequired as e:
		res = 'Error : ' + str(e)
	except requests.exceptions.TooManyRedirects as e:
		res = 'Error : ' + str(e)
	except:
		res = 'Error : Unknown error'
	return res"""

"""Method for cleaning data"""
def clean(data):
	#print('Entering clean')
	original_length=float(len(data))
	x= re.sub(r'[^a-zA-Z\s]+','',data).strip()
	modified_length=float(len(x))
	y=(modified_length/original_length)*100
	if(re.match('Weird',str(x)) or y<70):
		return 'discard'
	else:
		return x

"""This method is for writting state in to a file"""
def write_file(restore_array):
	state_file = open('copy.txt','w')
	state_file.write('0|'+str(sys.argv[1])+'|0\n')
	for keys,values in restore_array.items():
		state_file.write(str(keys) +"|"+str(values)+"\n")
	state_file.close()

"""This function dig till core"""
def dig(url_array,length,depth,flag=0):
	# -*- coding: utf-8 -*-
	if(flag==0):
		count_of_url_traversed=0
	else:
		public_response=ping(url_array[0])
		print('pinging : '+url_array[0])
		if(link_contains_public_profile_url(public_response)):
			count_of_url_traversed=0
		else:
			f=open('paste.txt','r')
			f1=open('paste.txt','r')
			read_file=[]
			url1=""
			count_of_depth=0
			for i in f:
				count_of_depth+=1
			f.close()
			for i in range(count_of_depth-1):
				read_file=f1.readline().split('|')
				if(int(read_file[0]) == depth+1):
					url1 = str(read_file[1])
					count_from_file = str(read_file[2])[:-1]
			f1.close()	
			count_of_url_traversed = int(count_from_file)
	print("Length of url retuned : " + str(length))
	while(True):
		print('count_of_url_traversed : ' + str(count_of_url_traversed) + ' and length is : ' + str(length))
		if(count_of_url_traversed == length):
			print('All url traversed')
			return
		else:
			#ping the link get response
			restore_array[depth + 1] = url_array[count_of_url_traversed] + "|" + str(count_of_url_traversed)
			write_file(restore_array)
			print('pinging : ' + url_array[count_of_url_traversed])
			response = ping(url_array[count_of_url_traversed])
			if(re.match('Error',str(response))):
				pass
			else:
				if(link_contains_public_profile_url(response)):
					public_urls=parse_and_return_publicurl(response)
					for i in public_urls:
						res=public_ping(i)
						if(re.match('Error',str(res))):
							pass
						else:
							soup = BeautifulSoup(res)
							location = soup.find('span', {'class' :'locality'})
							name = soup.find('span', {'class' :'full-name'})
							if(name and location):
								data=name.text + "|"+ location.text
								try:
									clean_data = clean(str(name.text))
									if(location.text=='India'):
										clean_data='discard'
									print(clean_data)
								except:
									print('Discarding')
									clean_data='discard'
								if(re.match('discard',clean_data)):
										pass
								else:
									try:
										f = codecs.open('data.csv', encoding='utf-8', mode='a')
										query = 'INSERT INTO users (url, Name, Location) VALUES (\"'+str(i)+'\",\"'+ clean_data +'\",\"'+ str(location.text) +'\");\n'
										f.write(query)
										f.close()
									except:
										pass

					count_of_url_traversed+=1
					while(count_of_url_traversed<len(url_array)):
						#ping to each link get the response and write in the file
						print('count_of_url_traversed : '+str(count_of_url_traversed)+' and length is : '+str(len(url_array)))
						public_profile=url_array[count_of_url_traversed]
						print("pinging : "+public_profile)
						response=ping(public_profile)
						other_public_page=parse_and_return_publicurl(response)
						for j in other_public_page:
							res=public_ping(j)
							if(re.match('Error',str(res))):
								pass
							else:
								soup = BeautifulSoup(res.decode('utf-8'))
								location = soup.find('span', {'class' :'locality'})
								name=soup.find('span', {'class' :'full-name'})
								if(name and location):
									data1=name.text + "|"+ location.text
									try:
										clean_data = clean(str(name.text))
										if(location.text=='India'):
											clean_data='discard'
									except:
										clean_data='discard'
									#print(clean_data)
									if(re.match('discard',clean_data)):
										pass
									else:
										try:
											f = codecs.open('data.csv', encoding='utf-8', mode='a')
											query = 'INSERT INTO users (url, Name, Location) VALUES (\"'+str(j)+'\",\"'+ clean_data +'\",\"'+ str(location.text) +'\");\n'
											f.write(query)
											f.close()
										except:
											pass
						count_of_url_traversed+=1
					print("Depth is : "+str(depth))
					return
				else:
					# digging starts here
					print(url_array[count_of_url_traversed])
					list_of_url=parse_and_return_list(url_array[count_of_url_traversed],response)
					write_file(restore_array)
					dig(list_of_url,len(list_of_url),depth+1)
			count_of_url_traversed+=1

			print("count of url traversed : "+str(count_of_url_traversed))
	print("Depth at top hiearchy : " + str(depth))	
	return

x=ping(root_url)
u=parse_and_return_list(root_url,x)
dig(u,len(u),depth)
