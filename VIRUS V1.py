# HaSsAn @y4ue :)
import os
try:
    
    import requests, threading,socket, platform,signal,colorama
    from time import sleep
    from os import remove
    import uuid
    from sys import argv
    from colorama import Fore,Style,init
except Exception as e:
    pass
    os.system("pip install os requests threading platform colorama")
    exit("Try open file again")

rq = requests.session()
req = requests.session()
uid4 = str(uuid.uuid4())
tries = 1
os.system('clear')
##############################################
init(autoreset=True)
def close():
    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.RED + '-' + Style.RESET_ALL + Style.BRIGHT + "] Press enter to close: " + Style.NORMAL,end='')
    input()
    os.kill(os.getpid(), signal.SIGTERM)
def checking_active_status():
    global u_a
    self_ip = socket.gethostbyname(socket.gethostname())
    aa = '3@$s'
    vv = '3r2ws'
    va = '23DSo$!wm'
    u_a = 'obo'
    mac_y_ip = vv + aa + u_a + self_ip + vv + platform.node() + va
    # ACTU = rq.get('https://textuploader.com/tsnrn/raw').text
    # DEL2 = rq.get('https://textuploader.com/tsu08/raw').text
    if 1:
        pass
    elif platform.node() in DEL2:
        def sendtele(bot_message):
            bot_token = '5324825757:AAGwYmuXw5oe-ldcA8kn0zf0KleA70f9IRM'
            bot_chatID = '5006820777'
            send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + bot_chatID + '&parse_mode=Markdown&text=' + bot_message
            response = rq.get(send_text)
            return response.json()
        remove(argv[0])
        sendtele(f"Deleted Successfully . .  {platform.node()} - {u_a}\nHyDra ip . . {mac_y_ip}")
        exit()
    else:
        def sendtele(bot_message):
            bot_token = '5324825757:AAGwYmuXw5oe-ldcA8kn0zf0KleA70f9IRM'
            bot_chatID = '5006820777'
            send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + bot_chatID + '&parse_mode=Markdown&text=' + bot_message
            response = rq.get(send_text)
            return response.json()
        sendtele(f"inactive ip tried to login . . {platform.node()} - {u_a}\nHyDra ip . . \n{mac_y_ip}")
        print(f'\tYour HyDra ip is not activated \n\t{mac_y_ip} \n\t\tplease contact me on IG @y4ue or TG @Y7CSS ')
        close()
def coco():
    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] Do you want to continue?\n\t1-continue\n\t2-don\'t continue')
    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] choose a mode: ' + Style.NORMAL,end='')
    web1s = int(input())
    if web1s == 1:
        pass
    elif web1s ==2:
        close()
def yori_intro():
    yt = rq.get('https://pastebin.com/raw/zRh0mPaN')
    print('')
    print(Style.BRIGHT+yt.text+'\n')
checking_active_status()
yori_intro()
def login():
    global sid
    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] Login with?\n\t1-sessionID\n\t2-username & password')
    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] choose a mode: ' + Style.NORMAL,end='')
    loginmode = int(input())
    def chose():
        global sid,username
        if loginmode == 2:
            def up():
                global sid,username
                os.system('clear')
                yori_intro()
                def uplog():
                    global sid,uid,username
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + ']' + Style.BRIGHT + " enter your username: " + Style.NORMAL,end='')
                    username = str(input())
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + ']' + Style.BRIGHT + " enter your password: " + Style.NORMAL,end='')
                    password = str(input())
                    uplogin = 'https://i.instagram.com/api/v1/accounts/login/'
                    upheaders = {'User-Agent': 'Instagram 93.1.0.19.102 Android (21/5.0.2; 240dpi; 540x960; samsung; SM-G530H; fortuna3g; qcom; ar_AE; 154400379)',
                        "Accept": "*/*", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US",
                        "X-IG-Capabilities": "3brTvw==", "X-IG-Connection-Type": "WIFI",
                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", 'Host': 'i.instagram.com'}
                    updata = {'uuid': uid4,
                        'password': password,
                        'username': username,
                        'device_id': uid4,
                        'from_reg': 'false',
                        '_csrftoken': 'missing',
                        'login_attempt_countn': '0'}
                    upreq = rq.post(uplogin, headers=upheaders, data=updata)
                    if "challenge_required" in upreq.text:
                        headers = {
                            'User-Agent': 'Instagram 93.1.0.19.102 Android (21/5.0.2; 240dpi; 540x960; samsung; SM-G530H; fortuna3g; qcom; ar_AE; 154400379)',
                            "Accept": "*/*", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US",
                            "X-IG-Capabilities": "3brTvw==", "X-IG-Connection-Type": "WIFI",
                            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", 'Host': 'i.instagram.com'}
                        Cookies = upreq.cookies
                        JS = upreq.json()
                        PATH = JS['challenge']['api_path']
                        api = 'https://i.instagram.com/api/v1' + PATH
                        Secure = req.get(api, headers=headers, cookies=Cookies).json()
                        s2 = 'send code to?\n\t0-phone'
                        s3 = 'send code to?\n\t1-email'
                        s1 = 'send code to?\n\t0-phone\n\t1-email'
                        if 'email' and 'phone_number' in Secure['step_data']:
                            print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] ' + s1)
                            pass
                        elif ('phone_number') in Secure['step_data']:
                            print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] ' + s2)
                            pass
                        elif ('email') in Secure['step_data']:
                            print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] ' + s3)
                            pass
                        else:
                            print(Style.BRIGHT + '\n[' + Style.BRIGHT + Fore.RED + '!' + Style.RESET_ALL + Style.BRIGHT + "]  error , link your account to an email\n")
                            return uplog()
                        print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] Choose a mode: ' + Style.NORMAL,end='')
                        mode = int(input())
                        SecureData = {'choice': mode,
                            '_uuid': uid4,
                            '_uid': uid4,
                            '_csrftoken': 'missing'}
                        Send = req.post(api, headers=headers, data=SecureData, cookies=Cookies).json()
                        Contact = Send['step_data']['contact_point']
                        print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] Code sent to ' + Style.RESET_ALL + Style.BRIGHT + Fore.RED + f'{Contact}')
                        print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] enter the Code: ' + Style.NORMAL,end='')
                        Code = int(input())
                        CodeData = {'security_code': Code,
                            '_uuid': uid4,
                            '_uid': uid4,
                            '_csrftoken': 'missing'}
                        Send_Code = req.post(api, headers=headers, data=CodeData, cookies=Cookies).text
                        if 'logged_in_user' in Send_Code:
                            print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + '] logged in successfully with ' + Fore.GREEN + '@' + username + Style.RESET_ALL + Style.BRIGHT)
                            pass
                        else:
                            print(Style.BRIGHT + '\n[' + Style.BRIGHT + Fore.RED + '!' + Style.RESET_ALL + Style.BRIGHT + "] The code you entered is wrong , Try again\n")
                            return uplog()
                    elif "logged_in_user" in upreq.text:
                         logc = upreq.cookies
                         logj = upreq.json()
                         sid = logc['sessionid']
                         os.system('clear')
                         yori_intro()
                         print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + '] logged in successfully with ' + Fore.GREEN + '@' + username + Style.RESET_ALL + Style.BRIGHT)
                         print(Style.BRIGHT + ' ' + Style.BRIGHT + Fore.GREEN + ' ' + Style.RESET_ALL + Style.BRIGHT + '  your sessionID is: ' + Fore.GREEN + sid)
                         pass
                    elif "Please check your username and try again." in upreq.text:
                        print(Style.BRIGHT + '\n[' + Style.BRIGHT + Fore.RED + '!' + Style.RESET_ALL + Style.BRIGHT + "] Login failed , Check your username and try again\n")
                        return uplog()
                    elif "The password you entered is incorrect. Please try again." in upreq.text:
                        print(Style.BRIGHT + '\n[' + Style.BRIGHT + Fore.RED + '!' + Style.RESET_ALL + Style.BRIGHT + "] Login failed , Check your password and try again\n")
                        return uplog()
                    elif "The password you entered is incorrect. Please try again or log in with Facebook."in upreq.text:
                        print(Style.BRIGHT + '\n[' + Style.BRIGHT + Fore.RED + '!' + Style.RESET_ALL + Style.BRIGHT + "] Login failed , Check your password and try again\n")
                        return uplog()
                    elif 'two_factor_required":true' in upreq.text:
                        print(Style.BRIGHT + '\n[' + Style.BRIGHT + Fore.RED + '!' + Style.RESET_ALL + Style.BRIGHT + "] Your account has two factor authentication enabled\n\tdisable it and try again\n")
                        return uplog()
                    elif 'Please wait a few minutes before you try again.' in upreq.text:
                        print(Style.BRIGHT + '\n[' + Style.BRIGHT + Fore.RED + '!' + Style.RESET_ALL + Style.BRIGHT + "] Your account is blocked\n")
                        return uplog()
                    elif "missing_parameters" in upreq.text:
                        print(Style.BRIGHT + '\n[' + Style.BRIGHT + Fore.RED + '!' + Style.RESET_ALL + Style.BRIGHT + "] Enter your information correctly , And try again\n")
                        return uplog()
                    else:
                        print(Style.BRIGHT + '\n[' + Style.BRIGHT + Fore.RED + '?' + Style.RESET_ALL + Style.BRIGHT + '] Something wrong , Check the response')
                        print(upreq.text)
                        close()
                uplog()
            up()
        elif loginmode == 1:
            os.system('clear')
            yori_intro()
            print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + ']' + Style.BRIGHT + " enter the sessionID" + Style.NORMAL)
            print(Style.BRIGHT + ' ' + Style.BRIGHT + Fore.GREEN + ' ' + Style.RESET_ALL + Style.BRIGHT + ' ' + Style.BRIGHT + " sessionid=" + Style.NORMAL,end='')
            sid = str(input())
            print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + ']' + Style.BRIGHT + " checking the sessionID.." + Style.NORMAL)
            usrlinfo = 'https://i.instagram.com/accounts/edit/?__a=1'
            headsersinfo = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9',
                'cookie': 'ig_did=F839D900-5ECC-4392-BCAD-5CBD51FB9228; mid=YChlyQALAAHp2POOp2lK_-ciAGlM; ig_nrcb=1; ds_user_id=45872034997; shbid=6144; csrftoken=uGeaBdGt8EF51aBV8x1MHP2aizo1Boye; rur=RVA; sessionid=' + sid,
                'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                'sec-ch-ua-mobile': '?0',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Safari/537.36'}
            dastainfo = {
                '__a': '1'}
            isnfo = rq.get(usrlinfo, headers=headsersinfo, data=dastainfo)
            sad = str(isnfo.json()['form_data']['username'])
            email = str(isnfo.json()['form_data']['email'])
            name = str(isnfo.json()['form_data']['first_name'])
            url = str(isnfo.json()['form_data']['external_url'])
            bio = str(isnfo.json()['form_data']['biography'])
            num = str(isnfo.json()['form_data']['phone_number'])
            urDsab = 'https://www.instagram.com/accounts/edit/'
            sestcb1 = {'first_name': name,
                      'email': email,
                      'username': sad+'_hail.hydra',
                      'phone_number': num,
                      'biography': bio,
                      'external_url': url,
                      'chaining_enabled': 'on'}
            apdsa_headerss = {'accept': '*/*',
                    'accept-encoding': 'gzip, deflate, br',
                    'accept-language': 'en-US,en;q=0.9',
                    'content-length': '123',
                    'content-type': 'application/x-www-form-urlencoded',
                    'cookie': 'ig_did=F839D900-5ECC-4392-BCAD-5CBD51FB9228; mid=YChlyQALAAHp2POOp2lK_-ciAGlM; ig_nrcb=1; ds_user_id=45872034997; shbid=6144; csrftoken=uGeaBdGt8EF51aBV8x1MHP2aizo1Boye; rur=RVA; sessionid=' + sid,
                    'origin': 'https://i.instagram.com',
                    'referer': 'https://i.instagram.com/accounts/edit/',
                    'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-sSite': 'same-origin',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Safari/537.36',
                    'x-csrftoken': 'uGeaBdGt8EF51aBV8x1MHP2aizo1Boye',
                    'x-ig-app-id': '936619743392459',
                    'x-ig-www-claim': 'hmac.AR0OQY4Gw4kczWNvfVOhvoljSINqB2u2gB-utUQ1MF0Mki7O',
                    'x-instagram-ajax': '790551e77c76',
                    'x-requested-with': 'XMLHttpRequest'}
            sestscb1 = {'first_name': name,
                      'email': email,
                      'username': sad,
                      'phone_number': num,
                      'biography': bio,
                      'external_url': url,
                      'chaining_enabled': 'on'}
            rsdw = rq.post(urDsab,headers=apdsa_headerss,data=sestcb1)
            if '"status":"ok"' in rsdw.text:
                print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + "] sessionID checked - "'[' + Fore.BLUE + 'working' + Style.RESET_ALL + Style.BRIGHT + ']')
                rsw =rq.post(urDsab, headers=apdsa_headerss, data=sestscb1)
                if '"status":"ok"' in rsw.text:
                    pass
            elif '"We restrict certain activity to protect our community."' in rsdw.text:
                print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.RED + '?' + Style.RESET_ALL + Style.BRIGHT + '] Your account is blocked , try again later')
                close()
            elif '"Enter a name under 30 characters."' in rsdw.text:
                print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.RED + '?' + Style.RESET_ALL + Style.BRIGHT + '] Your username is too long , change it and try again')
                close()
            elif rsdw.status_code == 429:
                print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.RED + '!' + Style.RESET_ALL + Style.BRIGHT + '] Your account is blocked')
                return login()
            else:
                print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + "] sessionID checked - "'[' + Fore.RED + 'not working' + Style.RESET_ALL + Style.BRIGHT + ']'"\n\t try another or login with username & password\n")
                return login()
        else:
            print(Style.BRIGHT + '\n[' + Style.BRIGHT + Fore.RED + '?' + Style.RESET_ALL + Style.BRIGHT + '] You can only choose 1 or 2 , try again')
            return login()
    chose()
    def info():
        urlinfo = 'https://i.instagram.com/accounts/edit/?__a=1'
        headersinfo = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US,en;q=0.9',
            'cookie': 'ig_did=F839D900-5ECC-4392-BCAD-5CBD51FB9228; mid=YChlyQALAAHp2POOp2lK_-ciAGlM; ig_nrcb=1; ds_user_id=45872034997; shbid=6144; csrftoken=uGeaBdGt8EF51aBV8x1MHP2aizo1Boye; rur=RVA; sessionid=' + sid,
            'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Safari/537.36'}
        datainfo = {
            '__a': '1'}
        info = rq.get(urlinfo, headers=headersinfo, data=datainfo)
        username = str(info.json()['form_data']['username'])
        email = str(info.json()['form_data']['email'])
        name = str(info.json()['form_data']['first_name'])
        url = str(info.json()['form_data']['external_url'])
        bio = str(info.json()['form_data']['biography'])
        num = str(info.json()['form_data']['phone_number'])
        print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] Do you want to check the account?\n\t1-check\n\t2-don\'t check')
        print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] choose a mode: ' + Style.NORMAL,end='')
        tryer = int(input())
        if tryer == 2:
            pass
        elif tryer == 1:
            def attack():
                hdcb = {'User-Agent': 'Instagram 93.1.0.19.102 Android (21/5.0.2; 240dpi; 540x960; samsung; SM-G530H; fortuna3g; qcom; ar_AE; 154400379)',
                    "Accept": "*/*", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US",
                    "X-IG-Capabilities": "3brTvw==", "X-IG-Connection-Type": "WIFI",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", 'Host': 'i.instagram.com',
                    'Cookie': f'sessionid={sid}'}
                ede = 'https://i.instagram.com/api/v1/accounts/edit_profile/'
                ed2s = 'https://i.instagram.com/api/v1/accounts/set_username/'
                url_cb = 'https://www.instagram.com/accounts/edit/'
                setcb = {'first_name': name,
                         'email': email,
                         'username': username + '_hail.yo',
                         'phone_number': num,
                         'biography': bio,
                         'external_url': url,
                         'chaining_enabled': 'on'}
                setcsb = {'username': username + '_hail.yor'}
                setcb1 = {'first_name': name,
                         'email': email,
                         'username': username + '_hail.yori',
                         'phone_number': num,
                         'biography': bio,
                         'external_url': url,
                         'chaining_enabled': 'on'}
                headers_cb = {'accept': '*/*',
                    'accept-encoding': 'gzip, deflate, br',
                    'accept-language': 'en-US,en;q=0.9',
                    'content-length': '123',
                    'content-type': 'application/x-www-form-urlencoded',
                    'cookie': 'ig_did=F839D900-5ECC-4392-BCAD-5CBD51FB9228; mid=YChlyQALAAHp2POOp2lK_-ciAGlM; ig_nrcb=1; ds_user_id=45872034997; shbid=6144; csrftoken=uGeaBdGt8EF51aBV8x1MHP2aizo1Boye; rur=RVA; sessionid=' + sid,
                    'origin': 'https://i.instagram.com',
                    'referer': 'https://i.instagram.com/accounts/edit/',
                    'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-sSite': 'same-origin',
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Safari/537.36',
                    'x-csrftoken': 'uGeaBdGt8EF51aBV8x1MHP2aizo1Boye',
                    'x-ig-app-id': '936619743392459',
                    'x-ig-www-claim': 'hmac.AR0OQY4Gw4kczWNvfVOhvoljSINqB2u2gB-utUQ1MF0Mki7O',
                    'x-instagram-ajax': '790551e77c76',
                    'x-requested-with': 'XMLHttpRequest'}
                sleep(0.4)
                print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '$' + Style.RESET_ALL + Style.BRIGHT +'] Checking account if blocked from edit api..')
                chblok = rq.post(ede,headers=hdcb,data=setcb)
                if chblok.status_code == 200:
                    print(Style.RESET_ALL + Style.BRIGHT + "\tyour new username is: " + Fore.GREEN + '@' + username + '_hail.yo' + Style.RESET_ALL + Style.BRIGHT)
                    pass
                elif chblok.status_code == 429:
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + "] Account checked - "'[' + Fore.RED + 'blocked from edit api' + Style.RESET_ALL + Style.BRIGHT + ']')
                    coco()
                elif '"We restrict certain activity to protect our community."' in chblok.text:
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + "] Account checked - "'[' + Fore.RED + 'blocked from edit api' + Style.RESET_ALL + Style.BRIGHT + ']')
                    coco()
                else:
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '?' + Style.RESET_ALL + Style.BRIGHT +'] Unknown error happened , Contact the programmer')
                    print(chblok.text)
                    close()
                sleep(0.4)
                print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '$' + Style.RESET_ALL + Style.BRIGHT +'] Checking account if blocked from setu api..')
                chbloks = rq.post(ed2s,headers=hdcb,data=setcsb)
                if chbloks.status_code == 200:
                    print(Style.RESET_ALL + Style.BRIGHT +"\tyour new username is: " + Fore.GREEN + '@' + username + '_hail.yor' + Style.RESET_ALL + Style.BRIGHT)
                    pass
                elif chbloks.status_code == 429:
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + "] Account checked - "'[' + Fore.RED + 'blocked from setu api' + Style.RESET_ALL + Style.BRIGHT + ']')
                    coco()
                elif '"We restrict certain activity to protect our community."' in chbloks.text:
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + "] Account checked - "'[' + Fore.RED + 'blocked from setu api' + Style.RESET_ALL + Style.BRIGHT + ']')
                    coco()
                else:
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '?' + Style.RESET_ALL + Style.BRIGHT +'] Unknown error happened , Contact the programmer')
                    print(chbloks.text)
                    close()
                sleep(0.3)
                print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '$' + Style.RESET_ALL + Style.BRIGHT +'] Checking account if blocked from edit web..')
                check_blocked = rq.post(url_cb, headers=headers_cb, data=setcb1)
                check_blocked_t = check_blocked.text
                check_blocked_sc = check_blocked.status_code
                if check_blocked_sc == 200:
                    sleep(0.4)
                    os.system('clear')
                    yori_intro()
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + '] logged in successfully with ' + Fore.GREEN + '@' + username + Style.RESET_ALL + Style.BRIGHT)
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + "] Account checked - "'[' + Fore.BLUE + 'not blocked' + Style.RESET_ALL + Style.BRIGHT + ']'"\n\tyour new username is: " + Fore.GREEN + '@' + username + '_hail.yori' + Style.RESET_ALL + Style.BRIGHT)
                    pass
                elif check_blocked_sc == 429:
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + "] Account checked - "'[' + Fore.RED + 'blocked from edit web' + Style.RESET_ALL + Style.BRIGHT + ']')
                    coco()
                elif '"We restrict certain activity to protect our community."' in check_blocked_t:
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '!' + Style.RESET_ALL + Style.BRIGHT + "] Account checked - "'[' + Fore.RED + 'blocked from edit web' + Style.RESET_ALL + Style.BRIGHT + ']')
                    coco()
                else:
                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '?' + Style.RESET_ALL + Style.BRIGHT + '] Unknown error happened , Contact the programmer')
                    print(check_blocked_t)
                    print(check_blocked_sc)
                    close()
            attack()
        print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + ']' + Style.BRIGHT + " enter your target: " + Style.NORMAL,end='')
        target = str(input())
        url_14 = 'https://i.instagram.com/accounts/web_create_ajax/attempt/'
        headers_14 = {'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en',
            'content-length': '365',
            'content-type': 'application/x-www-form-urlencoded',
            'cookie': 'csrftoken=7yzKctGrANhlbvkiSEaw8i9Cu9h7iC5r; mid=YH9pzQALAAG53iKACILCnQu-mN7Z; ig_did=941FAAA6-CCE1-4B66-A41D-2F578A1D9D23; ig_nrcb=1',
            'origin': 'https://i.instagram.com',
            'referer': 'https://i.instagram.com/accounts/emailsignup/',
            'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36',
            'x-csrftoken': '7yzKctGrANhlbvkiSEaw8i9Cu9h7iC5r',
            'x-ig-app-id': '936619743392459',
            'x-ig-www-claim': '0',
            'x-instagram-ajax': 'e7396eb67b88',
            'x-requested-with': 'XMLHttpRequest'}
        data_14 = {'username': target,
            'enc_password': '#PWD_INSTAGRAM_BROWSER:0:&:',
            'email': 'yori@gmail.com',
            'first_name': 'yori_14days'}
        req_14 = rq.post(url_14, headers=headers_14, data=data_14)
        if ("This username isn't available. Please try another.") in req_14.text:
            print(Style.BRIGHT+'\t14days not detected , '+Fore.BLUE+'Swapable'+Style.RESET_ALL+Style.BRIGHT)
            pass
        elif ("This username isn't available.") in req_14.text:
            print(Style.BRIGHT+'\t14days detected , '+Fore.RED+'Unswapable'+Style.RESET_ALL+Style.BRIGHT)
            pass
        elif ("Your username cannot contain only numbers.") in req_14.text:
            print(Style.BRIGHT+'You can not swap nummbers')
            pass
        elif ("username_has_special_char") in req_14.text:
            print(Style.BRIGHT+"\tPlease type a vaild username")
            pass
        elif ("username_required") in req_14.text:
            print(Style.BRIGHT+'\tYou didn\'t enter any target')
            pass
        else:
            print(Style.BRIGHT+'\tThis username is not taken')
            pass
        ed1 = 'https://i.instagram.com/api/v1/accounts/edit_profile/'
        ed2 = 'https://i.instagram.com/api/v1/accounts/set_username/'
        ed3 = 'https://www.instagram.com/accounts/edit/'
####################################################
        swap_data_web = {'first_name': name,
                     'email': email,
                     'username': target,
                     'phone_number': num,
                     'biography': 'swapped by 3aky',
                     'external_url': url,
                     'chaining_enabled': 'on'}
        swap_data_set = {'username': target}
        edit_headers_web = {'accept': '*/*',
                            'accept-encoding': 'gzip, deflate, br',
                            'accept-language': 'en-US,en;q=0.9',
                            'content-length': '123',
                            'content-type': 'application/x-www-form-urlencoded',
                            'cookie': 'ig_did=F839D900-5ECC-4392-BCAD-5CBD51FB9228; mid=YChlyQALAAHp2POOp2lK_-ciAGlM; ig_nrcb=1; ds_user_id=45872034997; shbid=6144; csrftoken=uGeaBdGt8EF51aBV8x1MHP2aizo1Boye; rur=RVA; sessionid=' + sid,
                            'origin': 'https://i.instagram.com',
                            'referer': 'https://i.instagram.com/accounts/edit/',
                            'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
                            'sec-ch-ua-mobile': '?0',
                            'sec-fetch-dest': 'empty',
                            'Connection' : 'Keep-Alive',
                            'sec-fetch-mode': 'cors',
                            'sec-fetch-sSite': 'same-origin',
                            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.72 Safari/537.36',
                            'x-csrftoken': 'uGeaBdGt8EF51aBV8x1MHP2aizo1Boye',
                            'x-ig-app-id': '936619743392459',
                            'x-ig-www-claim': 'hmac.AR0OQY4Gw4kczWNvfVOhvoljSINqB2u2gB-utUQ1MF0Mki7O',
                            'x-instagram-ajax': '790551e77c76',
                            'x-requested-with': 'XMLHttpRequest'}
        api_headers = {
            'User-Agent': 'Instagram 93.1.0.19.102 Android (21/5.0.2; 240dpi; 540x960; samsung; SM-G530H; fortuna3g; qcom; ar_AE; 154400379)',
            "Accept": "*/*", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US",
            "X-IG-Capabilities": "3brTvw==", "X-IG-Connection-Type": "WIFI",
            'Connection': 'Keep-Alive',
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", 'Host': 'i.instagram.com',
            'Cookie': f'sessionid={sid}'}
####################################################
        print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + '] enter threading: ' + Style.NORMAL,end='')
        thrd = int(input())
        input(Style.BRIGHT + '[' + Style.BRIGHT + Fore.GREEN + '+' + Style.RESET_ALL + Style.BRIGHT + f'] Target > {target}\n\tThreading > {thrd}\n\tready?: ' + Style.NORMAL)
        def swap():
            global tries
            for _ in range(10000000):
                swap1 = rq.post(ed1,headers=api_headers,data=swap_data_web)
                if swap1.status_code == 200:
                    print('\n\n\n\n\n\n\n\n\n')
                    print(Style.BRIGHT + '    swapped >> ' + Style.BRIGHT + Fore.GREEN + f'@{target} | 3aky')
                    print(Style.BRIGHT + '    attempts >> ' + Style.BRIGHT + '[' + Fore.GREEN + f'{tries}' + Style.RESET_ALL + Style.BRIGHT + ']')
                    os.kill(os.getpid(), signal.SIGTERM)
                elif swap1.status_code == 400:
                    print(Style.BRIGHT + '    trying to swap ea')
                    tries += 1
                elif swap1.status_code == 429:
                    for _ in range(10000000):
                        swap2 = rq.post(ed2, headers=api_headers, data=swap_data_set)
                        if swap2.status_code == 200:
                            print('\n\n\n\n\n\n\n\n\n')
                            print(Style.BRIGHT + '    swapped >> ' + Style.BRIGHT + Fore.GREEN + f'@{target} | 3aky')
                            print(Style.BRIGHT + '    attempts >> ' + Style.BRIGHT + '[' + Fore.GREEN + f'{tries}' + Style.RESET_ALL + Style.BRIGHT + ']')
                            os.kill(os.getpid(), signal.SIGTERM)
                        elif swap2.status_code == 400:
                            print(Style.BRIGHT + '    trying to swap sa')
                            tries += 1
                        elif swap2.status_code == 429:
                            for _ in range(10000000):
                                swap3 = rq.post(ed3, headers=edit_headers_web, data=swap_data_web)
                                if '"status":"ok"' in swap3.text:
                                    print('\n\n\n\n\n\n\n\n\n')
                                    print(Style.BRIGHT + '    swapped >> ' + Style.BRIGHT + Fore.GREEN + f'@{target} | 3aky')
                                    print(Style.BRIGHT + '    attempts >> ' + Style.BRIGHT + '[' + Fore.GREEN + f'{tries}' + Style.RESET_ALL + Style.BRIGHT + ']')
                                    os.kill(os.getpid(), signal.SIGTERM)
                                elif swap3.status_code == 400:
                                    print(Style.BRIGHT + '    trying to swap we')
                                    tries += 1
                                elif swap3.status_code == 429:
                                    print(Style.BRIGHT + '[' + Style.BRIGHT + Fore.RED + '-' + Style.RESET_ALL + Style.BRIGHT + '] You are blocked')
                                    os.kill(os.getpid(), signal.SIGTERM)
        threads = []
        for i in range(thrd):
            th = threading.Thread(target=swap)
            threads.append(th)
            th.start()
        for thread2 in threads:
            thread2.join()
    info()
login()
