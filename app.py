from flask import Flask, session, render_template, request, redirect, make_response
import json
import requests
from datetime import timedelta
import random
import hashlib
from misskey import Misskey, MiAuth, Permissions
from misskey.exceptions import MisskeyMiAuthFailedException
import time
import sqlite3
import os

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'

http_session = requests.Session()
http_session.headers.update({'User-Agent': USER_AGENT})

app = Flask(__name__, static_url_path='')
app.secret_key = bytes(bytearray(random.getrandbits(8) for _ in range(32)))
app.permanent_session_lifetime = timedelta(hours=1)

db = sqlite3.connect('blomi.db', check_same_thread=False)

def row_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

db.row_factory = row_factory

def error_response(text, code:int = 200, content_type: str = 'text/html; charset=utf-8'):
    r = make_response(text, code)
    r.headers['Content-Type'] = content_type
    return r

def sha256(data: bytes):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

def convertURI(u, hostname):
    uri = u['uri']
    if not u['uri']:
        return f'https://{hostname}/users/{u["id"]}'
    return uri

@app.route('/')
def root():
    return render_template('index.html')

@app.route('/mypage')
def mypage():
    if not session.get('logged_in'):
        return redirect('/')
    
    myURI = convertURI(session['i'], session['hostname'])

    cur = db.cursor()
    cur.execute('SELECT COUNT(*) FROM hashedBlockInfo WHERE blockBy = ?', (sha256(myURI),))
    blockingCount = cur.fetchone()['COUNT(*)']
    cur.execute('SELECT COUNT(*) FROM hashedBlockInfo WHERE blockTo = ?', (sha256(myURI),))
    blockedCount = cur.fetchone()['COUNT(*)']
    cur.execute('SELECT COUNT(*) FROM hashedBlockInfo')
    totalCount = cur.fetchone()['COUNT(*)']
    cur.close()

    return render_template('mypage.html', blockingCount=blockingCount, blockedCount=blockedCount, totalCount=totalCount)

@app.route('/status')
def status():

    cur = db.cursor()
    cur.execute('SELECT COUNT(DISTINCT blockBy) FROM hashedBlockInfo')
    usersCount = cur.fetchone()['COUNT(DISTINCT blockBy)']
    cur.execute('SELECT COUNT(*) FROM hashedBlockInfo')
    totalCount = cur.fetchone()['COUNT(*)']
    cur.close()

    return render_template('status.html', usersCount=usersCount, totalCount=totalCount)
    


@app.route('/login', methods=['POST'])
def login():
    data = request.form
    session['logged_in'] = False
    if not data.get('hostname'):
        return error_response('インスタンスのホスト名を入力してください', 400)
    
    try:
        mi = Misskey(address=data['hostname'], session=http_session)
    except requests.exceptions.ConnectionError:
        return error_response('インスタンスと通信できませんでした。', code=500)
    instance_info = mi.meta()

    session['hostname'] = data['hostname']

    if instance_info['features'].get('miauth') == True:
        miauth = MiAuth(
            address=data['hostname'],
            name='Blomi',
            callback=f'{request.host_url}login/callback',
            permission=[Permissions.READ_ACCOUNT, Permissions.READ_BLOCKS],
            session=http_session
        )
        url = miauth.generate_url()
        session['session_id'] = miauth.session_id
        session['mi_legacy'] = False
        return redirect(url)
    else:
        # v12.39.1以前のインスタンス向け
        options = {
            'name': 'Blomi (Legacy)',
            'callback': f'{request.host_url}login/callback',
            'permission': ['read:account', 'read:blocks'],
            'description': 'Created by CyberRex (@cyberrex_v2@misskey.io)',
            'callbackUrl': f'{request.host_url}login/callback',
        }

        r = requests.post(f'https://{data["hostname"]}/api/app/create', json=options, headers={'User-Agent': USER_AGENT})
        if r.status_code != 200:
            return make_response(f'Failed to generate app: {r.text}', 500)
        j = r.json()

        secret_key = j['secret']

        r = requests.post(f'https://{data["hostname"]}/api/auth/session/generate', json={'appSecret': secret_key}, headers={'User-Agent': USER_AGENT})
        if r.status_code != 200:
            return make_response(f'Failed to generate session: {r.text}', 500)
        j = r.json()
        
        session['mi_session_token'] = j['token']
        session['mi_secret_key'] = secret_key
        session['mi_legacy'] = True
        return redirect(j['url'])

@app.route('/login/callback')
def login_msk_callback():
    if not ('logged_in' in list(session.keys())):
        return error_response('<meta name="viewport" content="width=device-width">セッションデータが異常です。Cookieを有効にしているか確認の上再試行してください。<a href="/">トップページへ戻る</a>')

    if not session['mi_legacy']:

        miauth = MiAuth(session['hostname'] ,session_id=session['session_id'], session=http_session)
        try:
            token = miauth.check()
        except MisskeyMiAuthFailedException:
            session.clear()
            return error_response('<meta name="viewport" content="width=device-width">認証に失敗しました。', code=500)
        session['token'] = token

    else:
        secret_key = session['mi_secret_key']
        session_token = session['mi_session_token']
        r = requests.post(f'https://{session["hostname"]}/api/auth/session/userkey', json={'appSecret': secret_key, 'token': session_token}, headers={'User-Agent': USER_AGENT})
        if r.status_code != 200:
            return error_response(f'Failed to generate session: {r.text}', code=500)
        j = r.json()

        access_token = j['accessToken']
        ccStr = f'{access_token}{secret_key}'
        token = hashlib.sha256(ccStr.encode('utf-8')).hexdigest()

    mi: Misskey = Misskey(address=session['hostname'], i=token, session=http_session)
    i = mi.i()

    session['username'] = i['username']
    session['acct'] = f'{i["username"]}@{session["hostname"]}'
    session['user_id'] = i['id']
    session['i'] = i
 
    collectBlocking({
        'hostname': session['hostname'],
        'token': token,
        'user_id': session['user_id'],
        'user_uri': convertURI(i, session['hostname'])
    })

    session['logged_in'] = True

    return redirect('/mypage')

def collectBlocking(data):
    mi: Misskey = Misskey(address=data['hostname'], i=data['token'], session=http_session)
    blocking_users = []
    
    last_id = None
    while True:
        blocks = mi.blocking_list(limit=100, since_id=last_id)
        if not blocks:
            break
        blocking_users.extend(blocks)
        if len(blocks) < 100:
            break
        last_id = blocks[-1]['id']
        time.sleep(0.2)
    
    hashedBlockInfo = []
    hashedBlockerId = sha256(data['user_uri'])

    for block in blocking_users:
        hashedBlockInfo.append((
            hashedBlockerId,
            sha256(convertURI(block['blockee'], data['hostname']))
        ))
    
    cur = db.cursor()
    cur.executemany('REPLACE INTO hashedBlockInfo(blockBy, blockTo) VALUES(?, ?)', hashedBlockInfo)
    cur.close()
    db.commit()
    




app.run(host='127.0.0.1', port=3300, debug=(True if os.environ.get('FLASK_ENV')!='production' else False), threaded=True)