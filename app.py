from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import sqlite3
from pathlib import Path

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'chat.db'

MAX_REQUEST_BYTES = 1_000_000
MAX_TEXT_LENGTH = 2000
MAX_USERNAME_LENGTH = 40
MAX_OPTIONS = 6
MAX_OPTION_LENGTH = 120
POLL_DURATION = timedelta(hours=6)

app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_BYTES

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per minute"],
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS polls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT NOT NULL,
            options TEXT NOT NULL,
            votes TEXT NOT NULL,
            voters TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            closed INTEGER NOT NULL,
            expires_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


def request_too_large():
    content_length = request.content_length
    return content_length is not None and content_length > MAX_REQUEST_BYTES


def iso_now():
    return datetime.utcnow().isoformat()


def friendly_timestamp():
    return datetime.now().strftime('%I:%M %p')


def normalize_username(value):
    username = (value or '').strip()
    if not username or len(username) > MAX_USERNAME_LENGTH:
        return None
    return username


def parse_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def poll_row_to_payload(row):
    return {
        'type': 'poll',
        'id': row['id'],
        'question': row['question'],
        'options': json.loads(row['options']),
        'votes': json.loads(row['votes']),
        'voters': json.loads(row['voters']),
        'timestamp': datetime.fromisoformat(row['created_at']).strftime('%I:%M %p'),
        'username': row['created_by'],
        'closed': bool(row['closed']),
        'expires_at': row['expires_at'],
    }


def poll_is_expired(row):
    return datetime.fromisoformat(row['expires_at']) <= datetime.utcnow()


init_db()

# ---------------------------------------------------------------------
#                          HTML + JavaScript
# ---------------------------------------------------------------------
HTML = '''
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>E2EE Chat + Polls</title>
<style>
body{margin:0;font-family:"Helvetica Neue",sans-serif;background:#f5f7fa;
     display:flex;flex-direction:column;height:100vh}
.chat-container{flex:1;overflow-y:auto;padding:20px;display:flex;flex-direction:column}
.message{max-width:60%;padding:12px 16px;margin:10px 0;border-radius:18px;word-wrap:break-word}
.message img{max-width:100%;border-radius:10px;margin-top:8px}
.you{align-self:flex-end;background:#007aff;color:#fff;border-bottom-right-radius:0}
.other{align-self:flex-start;background:#e5e5ea;color:#000;border-bottom-left-radius:0}
.poll{align-self:flex-start;background:#fff;border:1px solid #ccc;border-radius:12px;padding:12px;max-width:70%}
.poll h4{margin:0 0 8px 0}
.option-btn{display:block;width:100%;margin:4px 0;padding:6px 10px;border:1px solid #aaa;border-radius:10px;
            background:#eee;cursor:pointer;text-align:left}
.option-btn:hover{background:#ddd}
.bar{height:12px;background:#007aff;border-radius:6px}
.meta{font-size:12px;color:#ccc;margin-bottom:4px}
.timestamp{font-size:11px;color:#aaa;margin-top:6px;text-align:right}
.chat-input{display:flex;padding:15px;background:#fff;border-top:1px solid #ccc;gap:10px}
.chat-input input[type=text]{flex:2;padding:10px;border:1px solid #ccc;border-radius:18px;font-size:16px}
.chat-input input[type=file]{flex:1;font-size:14px}
.chat-input button{background:#007aff;color:#fff;border:none;border-radius:18px;padding:10px 20px;font-size:16px;cursor:pointer}
</style>
<script>
// ============== helpers =================================================
function toB64(buf){const b=new Uint8Array(buf),c=0x8000,l=b.length;let bin='';for(let i=0;i<l;i+=c)bin+=String.fromCharCode.apply(null,b.subarray(i,i+c));return btoa(bin);}
function fromB64(s){const bin=atob(s),l=bin.length,u=new Uint8Array(l);for(let i=0;i<l;i++)u[i]=bin.charCodeAt(i);return u;}

const enc=new TextEncoder(),dec=new TextDecoder();
let key=null,lastRendered=0;
let me=localStorage.getItem('me')||null;   // saved display‑name

const KDF_SALT='encrypted-chat-salt-v1';
const KDF_ITERATIONS=120000;
async function deriveKey(p){
  const baseKey=await crypto.subtle.importKey('raw',enc.encode(p),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt:enc.encode(KDF_SALT),iterations:KDF_ITERATIONS,hash:'SHA-256'},
    baseKey,
    {name:'AES-GCM',length:256},
    false,
    ['encrypt','decrypt']
  );
}
async function encrypt(o){const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,enc.encode(JSON.stringify(o)));
  return{iv:toB64(iv),cipher:toB64(ct)};}
async function decrypt(m){
  try{const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:fromB64(m.iv)},key,fromB64(m.cipher));
      return JSON.parse(dec.decode(pt));}
  catch{return{text:'(decrypt error)'};}}

const fileToDataURL=f=>new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result);r.onerror=rej;r.readAsDataURL(f);});
const ding=new Audio("data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAgD4AAIA+AAABAAgAZGF0YQAAACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA=");

// ============== rendering ===============================================
function addChatBubble(m,pl){
  const box=document.getElementById('chat');
  const div=document.createElement('div');
  const isMe=(me&&m.username===me);
  div.className='message '+(isMe?'you':'other');
  div.insertAdjacentHTML('beforeend',`<div class="meta">${isMe?'You':m.username}</div>`);
  if(pl.text) div.insertAdjacentHTML('beforeend',`<div>${pl.text}</div>`);
  if(pl.image)div.insertAdjacentHTML('beforeend',`<img src="${pl.image}">`);
  div.insertAdjacentHTML('beforeend',`<div class="timestamp">${m.timestamp}</div>`);
  box.appendChild(div);
}

function renderPoll(p){
  const box=document.getElementById('chat');
  const wrap=document.createElement('div');
  wrap.className='poll';
  wrap.id='poll-'+p.id;
  wrap.innerHTML=`<h4>${p.question}</h4>`;
  p.options.forEach((opt,i)=>{
    const total=p.votes.reduce((a,b)=>a+b,0)||1;
    const percent=Math.round(p.votes[i]/total*100);
    const bar=`<div class="bar" style="width:${percent}%;"></div>`;
    const btn=document.createElement('button');
    btn.className='option-btn';
    btn.innerHTML=`${opt}<br>${bar}`;
    btn.disabled= (me in p.voters) || p.closed;
    btn.onclick=()=>vote(p.id,i);
    wrap.appendChild(btn);
  });
  box.appendChild(wrap);
}

// ============== network ==================================================
async function fetchNew(){
  if(!key)return;
  const res=await fetch('/messages');
  const data=await res.json();
  const box=document.getElementById('chat');
  const nearBottom=(box.scrollHeight-box.scrollTop-box.clientHeight)<50;

  if(data.length>lastRendered){
    for(const m of data.slice(lastRendered)){
      if(m.type==='poll'){renderPoll(m);}
      else{
        const pl=await decrypt(m);
        addChatBubble(m,pl);
      }
    }
    lastRendered=data.length;
    if(nearBottom)box.scrollTop=box.scrollHeight;
    ding.play();
  }
}

async function postChat(text,imgData){
  const encObj=await encrypt({text,image:imgData});
  encObj.username=me; encObj.timestamp=''; encObj.type='chat';
  await fetch('/',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(encObj)});
}

async function createPoll(){
  if(!me)return;
  const q=prompt('Poll question?')?.trim(); if(!q)return;
  const opts=[]; for(let i=1;i<=4;i++){
    const v=prompt('Option '+i+' (leave blank to finish):')?.trim();
    if(v)opts.push(v); else break;
  }
  if(opts.length<2)return alert('Need at least 2 options.');
  await fetch('/poll',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({question:q,options:opts,username:me})});
}

async function vote(id,idx){
  await fetch('/vote',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({poll_id:id,option:idx,username:me})});
}

// ============== sending handler ==========================================
async function sendMsg(e){
  e.preventDefault(); if(!key||!me)return;
  const f=new FormData(e.target);
  const text=f.get('text').trim(); const file=f.get('image');
  let img=null; if(file&&file.size)img=await fileToDataURL(file);
  if(!text&&!img)return;
  await postChat(text,img);
  e.target.reset();
}

// ============== startup prompts ==========================================
window.addEventListener('load',async()=>{
  let pass=''; while(!pass){pass=prompt('Enter shared pass‑phrase:')?.trim();}
  key=await deriveKey(pass);
  if(!me){ do{me=prompt('Enter display name:')?.trim();}while(!me); localStorage.setItem('me',me);}
  fetchNew(); setInterval(fetchNew,1000);
});
</script>
</head>
<body>
  <div class="chat-container" id="chat"></div>

  <form class="chat-input" onsubmit="sendMsg(event)" enctype="multipart/form-data">
    <input type="text" name="text" placeholder="Type a message…" required>
    <input type="file" name="image" accept="image/*">
    <button type="submit">Send</button>
    <button type="button" onclick="createPoll()">Poll</button>
  </form>
</body>
</html>
'''

# ---------------------------------------------------------------------
#                           Flask routes (chat)
# ---------------------------------------------------------------------
@app.route('/', methods=['GET','POST'])
@limiter.limit("30 per minute")
def chat():
    if request.method=='POST':
        if request_too_large():
            return 'Payload too large', 413
        m = request.get_json() or {}
        username = normalize_username(m.get('username'))
        cipher = m.get('cipher')
        iv = m.get('iv')
        if not username or not isinstance(cipher, str) or not isinstance(iv, str):
            return 'Invalid message', 400
        if len(cipher) > MAX_REQUEST_BYTES or len(iv) > 64:
            return 'Payload too large', 413
        payload = {
            'username': username,
            'cipher': cipher,
            'iv': iv,
            'timestamp': friendly_timestamp(),
            'type': 'chat',
        }
        conn = get_db()
        conn.execute(
            "INSERT INTO messages (type, payload, created_at) VALUES (?, ?, ?)",
            ('chat', json.dumps(payload), iso_now()),
        )
        conn.commit()
        conn.close()
        return '', 204
    return render_template_string(HTML)

# ---------------------------------------------------------------------
#                             continue …
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
#                         Poll & Vote endpoints
# ---------------------------------------------------------------------
@app.route('/poll', methods=['POST'])
@limiter.limit("10 per minute")
def new_poll():
    """
    Body: {question:str, options:[str], username:str}
    """
    if request_too_large():
        return 'Payload too large', 413
    data = request.get_json() or {}
    q = (data.get('question') or '').strip()
    opts = [o.strip() for o in data.get('options', []) if o and o.strip()]
    user = normalize_username(data.get('username'))
    if not user:
        return 'Invalid username', 400
    if len(q) == 0 or len(q) > MAX_TEXT_LENGTH:
        return 'Bad poll', 400
    if len(opts) < 2 or len(opts) > MAX_OPTIONS:
        return 'Bad poll', 400
    if any(len(opt) > MAX_OPTION_LENGTH for opt in opts):
        return 'Bad poll', 400

    now = datetime.utcnow()
    poll_payload = {
        'question': q,
        'options': json.dumps(opts),
        'votes': json.dumps([0] * len(opts)),
        'voters': json.dumps({}),
        'created_at': now.isoformat(),
        'created_by': user,
        'closed': 0,
        'expires_at': (now + POLL_DURATION).isoformat(),
    }
    conn = get_db()
    conn.execute(
        """
        INSERT INTO polls (question, options, votes, voters, created_at, created_by, closed, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            poll_payload['question'],
            poll_payload['options'],
            poll_payload['votes'],
            poll_payload['voters'],
            poll_payload['created_at'],
            poll_payload['created_by'],
            poll_payload['closed'],
            poll_payload['expires_at'],
        ),
    )
    conn.commit()
    conn.close()
    return '', 201


@app.route('/vote', methods=['POST'])
@limiter.limit("60 per minute")
def vote():
    """
    Body: {poll_id:int, option:int, username:str}
    """
    if request_too_large():
        return 'Payload too large', 413
    data = request.get_json() or {}
    poll_id = parse_int(data.get('poll_id'))
    idx = parse_int(data.get('option'))
    user = normalize_username(data.get('username'))
    if poll_id is None or idx is None:
        return 'Invalid poll or option', 400
    if not user:
        return 'Invalid username', 400

    conn = get_db()
    row = conn.execute("SELECT * FROM polls WHERE id = ?", (poll_id,)).fetchone()
    if row is None:
        conn.close()
        return 'Poll or option not found', 404
    if poll_is_expired(row) or row['closed']:
        conn.execute("UPDATE polls SET closed = 1 WHERE id = ?", (poll_id,))
        conn.commit()
        conn.close()
        return 'Poll closed', 409

    options = json.loads(row['options'])
    if not (0 <= idx < len(options)):
        conn.close()
        return 'Poll or option not found', 404

    votes = json.loads(row['votes'])
    voters = json.loads(row['voters'])
    previous = voters.get(user)
    if previous is not None:
        if previous == idx:
            conn.close()
            return '', 204  # same vote, nothing changes
        votes[previous] = max(votes[previous] - 1, 0)

    voters[user] = idx
    votes[idx] += 1
    conn.execute(
        "UPDATE polls SET votes = ?, voters = ? WHERE id = ?",
        (json.dumps(votes), json.dumps(voters), poll_id),
    )
    conn.commit()
    conn.close()
    return '', 204


@app.route('/poll/close', methods=['POST'])
@limiter.limit("10 per minute")
def close_poll():
    if request_too_large():
        return 'Payload too large', 413
    data = request.get_json() or {}
    poll_id = parse_int(data.get('poll_id'))
    user = normalize_username(data.get('username'))
    if poll_id is None or not user:
        return 'Invalid request', 400
    conn = get_db()
    row = conn.execute("SELECT created_by FROM polls WHERE id = ?", (poll_id,)).fetchone()
    if row is None:
        conn.close()
        return 'Poll not found', 404
    if row['created_by'] != user:
        conn.close()
        return 'Forbidden', 403
    conn.execute("UPDATE polls SET closed = 1 WHERE id = ?", (poll_id,))
    conn.commit()
    conn.close()
    return '', 204


# ---------------------------------------------------------------------
#                      Messages fetch (chat + polls)
# ---------------------------------------------------------------------
@app.route('/messages')
@limiter.limit("120 per minute")
def get_messages():
    conn = get_db()
    chat_rows = conn.execute("SELECT payload, created_at FROM messages").fetchall()
    poll_rows = conn.execute("SELECT * FROM polls").fetchall()

    chats = []
    for row in chat_rows:
        payload = json.loads(row['payload'])
        payload['timestamp'] = payload.get('timestamp') or datetime.fromisoformat(
            row['created_at']
        ).strftime('%I:%M %p')
        chats.append((row['created_at'], payload))

    polls = []
    for row in poll_rows:
        if poll_is_expired(row) and not row['closed']:
            conn.execute("UPDATE polls SET closed = 1 WHERE id = ?", (row['id'],))
            conn.commit()
            row = conn.execute("SELECT * FROM polls WHERE id = ?", (row['id'],)).fetchone()
        polls.append((row['created_at'], poll_row_to_payload(row)))

    combined = [item for _, item in sorted(chats + polls, key=lambda x: x[0])]
    conn.close()
    return jsonify(combined)


# ---------------------------------------------------------------------
#                               run
# ---------------------------------------------------------------------
if __name__ == '__main__':
    print('Server running at https://<YOUR‑PC‑IP>:5000')
    cert_path = BASE_DIR / 'cert.pem'
    key_path = BASE_DIR / 'key.pem'
    ssl_context = None
    if cert_path.exists() and key_path.exists():
        ssl_context = (str(cert_path), str(key_path))
    app.run(host='0.0.0.0',
            port=5000,
            ssl_context=ssl_context,
            debug=False)
