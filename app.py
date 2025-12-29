from flask import Flask, request, jsonify, render_template_string
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import json
import sqlite3
from pathlib import Path
import secrets

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'chat.db'

MAX_REQUEST_BYTES = 1_000_000
MAX_CIPHER_LENGTH = 200_000
MAX_TEXT_LENGTH = 2000
MAX_USERNAME_LENGTH = 40
MAX_OPTIONS = 6
MAX_OPTION_LENGTH = 120
POLL_DURATION = timedelta(hours=6)
SESSION_TTL = timedelta(hours=12)

app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_BYTES

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["120 per minute"],
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def request_too_large():
    content_length = request.content_length
    return content_length is not None and content_length > MAX_REQUEST_BYTES


def iso_now():
    return datetime.utcnow().isoformat()


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
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            closed INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS poll_options (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poll_id INTEGER NOT NULL,
            option_index INTEGER NOT NULL,
            option_text TEXT NOT NULL,
            UNIQUE (poll_id, option_index),
            FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS poll_votes (
            poll_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            option_index INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (poll_id, username),
            FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS sessions (
            username TEXT PRIMARY KEY,
            token TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );
        """
    )
    poll_columns = {row["name"] for row in conn.execute("PRAGMA table_info(polls)").fetchall()}
    if "updated_at" not in poll_columns:
        conn.execute("ALTER TABLE polls ADD COLUMN updated_at TEXT")
        conn.execute("UPDATE polls SET updated_at = created_at WHERE updated_at IS NULL")
    if {"options", "votes", "voters"}.issubset(poll_columns):
        options_count = conn.execute("SELECT COUNT(*) FROM poll_options").fetchone()[0]
        if options_count == 0:
            for row in conn.execute("SELECT * FROM polls").fetchall():
                options = json.loads(row["options"])
                for idx, option_text in enumerate(options):
                    conn.execute(
                        "INSERT OR IGNORE INTO poll_options (poll_id, option_index, option_text) VALUES (?, ?, ?)",
                        (row["id"], idx, option_text),
                    )
                voters = json.loads(row["voters"])
                for username, option_index in voters.items():
                    conn.execute(
                        "INSERT OR IGNORE INTO poll_votes (poll_id, username, option_index, created_at) VALUES (?, ?, ?, ?)",
                        (row["id"], username, option_index, row["created_at"]),
                    )
    cutoff = (datetime.utcnow() - SESSION_TTL).isoformat()
    conn.execute("DELETE FROM sessions WHERE last_seen < ?", (cutoff,))
    conn.commit()
    conn.close()


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


def poll_is_expired(row):
    return datetime.fromisoformat(row['expires_at']) <= datetime.utcnow()


def fetch_poll_options(conn, poll_id):
    rows = conn.execute(
        "SELECT option_index, option_text FROM poll_options WHERE poll_id = ? ORDER BY option_index",
        (poll_id,),
    ).fetchall()
    return [row["option_text"] for row in rows]


def fetch_poll_votes(conn, poll_id, option_count):
    rows = conn.execute(
        "SELECT option_index, COUNT(*) as total FROM poll_votes WHERE poll_id = ? GROUP BY option_index",
        (poll_id,),
    ).fetchall()
    counts = [0] * option_count
    for row in rows:
        if 0 <= row["option_index"] < option_count:
            counts[row["option_index"]] = row["total"]
    return counts


def poll_row_to_payload(conn, row):
    options = fetch_poll_options(conn, row["id"])
    votes = fetch_poll_votes(conn, row["id"], len(options))
    voters = {
        vote["username"]: vote["option_index"]
        for vote in conn.execute(
            "SELECT username, option_index FROM poll_votes WHERE poll_id = ?",
            (row["id"],),
        ).fetchall()
    }
    return {
        "type": "poll",
        "id": row["id"],
        "question": row["question"],
        "options": options,
        "votes": votes,
        "voters": voters,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "username": row["created_by"],
        "closed": bool(row["closed"]),
        "expires_at": row["expires_at"],
        "sort_at": row["updated_at"],
    }


def ensure_session(conn, username, token):
    if not token or not isinstance(token, str):
        return False
    row = conn.execute(
        "SELECT token, last_seen FROM sessions WHERE username = ?", (username,)
    ).fetchone()
    if row is None or row["token"] != token:
        return False
    cutoff = datetime.utcnow() - SESSION_TTL
    if datetime.fromisoformat(row["last_seen"]) < cutoff:
        conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
        return False
    conn.execute(
        "UPDATE sessions SET last_seen = ? WHERE username = ?",
        (iso_now(), username),
    )
    return True


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
let key=null;
let lastSeenAt=null;
let me=localStorage.getItem('me')||null;   // saved display‑name
let token=localStorage.getItem('token')||null;

const KDF_SALT='encrypted-chat-salt-v1';
const KDF_ITERATIONS=120000;
const MAX_TEXT_LENGTH=2000;
const MAX_IMAGE_BYTES=300000;
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
  const meta=document.createElement('div');
  meta.className='meta';
  meta.textContent=isMe?'You':m.username;
  div.appendChild(meta);
  if(pl.text){
    const text=document.createElement('div');
    text.textContent=pl.text;
    div.appendChild(text);
  }
  if(pl.image){
    const img=document.createElement('img');
    img.src=pl.image;
    div.appendChild(img);
  }
  const timestamp=document.createElement('div');
  timestamp.className='timestamp';
  timestamp.textContent=formatTime(m.created_at);
  div.appendChild(timestamp);
  box.appendChild(div);
}

function renderPoll(p){
  const box=document.getElementById('chat');
  let wrap=document.getElementById('poll-'+p.id);
  if(!wrap){
    wrap=document.createElement('div');
    wrap.className='poll';
    wrap.id='poll-'+p.id;
    box.appendChild(wrap);
  }
  wrap.innerHTML='';
  const heading=document.createElement('h4');
  heading.textContent=p.question;
  wrap.appendChild(heading);
  p.options.forEach((opt,i)=>{
    const total=p.votes.reduce((a,b)=>a+b,0)||1;
    const percent=Math.round(p.votes[i]/total*100);
    const btn=document.createElement('button');
    btn.className='option-btn';
    const label=document.createElement('div');
    label.textContent=opt;
    const bar=document.createElement('div');
    bar.className='bar';
    bar.style.width=`${percent}%`;
    btn.appendChild(label);
    btn.appendChild(bar);
    btn.disabled= (me in p.voters) || p.closed;
    btn.onclick=()=>vote(p.id,i);
    wrap.appendChild(btn);
  });
}

// ============== network ==================================================
async function fetchNew(){
  if(!key)return;
  const url=lastSeenAt?`/messages?since=${encodeURIComponent(lastSeenAt)}`:'/messages';
  const res=await fetch(url);
  const data=await res.json();
  const box=document.getElementById('chat');
  const nearBottom=(box.scrollHeight-box.scrollTop-box.clientHeight)<50;

  if(data.length){
    for(const m of data){
      if(m.type==='poll'){
        renderPoll(m);
      }else{
        const pl=await decrypt(m);
        addChatBubble(m,pl);
      }
    }
    lastSeenAt=data[data.length-1].sort_at;
    if(nearBottom)box.scrollTop=box.scrollHeight;
    ding.play();
  }
}

async function postChat(text,imgData){
  const encObj=await encrypt({text,image:imgData});
  encObj.username=me; encObj.type='chat'; encObj.token=token;
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
    body:JSON.stringify({question:q,options:opts,username:me,token})});
}

async function vote(id,idx){
  await fetch('/vote',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({poll_id:id,option:idx,username:me,token})});
}

// ============== sending handler ==========================================
async function sendMsg(e){
  e.preventDefault(); if(!key||!me)return;
  const f=new FormData(e.target);
  const text=f.get('text').trim(); const file=f.get('image');
  if(text.length>MAX_TEXT_LENGTH)return alert('Message is too long.');
  if(file&&file.size>MAX_IMAGE_BYTES)return alert('Image is too large.');
  let img=null; if(file&&file.size)img=await fileToDataURL(file);
  if(!text&&!img)return;
  await postChat(text,img);
  e.target.reset();
}

function formatTime(iso){
  if(!iso)return '';
  const date=new Date(iso+'Z');
  return date.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
}

async function ensureSession(){
  while(true){
    const res=await fetch('/session',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:me})});
    if(res.status===201){
      const data=await res.json();
      token=data.token;
      localStorage.setItem('token',token);
      return;
    }
    if(res.status===409){
      me=null;
      localStorage.removeItem('me');
      const name=prompt('Name is in use. Choose another display name:')?.trim();
      if(name){
        me=name;
        localStorage.setItem('me',me);
      }
      continue;
    }
    throw new Error('Failed to start session.');
  }
}

// ============== startup prompts ==========================================
window.addEventListener('load',async()=>{
  let pass=''; while(!pass){pass=prompt('Enter shared pass‑phrase:')?.trim();}
  key=await deriveKey(pass);
  if(!me){ do{me=prompt('Enter display name:')?.trim();}while(!me); localStorage.setItem('me',me);}
  await ensureSession();
  fetchNew(); setInterval(fetchNew,1000);
});
</script>
</head>
<body>
  <div class="chat-container" id="chat"></div>

  <form class="chat-input" onsubmit="sendMsg(event)" enctype="multipart/form-data">
    <input type="text" name="text" placeholder="Type a message…">
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
        token = m.get('token')
        if not username or not isinstance(cipher, str) or not isinstance(iv, str):
            return 'Invalid message', 400
        if len(cipher) > MAX_CIPHER_LENGTH or len(iv) > 64:
            return 'Payload too large', 413
        payload = {
            'username': username,
            'cipher': cipher,
            'iv': iv,
            'type': 'chat',
        }
        conn = get_db()
        if not ensure_session(conn, username, token):
            conn.close()
            return 'Unauthorized', 403
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
#                             Sessions
# ---------------------------------------------------------------------
@app.route('/session', methods=['POST'])
@limiter.limit("20 per minute")
def create_session():
    if request_too_large():
        return 'Payload too large', 413
    data = request.get_json() or {}
    username = normalize_username(data.get('username'))
    if not username:
        return 'Invalid username', 400
    conn = get_db()
    row = conn.execute(
        "SELECT token, last_seen FROM sessions WHERE username = ?",
        (username,),
    ).fetchone()
    cutoff = datetime.utcnow() - SESSION_TTL
    if row is not None and datetime.fromisoformat(row["last_seen"]) >= cutoff:
        conn.close()
        return 'Username already in use', 409
    if row is not None:
        conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
    token = secrets.token_urlsafe(32)
    now = iso_now()
    conn.execute(
        "INSERT INTO sessions (username, token, created_at, last_seen) VALUES (?, ?, ?, ?)",
        (username, token, now, now),
    )
    conn.commit()
    conn.close()
    return jsonify({"token": token}), 201


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
    token = data.get('token')
    if not user:
        return 'Invalid username', 400
    if len(q) == 0 or len(q) > MAX_TEXT_LENGTH:
        return 'Bad poll', 400
    if len(opts) < 2 or len(opts) > MAX_OPTIONS:
        return 'Bad poll', 400
    if any(len(opt) > MAX_OPTION_LENGTH for opt in opts):
        return 'Bad poll', 400

    now_dt = datetime.utcnow()
    now = now_dt.isoformat()
    expires_at = (now_dt + POLL_DURATION).isoformat()
    conn = get_db()
    if not ensure_session(conn, user, token):
        conn.close()
        return 'Unauthorized', 403
    conn.execute(
        """
        INSERT INTO polls (question, created_at, created_by, closed, expires_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            q,
            now,
            user,
            0,
            expires_at,
            now,
        ),
    )
    poll_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    for idx, option_text in enumerate(opts):
        conn.execute(
            "INSERT INTO poll_options (poll_id, option_index, option_text) VALUES (?, ?, ?)",
            (poll_id, idx, option_text),
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
    token = data.get('token')
    if poll_id is None or idx is None:
        return 'Invalid poll or option', 400
    if not user:
        return 'Invalid username', 400

    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if not ensure_session(conn, user, token):
            conn.rollback()
            return 'Unauthorized', 403
        row = conn.execute("SELECT * FROM polls WHERE id = ?", (poll_id,)).fetchone()
        if row is None:
            conn.rollback()
            return 'Poll or option not found', 404
        if poll_is_expired(row) or row['closed']:
            conn.execute(
                "UPDATE polls SET closed = 1, updated_at = ? WHERE id = ?",
                (iso_now(), poll_id),
            )
            conn.commit()
            return 'Poll closed', 409

        option_count = conn.execute(
            "SELECT COUNT(*) FROM poll_options WHERE poll_id = ?",
            (poll_id,),
        ).fetchone()[0]
        if not (0 <= idx < option_count):
            conn.rollback()
            return 'Poll or option not found', 404

        existing = conn.execute(
            "SELECT option_index FROM poll_votes WHERE poll_id = ? AND username = ?",
            (poll_id, user),
        ).fetchone()
        if existing is not None and existing["option_index"] == idx:
            conn.rollback()
            return '', 204

        conn.execute(
            "DELETE FROM poll_votes WHERE poll_id = ? AND username = ?",
            (poll_id, user),
        )
        conn.execute(
            "INSERT INTO poll_votes (poll_id, username, option_index, created_at) VALUES (?, ?, ?, ?)",
            (poll_id, user, idx, iso_now()),
        )
        conn.execute(
            "UPDATE polls SET updated_at = ? WHERE id = ?",
            (iso_now(), poll_id),
        )
        conn.commit()
        return '', 204
    finally:
        conn.close()


@app.route('/poll/close', methods=['POST'])
@limiter.limit("10 per minute")
def close_poll():
    if request_too_large():
        return 'Payload too large', 413
    data = request.get_json() or {}
    poll_id = parse_int(data.get('poll_id'))
    user = normalize_username(data.get('username'))
    token = data.get('token')
    if poll_id is None or not user:
        return 'Invalid request', 400
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        if not ensure_session(conn, user, token):
            conn.rollback()
            return 'Unauthorized', 403
        row = conn.execute("SELECT created_by FROM polls WHERE id = ?", (poll_id,)).fetchone()
        if row is None:
            conn.rollback()
            return 'Poll not found', 404
        if row['created_by'] != user:
            conn.rollback()
            return 'Forbidden', 403
        conn.execute(
            "UPDATE polls SET closed = 1, updated_at = ? WHERE id = ?",
            (iso_now(), poll_id),
        )
        conn.commit()
        return '', 204
    finally:
        conn.close()


# ---------------------------------------------------------------------
#                      Messages fetch (chat + polls)
# ---------------------------------------------------------------------
@app.route('/messages')
@limiter.limit("120 per minute")
def get_messages():
    conn = get_db()
    now = iso_now()
    conn.execute(
        "UPDATE polls SET closed = 1, updated_at = ? WHERE closed = 0 AND expires_at <= ?",
        (now, now),
    )
    since = request.args.get("since")
    since_value = None
    if since:
        try:
            datetime.fromisoformat(since)
            since_value = since
        except ValueError:
            since_value = None

    if since_value:
        chat_rows = conn.execute(
            "SELECT payload, created_at FROM messages WHERE created_at > ? ORDER BY created_at",
            (since_value,),
        ).fetchall()
        poll_rows = conn.execute(
            "SELECT * FROM polls WHERE updated_at > ? ORDER BY updated_at",
            (since_value,),
        ).fetchall()
    else:
        chat_rows = conn.execute(
            "SELECT payload, created_at FROM messages ORDER BY created_at"
        ).fetchall()
        poll_rows = conn.execute(
            "SELECT * FROM polls ORDER BY updated_at"
        ).fetchall()

    chats = []
    for row in chat_rows:
        payload = json.loads(row['payload'])
        payload['created_at'] = row['created_at']
        payload['sort_at'] = row['created_at']
        chats.append((row['created_at'], payload))

    polls = []
    for row in poll_rows:
        polls.append((row['updated_at'], poll_row_to_payload(conn, row)))

    combined = [item for _, item in sorted(chats + polls, key=lambda x: x[0])]
    conn.commit()
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
