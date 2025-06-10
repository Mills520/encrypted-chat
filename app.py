from flask import Flask, request, jsonify, render_template_string
from datetime import datetime
import itertools

app = Flask(__name__)

messages = []                              # chat ciphertext or poll objects
poll_id_counter = itertools.count(1)       # unique poll IDs

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

async function deriveKey(p){const h=await crypto.subtle.digest('SHA-256',enc.encode(p));
  return crypto.subtle.importKey('raw',h,'AES-GCM',false,['encrypt','decrypt']);}
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
    btn.disabled= (me in p.voters);
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
def chat():
    if request.method=='POST':
        m=request.get_json() or {}
        m['timestamp']=datetime.now().strftime('%I:%M %p')
        messages.append(m)
        return '',204
    return render_template_string(HTML)

# ---------------------------------------------------------------------
#                             continue …
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
#                         Poll & Vote endpoints
# ---------------------------------------------------------------------
def find_poll(poll_id):
    for msg in messages:
        if msg.get('type') == 'poll' and msg.get('id') == poll_id:
            return msg
    return None

@app.route('/poll', methods=['POST'])
def new_poll():
    """
    Body: {question:str, options:[str], username:str}
    """
    data = request.get_json() or {}
    q = data.get('question', '').strip()
    opts = [o.strip() for o in data.get('options', []) if o.strip()]
    user = data.get('username', '').strip()
    if len(q) == 0 or len(opts) < 2:
        return 'Bad poll', 400

    poll_obj = {
        'type': 'poll',
        'id': next(poll_id_counter),
        'question': q,
        'options': opts,
        'votes': [0] * len(opts),   # parallel list counts
        'voters': {},               # username -> option index
        'timestamp': datetime.now().strftime('%I:%M %p'),
        'username': user            # who created it
    }
    messages.append(poll_obj)
    return '', 201


@app.route('/vote', methods=['POST'])
def vote():
    """
    Body: {poll_id:int, option:int, username:str}
    """
    data = request.get_json() or {}
    poll_id = int(data.get('poll_id', -1))
    idx = int(data.get('option', -1))
    user = data.get('username', '').strip()
    poll = find_poll(poll_id)
    if poll is None or not (0 <= idx < len(poll['options'])):
        return 'Poll or option not found', 404

    # Prevent double‑voting
    previous = poll['voters'].get(user)
    if previous is not None:
        if previous == idx:
            return '', 204  # same vote, nothing changes
        poll['votes'][previous] -= 1  # remove prior vote

    poll['voters'][user] = idx
    poll['votes'][idx] += 1
    return '', 204


# ---------------------------------------------------------------------
#                      Messages fetch (chat + polls)
# ---------------------------------------------------------------------
@app.route('/messages')
def get_messages():
    return jsonify(messages)


# ---------------------------------------------------------------------
#                               run
# ---------------------------------------------------------------------
if __name__ == '__main__':
    print('Server running at https://<YOUR‑PC‑IP>:5000')
    app.run(host='0.0.0.0',
            port=5000,
            ssl_context=('cert.pem', 'key.pem'),
            debug=True)