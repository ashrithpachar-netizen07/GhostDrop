const $=s=>document.querySelector(s),app=$('#app');let fresh={};
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api=async(u,o={})=>{const r=await fetch(u,{credentials:'same-origin',...o,headers:{'X-Requested-With':'ghostdrop',...o.headers}});if(o.raw&&r.ok)return r;const d=await r.json().catch(()=>({}));if(!r.ok)throw Object.assign(new Error(d.error||'Something went wrong'),{status:r.status});return d};
const J=b=>({method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
const mb=n=>(n/1048576).toFixed(2)+' MB';
const ago=ms=>{const m=Math.round((ms-Date.now())/6e4);return m<=0?'now':m<60?m+'m':m<2880?Math.round(m/60)+'h':Math.round(m/1440)+'d'};
const toast=(m,bad)=>{const t=document.createElement('div');t.className='toast'+(bad?' bad':'');t.textContent=m;document.body.append(t);setTimeout(()=>t.remove(),3500)};
async function boot(){const m=location.pathname.match(/^\/d\/([\w-]+)/);if(m)return recv(m[1]);try{await api('/api/me');dash()}catch{login()}}
function login(){app.innerHTML=`<section class="card hero"><h1>👻 Ghostdrop</h1><p class=mut>Share files that vanish. Expiring, revocable, burn-after-N links.</p><input id=e type=email placeholder=Email><input id=p type=password placeholder="Password (8+ chars)"><div class=row><button id=li>Log in</button><button id=rg class=alt>Sign up</button></div></section>
 <div class=feat><div class=card>⏳<b>Auto-expiry</b><small>Links die in 1h–7d</small></div><div class=card>🔥<b>Burn after N</b><small>Cap downloads per link</small></div><div class=card>🔐<b>Hashed tokens</b><small>Leaked DB ≠ leaked links</small></div><div class=card>🛡️<b>Safe files</b><small>Magic-byte scanning</small></div></div>`;
 for(const[id,u]of[['li','login'],['rg','register']])$('#'+id).onclick=async()=>{try{await api('/api/'+u,J({email:$('#e').value,password:$('#p').value}));boot()}catch(e){toast(e.message,1)}}}
async function dash(){const me=await api('/api/me'),files=await api('/api/files');
 app.innerHTML=`<header><h2>👻 Ghostdrop</h2><span class=mut>${esc(me.email)} <button class=alt id=lo>Log out</button></span></header>
 <div class=card><label id=dz class=dz>Drop a file or click to upload · max ${mb(me.maxFile)}<input type=file id=f hidden></label><div class=bar><i style="width:${Math.min(100,me.used/me.quota*100)}%"></i></div><small>${mb(me.used)} / ${mb(me.quota)} used</small><div id=pg></div></div>
 ${files.map(f=>`<div class="card file" data-id=${f.id}><div class=top><div><b>${esc(f.name)}</b><br><small>${mb(f.size)} · ${f.links.reduce((a,l)=>a+l.downloads,0)} total downloads</small></div><button class=del data-del=${f.id}>Delete</button></div>
 ${fresh[f.id]?`<div class=fresh>🔗 Shown once — copy now:<br><b>${esc(fresh[f.id])}</b> <button data-copy="${esc(fresh[f.id])}">Copy</button></div>`:''}
 ${f.links.map(l=>`<div class="lk ${l.state}"><b>${l.state}</b>${l.locked?'🔒':''}${l.state=='active'?`expires in ${ago(l.expires)}`:''} · ${l.downloads}${l.max_dl?'/'+l.max_dl:''} downloads${l.state=='active'?`<button class=alt data-r=${l.id}>Revoke</button>`:''}</div>`).join('')}
 <div class=row><select class=h><option value=1>1 hour</option><option value=24 selected>24 hours</option><option value=168>7 days</option></select><input class=m type=number min=1 placeholder="Max downloads"><input class=w placeholder="Password (optional)"><button data-mk>+ Ghost link</button></div></div>`).join('')||'<p class=mut>No files yet — drop one above.</p>'}`;
 const up=file=>{if(!file)return;const x=new XMLHttpRequest(),d=new FormData();d.append('file',file);x.open('POST','/api/upload');x.setRequestHeader('X-Requested-With','ghostdrop');
  x.upload.onprogress=e=>$('#pg').textContent=`Uploading ${Math.round(e.loaded/e.total*100)}%`;
  x.onload=()=>{x.status==200?dash():toast(JSON.parse(x.responseText||'{}').error||'Upload failed',1);$('#pg').textContent=''};x.send(d)};
 $('#f').onchange=e=>up(e.target.files[0]);const dz=$('#dz');dz.ondragover=e=>{e.preventDefault();dz.classList.add('on')};dz.ondragleave=()=>dz.classList.remove('on');dz.ondrop=e=>{e.preventDefault();dz.classList.remove('on');up(e.dataTransfer.files[0])};
 $('#lo').onclick=async()=>{await api('/api/logout',{method:'POST'});fresh={};login()}}
document.addEventListener('click',async e=>{const t=e.target,c=t.closest('.file');try{
 if(t.dataset.del!=null){if(confirm('Delete file and kill all its links?')){await api('/api/files/'+t.dataset.del,{method:'DELETE'});dash()}}
 else if(t.dataset.r){await api('/api/links/'+t.dataset.r+'/revoke',{method:'POST'});dash()}
 else if(t.dataset.copy){await navigator.clipboard.writeText(t.dataset.copy);toast('Copied')}
 else if(t.dataset.mk!=null){const id=c.dataset.id,r=await api(`/api/files/${id}/links`,J({hours:c.querySelector('.h').value,maxDl:c.querySelector('.m').value,password:c.querySelector('.w').value}));fresh[id]=r.url;dash()}
}catch(err){toast(err.message,1)}});
async function recv(t){app.innerHTML='<section class="card hero" id=r>Loading…</section>';
 try{const i=await api('/api/s/'+t);$('#r').innerHTML=`<h1>📦</h1><h2>${esc(i.name)}</h2><p class=mut>${mb(i.size)} · expires in ${ago(i.expires)}${i.left!=null?` · ${i.left} download(s) left`:''}</p>${i.locked?'<input id=p type=password placeholder=Password>':''}<button id=dl>Download</button>`;
  $('#dl').onclick=async()=>{try{const r=await api(`/api/s/${t}/download`,{...J({password:$('#p')?.value}),raw:1}),a=document.createElement('a');a.href=URL.createObjectURL(await r.blob());a.download=i.name;a.click();toast('Downloaded ✔')}catch(e){toast(e.message,1)}}}
 catch(e){$('#r').innerHTML=`<h1>${e.status==410?'💨':'🚫'}</h1><h2>${e.status==410?'Link unavailable':'Link not found'}</h2><p class=mut>${esc(e.message)}</p>`}}
boot();
