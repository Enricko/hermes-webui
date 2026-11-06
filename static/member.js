'use strict';
(() => {
  const $ = id => document.getElementById(id), root = new URL('./', location.href);
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  let catalog, current = null, folder = '', file = null, busy = false;
  const pending = new Set();
  const node = (tag, text) => { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; return element; };
  function notice(text, error=false) { $('notice').textContent = text; $('notice').className = error ? 'error' : 'success'; }
  async function api(path, body) {
    const controller = new AbortController(); pending.add(controller);
    try {
      const response = await fetch(new URL('api/' + path, root), {cache:'no-store',credentials:'same-origin',signal:controller.signal,
        headers:{'Content-Type':'application/json','X-Hermes-CSRF-Token':csrf}, ...(body ? {method:'POST',body:JSON.stringify(body)} : {})});
      if (response.status === 401) { location.replace(new URL('login',root)); throw new Error('Please sign in again.'); }
      const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Request failed.'); return data;
    } finally { pending.delete(controller); }
  }
  function context() { return {profile_id:$('profile').value,workspace_id:$('workspace').value,connection_id:$('connection').value,
    model:$('model').value,skills:[...$('skills').querySelectorAll('input:checked')].map(input=>input.value)}; }
  function models() {
    const resource = catalog.resources.find(item=>item.id === $('connection').value);
    $('model').replaceChildren(...(resource?.models || []).map(model=>{const option=node('option',model);option.value=model;return option;}));
  }
  function selectContext(value) {
    for (const [id,field] of [['profile','profile_id'],['workspace','workspace_id'],['connection','connection_id']]) $(id).value=value[field];
    models(); $('model').value=value.model;
    $('skills').querySelectorAll('input').forEach(input=>{input.checked=value.skills.includes(input.value);});
  }
  function controls() { document.querySelectorAll('main button, main input, main select, main textarea').forEach(element=>{element.disabled=busy;}); }
  async function action(fn) {
    if (busy) return; busy=true; controls();
    try { await fn(); } catch(error) { if(error.name!=='AbortError') notice(error.message,true); }
    finally {busy=false;controls();}
  }
  function showConversation(data) {
    current=data; $('conversation-title').textContent=data.title || 'New conversation'; $('messages').replaceChildren();
    for(const message of data.messages || []) {
      const row=node('div');row.className='message ' + (message.role==='user'?'user':'assistant');
      row.append(node('strong',message.role==='user'?'You':'Assistant'),node('div',message.content));$('messages').append(row);
    }
    if(data.context) selectContext(data.context);
    $('messages').scrollTop=$('messages').scrollHeight;
  }
  async function conversations() {
    const result=await api('member/conversations');$('conversations').replaceChildren();
    for(const conversation of result.conversations) {
      const button=node('button',conversation.title);button.type='button';
      button.addEventListener('click',()=>action(async()=>{showConversation(await api('member/conversation?id='+encodeURIComponent(conversation.id)));folder='';await files();}));
      $('conversations').append(button);
    }
  }
  async function files() {
    if(!context().workspace_id || !context().profile_id || !context().connection_id || !context().model) return;
    const result=await api('member/files',{action:'list',context:context(),path:folder});
    $('folder').textContent='/'+folder;$('files').replaceChildren();file=null;$('file-preview').hidden=true;
    for(const entry of result.files) {
      const button=node('button',(entry.directory?'▸ ':'')+entry.name);button.type='button';
      button.addEventListener('click',()=>action(async()=>{
        const path=folder?folder+'/'+entry.name:entry.name;
        if(entry.directory){folder=path;await files();return;}
        const result=await api('member/files',{action:'read',context:context(),path});
        file={name:entry.name,content:result.content};$('file-name').textContent=entry.name;
        const bytes=Uint8Array.from(atob(result.content),character=>character.charCodeAt(0));
        $('file-content').value=new TextDecoder().decode(bytes);$('file-content').readOnly=true;$('file-preview').hidden=false;
      }));$('files').append(button);
    }
    if(!result.files.length)$('files').append(node('p','This folder is empty.'));
  }
  $('composer').addEventListener('submit',event=>{event.preventDefault();action(async()=>{
    const message=$('message').value;
    if(!current) current=await api('member/conversations',context());
    // Existing conversations retain their original, server-authorized selection.
    // Choose New conversation to use a different profile/connection/skill set.
    if(JSON.stringify({...context(),skills:context().skills.slice().sort()})!==JSON.stringify({
      profile_id:current.context.profile_id,workspace_id:current.context.workspace_id,connection_id:current.context.connection_id,
      model:current.context.model,skills:current.context.skills.slice().sort()})) throw new Error('Start a new conversation to change its selections.');
    notice('Generating a response…');await api('member/chat',{conversation_id:current.id,message});
    $('message').value='';showConversation(await api('member/conversation?id='+encodeURIComponent(current.id)));await conversations();notice('Response received.');
  });});
  $('new').addEventListener('click',()=>{if(!busy){current=null;$('messages').replaceChildren();$('conversation-title').textContent='New conversation';$('message').value='';}});
  $('connection').addEventListener('change',models);
  $('workspace').addEventListener('change',()=>{folder='';action(files);});
  $('profile').addEventListener('change',()=>action(files));
  $('up').addEventListener('click',()=>action(async()=>{folder=folder.split('/').slice(0,-1).join('/');await files();}));
  $('refresh-files').addEventListener('click',()=>action(files));
  $('folder-form').addEventListener('submit',event=>{event.preventDefault();action(async()=>{
    const name=$('folder-name').value;if(name.includes('/')||name.includes('\\')||name==='.'||name==='..')throw new Error('Enter a single folder name.');
    await api('member/files',{action:'mkdir',context:context(),path:folder?folder+'/'+name:name});$('folder-name').value='';await files();
  });});
  $('upload').addEventListener('change',()=>action(async()=>{
    const chosen=$('upload').files[0];if(!chosen)return;if(chosen.size>2*1024*1024)throw new Error('Choose a file up to 2 MiB.');
    const bytes=new Uint8Array(await chosen.arrayBuffer());let binary='';for(let offset=0;offset<bytes.length;offset+=32768)binary+=String.fromCharCode(...bytes.subarray(offset,offset+32768));
    await api('member/files',{action:'write',context:context(),path:folder?folder+'/'+chosen.name:chosen.name,content:btoa(binary)});$('upload').value='';await files();notice('File uploaded.');
  }));
  $('download').addEventListener('click',()=>{
    if(!file)return;const bytes=Uint8Array.from(atob(file.content),character=>character.charCodeAt(0));
    const url=URL.createObjectURL(new Blob([bytes],{type:'application/octet-stream'}));const link=node('a');link.href=url;link.download=file.name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
  $('logout').addEventListener('click',async()=>{
    pending.forEach(controller=>controller.abort());$('messages').replaceChildren();$('conversations').replaceChildren();$('files').replaceChildren();$('file-content').value='';$('message').value='';current=null;file=null;
    try{await api('auth/logout',{});}finally{location.replace(new URL('login',root));}
  });
  async function start(){
    catalog=await api('member/catalog');$('identity').textContent=catalog.username;$('admin-link').hidden=catalog.role!=='admin';
    for(const [id,kind] of [['profile','profile'],['workspace','workspace'],['connection','connection']]) {
      $(id).replaceChildren(...catalog.resources.filter(resource=>resource.kind===kind).map(resource=>{const option=node('option',resource.label);option.value=resource.id;return option;}));
    }
    for(const skill of catalog.resources.filter(resource=>resource.kind==='skill')) {
      const label=node('label');label.className='check';const input=node('input');input.type='checkbox';input.value=skill.id;input.checked=true;label.append(input,node('span',skill.label));$('skills').append(label);
    }
    models();await conversations();await files();notice(catalog.resources.length?'Your workspace is ready.':'Ask your administrator to assign a profile, workspace and provider/model.');
  }
  start().catch(error=>notice(error.message,true));
})();
