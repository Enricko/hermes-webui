"""Assigned-menu rendering lifecycle without loading personal Hermes state."""

import json
from pathlib import Path
import shutil
import subprocess

import pytest


def test_refresh_keeps_drawer_open_and_only_user_selection_closes_it():
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the real frontend lifecycle helper')
    source = Path(__file__).resolve().parents[1] / 'multiuser/static/client.js'
    script = r'''
const fs = require('fs'); const vm = require('vm');
class Element {
  constructor(tag) { this.tag=tag; this.children=[]; this.handlers={}; this.dataset={};
    this.classList={add(){},remove(){}}; }
  append(...nodes) { this.children.push(...nodes); }
  setAttribute(key,value) { this[key]=value; }
  addEventListener(key,handler) { this.handlers[key]=handler; }
}
let closes=0; const details=[];
const context={window:{}, document:{readyState:'loading',createElement:tag=>new Element(tag),
  addEventListener(){},querySelectorAll:()=>[]},
  _renderProfileDetail:p=>details.push(p),_closeMobileSidebarAfterPanelSelection:()=>closes++};
vm.createContext(context);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
const bridge=context.window.HermesAccountProfiles;
const first='a'.repeat(32),second='b'.repeat(32);
const data={account_profiles:[{id:first,name:'Assigned A'},{id:second,name:'Assigned B'}],
  account_profile_id:first,account_provider_label:'Owned provider',account_provider_configured:true,
  account_runtime_state:'ready',active:'default',
  profiles:[{name:'default',is_default:true,total_skills:37,enabled_skills:36,model:'runtime-model'}]};
const panel=new Element('div');
if(!bridge.render(panel,data))throw Error('Assigned menu was not rendered');
if(!bridge.refresh(first)||closes!==0)throw Error('Metadata refresh closed the drawer');
if(details[0].total_skills!==37||details[0].model!=='runtime-model')throw Error('Runtime statistics were replaced');
const cards=panel.children[0].children.filter(n=>n.dataset.accountProfile);
cards[0].handlers.click();
if(closes!==1)throw Error('User selection did not close the drawer');
cards[0].handlers.keydown({key:'Enter',preventDefault(){}});
if(closes!==2)throw Error('Keyboard selection did not close the drawer');
bridge.refresh(second);
const inactive=details.at(-1);
if(inactive.account_profile_active||inactive.model||inactive.total_skills)throw Error('Inactive runtime statistics were invented');
const count=details.length;
if(bridge.refresh('c'.repeat(32))||details.length!==count)throw Error('An unassigned profile was rendered');
if(bridge.render(new Element('div'),{profiles:[]})!==false)throw Error('Single-user rendering was overridden');
console.log(JSON.stringify({profiles:cards.map(n=>n.dataset.accountProfile),closes,realSkills:details[0].total_skills}));
'''
    result = subprocess.run([node, '-e', script, str(source)], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == {'profiles':['a' * 32, 'b' * 32], 'closes':2, 'realSkills':37}


@pytest.mark.parametrize('current,preferred,allowed,expected', [
    ('c', 'd', ['c', 'd'], 'c'),  # Keep the independently assigned current provider.
    ('e', 'd', ['c', 'd'], 'd'),  # Unavailable current provider: allowed profile default.
    ('e', 'f', ['c', 'd'], 'c'),  # Neither available: first allowed provider.
    ('e', 'f', [], None),        # No provider means no activation request.
])
def test_direct_activation_revalidates_grants_and_preserves_allowed_provider(current, preferred, allowed, expected):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for the real frontend lifecycle helper')
    source = Path(__file__).resolve().parents[1] / 'multiuser/static/client.js'
    script = r'''
const fs=require('fs'),vm=require('vm');
const cfg=JSON.parse(process.argv[2]),id=c=>c.repeat(32),posts=[],navigations=[];
let identity={csrf_token:'session-csrf',profile:{id:id('a')},provider:{id:id(cfg.current)},
  runtime:{state:'ready'},choices:{profiles:[{id:id('a'),name:'A'},{id:id('b'),name:'B',provider_id:id(cfg.preferred)}],
  providers:cfg.allowed.map(c=>({id:id(c),name:c}))}};
const context={window:{},document:{readyState:'loading',addEventListener(){},getElementById:()=>null},
  fetch:async (path,options)=>{
    if(path==='/multiuser/api/me')return {ok:true,json:async()=>identity};
    if(path!=='/multiuser/api/selection')throw Error('Unexpected endpoint');
    if(options.method!=='POST'||options.headers['X-Hermes-CSRF-Token']!=='session-csrf')throw Error('Missing CSRF');
    posts.push(JSON.parse(options.body));return {ok:true,json:async()=>({changed:true})};
  },localStorage:{clear(){}},sessionStorage:{clear(){}},location:{assign:p=>navigations.push(p)}};
vm.createContext(context);vm.runInContext(fs.readFileSync(process.argv[1],'utf8'),context);
(async()=>{
  const activate=context.window.HermesAccountProfiles.activate;
  if(cfg.expected){
    // Repeated click while the first operation is pending must not send twice.
    await Promise.all([activate(id('b')),activate(id('b'))]);
    if(posts.length!==1||posts[0].template_id!==id('b')||posts[0].provider_id!==id(cfg.expected))throw Error('Wrong selection');
    if(JSON.stringify(navigations)!=='["/"]')throw Error('No navigation to new runtime');
  }else{
    let rejected=false;try{await activate(id('b'));}catch(e){rejected=e.message.includes('assign an AI provider');}
    if(!rejected||posts.length)throw Error('No-provider activation did not fail closed');
  }
  const count=posts.length;
  let rejected=false;try{await activate(id('f'));}catch(e){rejected=e.message.includes('not assigned');}
  if(!rejected||posts.length!==count)throw Error('Unassigned profile accepted');
  // A refreshed revocation supersedes the previously displayed menu.
  identity={...identity,choices:{...identity.choices,profiles:[{id:id('a'),name:'A'}]}};
  rejected=false;try{await activate(id('b'));}catch(e){rejected=e.message.includes('not assigned');}
  if(!rejected||posts.length!==count)throw Error('Stale menu authorized a revoked profile');
  console.log(JSON.stringify({posts:posts.length}));
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
    config = dict(current=current, preferred=preferred, allowed=allowed, expected=expected)
    result = subprocess.run([node, '-e', script, str(source), json.dumps(config)], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == {'posts': 1 if expected else 0}
