const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const {EventEmitter} = require('node:events');

function harness(platform = 'linux', remoteName = 'ssh-remote', auto = null) {
  const commands = new Map(), calls = [], timers = new Map(), warnings = [];
  let counter = 0;
  let stateChanged;
  const watcher = new EventEmitter(); watcher.close=()=>{};
  const item = {show(){}, dispose(){}};
  const vscode = {
    env: {remoteName}, workspace: {isTrusted: true}, StatusBarAlignment: {Right: 1},
    commands: {registerCommand(id, fn) { commands.set(id,fn); return {dispose(){}}; }},
    window: {createOutputChannel(){return {clear(){},appendLine(){},show(){},dispose(){}}},
      createStatusBarItem(){return item}, async showWarningMessage(text){warnings.push(text)},
      async showInformationMessage(){}, async showQuickPick(){return []}}
  };
  function spawn(file,args,options) {
    calls.push({file,args,options});
    const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stdout.setEncoding=()=>{};
    child.stderr={resume(){}}; child.stdin = new EventEmitter();
    child.stdin.end=() => queueMicrotask(() => {
      child.stdout.emit('data',JSON.stringify({ok:true,result:{auto,items:[],eligible:[]}})); child.emit('close',0);
    }); return child;
  }
  const output = {exports:{}};
  const sandbox = {exports:output.exports, module:output, process:{platform,arch:'arm64'},
    require(n){if(n==='vscode')return vscode;if(n==='node:child_process')return {spawn};if(n==='node:fs')return {lstatSync(){return {isFile:()=>true,isSymbolicLink:()=>false,mode:0o755,size:100}},readFileSync(){return JSON.stringify({auto})},watch(_dir,cb){stateChanged=cb;return watcher}};return require(n)},
    setTimeout(fn,ms){timers.set(++counter,{fn,ms});return counter},clearTimeout(id){timers.delete(id)},Date,console};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../dist/extension.js'),'utf8'),sandbox);
  const context={extensionPath:'/fixed/extension',subscriptions:[]};
  return {api:output.exports,context,commands,calls,timers,warnings,vscode,
    changeAuto(value){auto=value;stateChanged('rename','state.json')},
    async fire(id){const value=timers.get(id);timers.delete(id);await value.fn()}};
}
const flush = () => new Promise(resolve=>setImmediate(resolve));

test('only Linux Remote-SSH can run deletion',()=>{
  const {api}=harness();
  assert.equal(api.supported('linux','ssh-remote'),true);
  for(const [p,r] of [['win32','ssh-remote'],['linux','wsl'],['linux',undefined],['darwin','ssh-remote']])assert.equal(api.supported(p,r),false);
});
test('24 hour schedule, overdue reconnect and invalid schedule',()=>{
  const {api}=harness();
  assert.equal(api.nextDelay(null,0,true),undefined);
  assert.equal(api.nextDelay({next_at:86400,suspended:null},0,true),86400000);
  assert.equal(api.nextDelay({next_at:1,suspended:null},2000,true),60000);
  assert.equal(api.nextDelay({next_at:1,suspended:null},2000,false),1000);
  assert.equal(api.nextDelay({next_at:NaN,suspended:null},0,true),undefined);
  assert.equal(api.nextDelay({next_at:0,suspended:'changed'},0,true),undefined);
});
test('Windows client activation never starts the engine',async()=>{
  const h=harness('win32');h.api.activate(h.context);await flush();assert.equal(h.calls.length,0);
  await h.commands.get('remotePrune.preview')();assert.equal(h.calls.length,0);
});
test('untrusted workspace cannot invoke engine',async()=>{
  const h=harness();h.vscode.workspace.isTrusted=false;h.api.activate(h.context);await flush();assert.equal(h.calls.length,0);
});
test('default activation uses cheap status only and has no automatic scan',async()=>{
  const h=harness();h.api.activate(h.context);await flush();
  assert.equal(h.calls.length,1);assert.equal(h.calls[0].args[0],'status');assert.equal(h.timers.size,0);
  assert.equal(h.calls[0].file,path.join('/fixed/extension','bin','linux-arm64','engine'));
  assert.equal(h.calls[0].options.shell,undefined);
  assert.equal(h.calls[0].options.env.PATH,'/usr/bin:/bin');
});
test('reconnect waits sixty seconds and disposal cancels scheduling',async()=>{
  const h=harness('linux','ssh-remote',{next_at:1,suspended:null});h.api.activate(h.context);await flush();
  assert.equal([...h.timers.values()][0].ms,60000);
  for(const disposable of h.context.subscriptions)disposable.dispose();
  assert.equal(h.timers.size,0);
});
test('manual preview never invokes delete and enable cancellation remains disabled',async()=>{
  const h=harness();h.api.activate(h.context);await flush();
  await h.commands.get('remotePrune.preview')();
  await h.commands.get('remotePrune.enableAuto')();
  assert.equal(h.calls.some(x=>x.args[0]==='cleanup'||x.args[0]==='enable-auto'),false);
});
test('workspace configuration cannot enable automatic deletion',()=>{
  const manifest=require('../package.json');
  assert.equal(manifest.contributes.configuration,undefined);
  assert.deepEqual(manifest.extensionKind,['workspace']);
});
test('another window enabling or disabling auto updates schedule without a directory scan',async()=>{
  const h=harness();h.api.activate(h.context);await flush();
  h.changeAuto({next_at:Date.now()/1000+86400,suspended:''});
  await h.fire([...h.timers.keys()][0]);await flush();
  assert.equal(h.timers.size,1);
  assert.equal(h.calls.every(c=>c.args[0]==='status'),true);
  h.changeAuto(null);const id=[...h.timers.entries()].find(([,v])=>v.ms===200)[0];
  await h.fire(id);await flush();assert.equal(h.timers.size,0);
});
