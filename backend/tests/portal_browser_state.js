"use strict";
// Isolated fixture: public account status never renders subscriptions or usage.
const vm=require("node:vm"),fs=require("node:fs"),assert=require("node:assert/strict");
const scriptPath=process.argv[2],markup=fs.readFileSync(scriptPath.replace(/app\.js$/,"index.html"),"utf8");
const allowedIds=new Set([...markup.matchAll(/\bid="([^"]+)"/g)].map(match=>match[1]));
const elements=new Map(),requests=[];
function element(id){
 assert.ok(allowedIds.has(id),"Removed or missing element referenced: "+id);
 if(!elements.has(id))elements.set(id,{hidden:false,value:"",textContent:"",dataset:{},listeners:{},attributes:{},
  addEventListener(name,fn){this.listeners[name]=fn;},querySelectorAll(){return [];},reset(){this.value="";},focus(){},
  setAttribute(key,value){this.attributes[key]=value;}});
 return elements.get(id);
}
const origin="https://203.0.113.10:9443",token="a".repeat(43);
const document={getElementById:element,cookie:"__Secure-dazzle_csrf="+"c".repeat(43)};
const context=vm.createContext({document,setTimeout:()=>0,clearTimeout:()=>{},
 fetch:(url,options)=>new Promise(resolve=>requests.push({url,options,resolve})),console});
vm.runInContext(fs.readFileSync(scriptPath,"utf8"),context);
const reply=(index,data)=>requests[index].resolve({json:async()=>({ok:true,data})});
// Extra legacy response fields must stay out of the public DOM.
const account={account:{id:"self",email:"private@example.test",nickname:"<script>untrusted</script>",status:"active",
 quota_bytes:100000000000,used_upload:12000000,used_download:34000000,expires_at:"2026-12-01T00:00:00Z"},
 subscriptions:{clash:origin+"/"+token+"/config.yaml",shadowrocket:origin+"/"+token+"/nodes.txt"}};
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function assertPublicOnly(){
 const rendered=JSON.stringify([...elements.values()].map(value=>({value:value.value,textContent:value.textContent,attributes:value.attributes})));
 assert.ok(!rendered.includes(token));
 assert.ok(!rendered.includes("config.yaml"));
 assert.ok(!rendered.includes("nodes.txt"));
 assert.ok(!rendered.includes("100000000000"));
 for(const id of ["clash-link","shadowrocket-link","config-content","qr-dialog","used","quota","usage-arc"]){
  assert.ok(!allowedIds.has(id),"Private or usage element remains: "+id);
  assert.ok(!elements.has(id));
 }
}
(async()=>{
 reply(0,account);reply(1,{enabled:true,full:false});await tick();
 assert.equal(element("account").hidden,false);
 assert.equal(element("greeting").textContent,"你好，<script>untrusted</script>");
 assert.equal(element("status-badge").textContent,"已启用");
 assert.ok(element("valid-until").textContent.includes("北京时间"));
 assertPublicOnly();
 const refreshing=element("refresh").listeners.click();
 const loggingOut=element("logout").listeners.click();
 reply(3,{logged_out:true});await loggingOut;
 assert.equal(element("account").hidden,true);assert.equal(element("account-email").textContent,"");
 assert.equal(element("valid-until").textContent,"");
 reply(2,account);await refreshing;
 assert.equal(element("account").hidden,true);
 assertPublicOnly();
})().catch(error=>{console.error(error);process.exitCode=1;});
