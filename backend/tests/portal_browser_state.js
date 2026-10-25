"use strict";
// Isolated unit fixture; no browser, network, accounts or real credentials.
const vm=require("node:vm"),fs=require("node:fs"),assert=require("node:assert/strict");
const elements=new Map(),requests=[];
function element(id){if(!elements.has(id))elements.set(id,{hidden:false,value:"",textContent:"",dataset:{},listeners:{},open:false,attributes:{},
 addEventListener(name,fn){this.listeners[name]=fn;},querySelectorAll(){return [];},reset(){this.value="";},focus(){},select(){},
 setAttribute(key,value){this.attributes[key]=value;},removeAttribute(key){delete this.attributes[key];},close(){this.open=false;}});return elements.get(id);}
const origin="https://203.0.113.10:9443",token="a".repeat(43);
const document={getElementById:element,querySelectorAll:()=>[],cookie:"__Secure-dazzle_csrf="+"c".repeat(43)};
const context=vm.createContext({document,location:{origin},URL,setTimeout:()=>0,clearTimeout:()=>{},navigator:{clipboard:{}},
 fetch:(url,options)=>new Promise(resolve=>requests.push({url,options,resolve})),console});
vm.runInContext(fs.readFileSync(process.argv[2],"utf8"),context);
const reply=(index,data)=>requests[index].resolve({json:async()=>({ok:true,data})});
const account={account:{id:"self",email:"private@example.test",nickname:"<script>untrusted</script>",status:"active",proxy_user_id:"self",quota_bytes:1000},subscriptions:{clash:origin+"/"+token+"/config.yaml",shadowrocket:origin+"/"+token+"/nodes.txt"}};
const tick=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 reply(0,account);await tick();
 assert.equal(element("clash-link").value,account.subscriptions.clash);
 assert.equal(element("greeting").textContent,"你好，<script>untrusted</script>");
 element("qr-dialog").open=true;element("qr-image").attributes.src="/portal/qr/clash";
 const refreshing=element("refresh").listeners.click();
 const loggingOut=element("logout").listeners.click();
 reply(2,{logged_out:true});await loggingOut;
 assert.equal(element("account").hidden,true);assert.equal(element("clash-link").value,"");
 assert.equal(element("shadowrocket-link").value,"");assert.equal(element("account-email").textContent,"");
 assert.equal(element("qr-dialog").open,false);assert.equal(element("qr-image").attributes.src,undefined);
 reply(1,account);await refreshing;
 assert.equal(element("account").hidden,true);assert.equal(element("clash-link").value,"");
})().catch(error=>{console.error(error);process.exitCode=1;});
