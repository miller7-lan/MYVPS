"use strict";
// Isolated fixture for phone browsers: a lost request-code reply, a reloaded tab
// and the signed-in resend button. No network, cookies or real storage.
const vm=require("node:vm"),fs=require("node:fs"),assert=require("node:assert/strict");
const scriptPath=process.argv[2],markup=fs.readFileSync(scriptPath.replace(/app\.js$/,"index.html"),"utf8");
const allowedIds=new Set([...markup.matchAll(/\bid="([^"]+)"/g)].map(match=>match[1]));
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const tick=()=>new Promise(resolve=>setImmediate(resolve));
async function settle(){for(let i=0;i<6;i++)await tick();}
function load(storage){
 const elements=new Map(),requests=[];
 function element(id){
  assert.ok(allowedIds.has(id),"Missing element referenced: "+id);
  if(!elements.has(id))elements.set(id,{hidden:false,value:"",textContent:"",dataset:{},listeners:{},disabled:false,
   addEventListener(name,fn){this.listeners[name]=fn;},querySelectorAll(){return [];},reset(){this.value="";},focus(){}});
  return elements.get(id);
 }
 for(const id of ["code-form","resend"])element(id).hidden=true;
 const context=vm.createContext({document:{getElementById:element,cookie:"__Secure-dazzle_csrf="+"c".repeat(43)},
  sessionStorage:storage,setTimeout:()=>0,clearTimeout:()=>{},Uint8Array,Array,Math,JSON,Date,console,
  fetch:(url,options)=>new Promise((resolve,reject)=>requests.push({url,options,resolve,reject}))});
 vm.runInContext(fs.readFileSync(scriptPath,"utf8"),context);
 const reply=(index,ok,data,code)=>requests[index].resolve({json:async()=>(ok?{ok:true,data}:{ok:false,error:{code,message:"x"}})});
 return {element,requests,reply};
}
function memoryStorage(){const map=new Map();return {getItem:k=>map.has(k)?map.get(k):null,setItem:(k,v)=>map.set(k,String(v)),removeItem:k=>map.delete(k)};}
(async()=>{
 // A: the reply is lost, but the page already knows its challenge.
 const storage=memoryStorage();
 let page=load(storage);
 page.reply(0,false,null,"UNAUTHENTICATED");page.reply(1,true,{enabled:true,full:false,accepting:true,message:""});await settle();
 page.element("email").value="phone@example.test";
 const form=page.element("email-form");form.listeners.submit({preventDefault(){},currentTarget:form});await settle();
 assert.equal(page.requests[2].url,"/portal/api/request-code");
 const sent=JSON.parse(page.requests[2].options.body);
 assert.match(sent.challenge_id,UUID);
 page.requests[2].reject(new TypeError("Failed to fetch"));await settle();
 assert.equal(page.element("code-form").hidden,false,"the code box must appear without the reply");
 assert.equal(page.element("email-form").hidden,true);
 assert.ok(page.element("message").textContent.includes("若已收到验证码可直接填写"));
 assert.ok(!page.element("message").textContent.includes("Failed to fetch"));
 // B: the phone reloads the tab while the user reads the mail.
 page=load(storage);
 assert.equal(page.element("code-form").hidden,false,"a reloaded tab keeps the pending code box");
 page.reply(0,false,null,"UNAUTHENTICATED");page.reply(1,true,{enabled:true,full:false,accepting:true,message:""});await settle();
 page.element("code").value="123456";
 const codeForm=page.element("code-form");codeForm.listeners.submit({preventDefault(){},currentTarget:codeForm});await settle();
 assert.equal(page.requests[2].url,"/portal/api/verify");
 assert.deepEqual(JSON.parse(page.requests[2].options.body),{challenge_id:sent.challenge_id,code:"123456"});
 page.reply(2,true,{expires_at:"2026-12-01T00:00:00Z"});await settle();
 assert.equal(storage.getItem("dazzle-pending-code"),null,"a used code is forgotten");
 // C: an active account can resend its subscription mail; others cannot.
 for(const status of ["active","pending"]){
  page=load(memoryStorage());
  page.reply(0,true,{account:{id:"self",email:"me@example.test",nickname:"",status,expires_at:null}});
  page.reply(1,true,{enabled:true,full:false,accepting:true,message:""});await settle();
  assert.equal(page.element("resend").hidden,status!=="active");
  if(status!=="active")continue;
  page.element("resend").listeners.click();await settle();
  assert.equal(page.requests[2].url,"/portal/api/resend-subscription");
  assert.equal(page.requests[2].options.method,"POST");
  assert.deepEqual(JSON.parse(page.requests[2].options.body),{});
  page.reply(2,true,{queued:true,email:"me@example.test"});await settle();
  assert.ok(page.element("message").textContent.includes("me@example.test"));
  assert.equal(page.element("resend").disabled,true,"the button waits out the cooldown");
 }
})().catch(error=>{console.error(error);process.exitCode=1;});
