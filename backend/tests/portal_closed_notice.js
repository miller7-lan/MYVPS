"use strict";
// Isolated fixture: the server answers every address alike, so the page alone
// explains that a new address receives no code while registration is closed.
const vm=require("node:vm"),fs=require("node:fs"),assert=require("node:assert/strict");
const scriptPath=process.argv[2],accepting=process.argv[3]==="accepting";
const elements=new Map(),requests=[];
function element(id){
 if(!elements.has(id))elements.set(id,{hidden:false,value:"",textContent:"",dataset:{},listeners:{},
  addEventListener(name,fn){this.listeners[name]=fn;},querySelectorAll(){return [];},reset(){this.value="";},focus(){}});
 return elements.get(id);
}
const document={getElementById:element,cookie:"__Secure-dazzle_csrf="+"c".repeat(43)};
const context=vm.createContext({document,setTimeout:()=>0,clearTimeout:()=>{},
 fetch:(url,options)=>new Promise(resolve=>requests.push({url,options,resolve})),console});
vm.runInContext(fs.readFileSync(scriptPath,"utf8"),context);
const reply=(index,ok,data)=>requests[index].resolve({json:async()=>(ok?{ok:true,data}:{ok:false,error:{code:"UNAUTHENTICATED",message:"x"}})});
const tick=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 reply(0,false);reply(1,true,{enabled:accepting,full:false,accepting,message:accepting?"":"暂不接受新注册，已有用户仍可登录。"});await tick();
 element("email").value="someone@example.test";
 const form=element("email-form");
 form.listeners.submit({preventDefault(){},currentTarget:form});
 await tick();
 assert.equal(requests[2].url,"/portal/api/request-code");
 reply(2,true,{challenge_id:"same-shape-for-every-address"});await tick();await tick();
 assert.equal(element("code-form").hidden,false);
 const expected=accepting?"发信请求已提交，请查看收件箱。":"已有用户将收到验证码；暂不接受新申请，新邮箱不会收到邮件。";
 assert.equal(element("message").textContent,expected);
})().catch(error=>{console.error(error);process.exitCode=1;});
