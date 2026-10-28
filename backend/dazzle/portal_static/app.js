"use strict";
const $ = id => document.getElementById(id);
let challenge = null, current = null, registration = null, messageTimer, resendTimer, sessionEpoch = 0;
const PENDING_KEY = "dazzle-pending-code", CODE_TTL = 10 * 60 * 1000, RESEND_WAIT = 5 * 60 * 1000;
const NETWORK = "网络连接中断，请检查网络后重试。";
const statuses = {
 pending:["等待启用","申请已提交","管理员实际开通后，你会收到使用资料邮件。"],
 needs_confirmation:["待确认","需要管理员确认账户","邮箱与已有账户信息不一致或尚未验证，请联系管理员核对。"],
 waiting_resources:["等待名额","正在等待可用名额","申请已记录，有可用名额后管理员可继续开通。"],
 provisioning:["正在开通","正在准备你的连接","管理员已确认，正在完成连接与用量检查。"],
 active:["已启用","连接已准备就绪","请查看已验证邮箱中的使用资料；未收到可点击下方按钮重新发送。"],
 disabled:["已暂停","连接暂不可用","请联系管理员查看原因；额度用尽或用量统计异常也可能导致暂停。"],
 rejected:["未通过","本次申请未获通过","如需重新申请，请联系管理员。"],
 revoked:["已撤销","账户访问已结束","此账户的访问已撤销，如有疑问请联系管理员。"],
 failed:["待处理","开通暂未完成","管理员需要检查服务状态，请稍后刷新。"]
};
function notify(text){
 $("message").textContent=text;$("message").hidden=false;
 clearTimeout(messageTimer);messageTimer=setTimeout(()=>$("message").hidden=true,6000);
}
function csrf(){
 const entry=document.cookie.split(";").map(v=>v.trim()).find(v=>v.startsWith("__Secure-dazzle_csrf="));
 return entry?decodeURIComponent(entry.split("=").slice(1).join("=")):"";
}
// The page names its own challenge, so a reply lost to a mobile network or a
// backgrounded tab still leaves the code box usable. Only uniqueness matters.
function newChallenge(){
 const source=typeof crypto!=="undefined"?crypto:null;
 if(source&&typeof source.randomUUID==="function")return source.randomUUID();
 const bytes=new Uint8Array(16);
 if(source&&typeof source.getRandomValues==="function")source.getRandomValues(bytes);
 else for(let i=0;i<16;i++)bytes[i]=Math.floor(Math.random()*256);
 bytes[6]=(bytes[6]&15)|64;bytes[8]=(bytes[8]&63)|128;
 const hex=Array.from(bytes,b=>b.toString(16).padStart(2,"0")).join("");
 return hex.slice(0,8)+"-"+hex.slice(8,12)+"-"+hex.slice(12,16)+"-"+hex.slice(16,20)+"-"+hex.slice(20);
}
function storage(){try{return sessionStorage;}catch{return null;}}
function savePending(value){try{const s=storage();if(s){value?s.setItem(PENDING_KEY,JSON.stringify(value)):s.removeItem(PENDING_KEY);}}catch{}}
function loadPending(){
 try{
  const s=storage(),value=s&&JSON.parse(s.getItem(PENDING_KEY)||"null");
  return value&&typeof value.challenge==="string"&&typeof value.email==="string"&&Date.now()-value.at<CODE_TTL?value:null;
 }catch{return null;}
}
async function api(action,data){
 const options={method:data===undefined?"GET":"POST",credentials:"same-origin",cache:"no-store",headers:{}};
 if(data!==undefined){options.headers={"Content-Type":"application/json","X-CSRF-Token":csrf()};options.body=JSON.stringify(data);}
 let response;
 for(let attempt=0;;attempt++){
  try{response=await fetch("/portal/api/"+action,options);break;}
  catch{
   // Only reads are repeated; a write may already have been applied.
   if(data===undefined&&attempt===0){await new Promise(resolve=>setTimeout(resolve,800));continue;}
   const error=new Error(NETWORK);error.code="NETWORK";throw error;
  }
 }
 let result;
 try{result=await response.json();}catch{throw new Error("服务暂时不可用，请稍后再试。");}
 if(!result.ok){
  const error=new Error(result.error?.message||"请求未能完成。");
  error.code=result.error?.code;throw error;
 }
 return result.data;
}
function showCode(pending,message){
 challenge=pending.challenge;savePending(pending);
 $("email-form").hidden=true;$("code-form").hidden=false;
 $("sent-to").textContent="验证码将发送至 "+pending.email;$("code").focus();
 if(message)notify(message);
}
function showEmail(){
 $("email-form").hidden=false;$("code-form").hidden=true;$("code").value="";challenge=null;savePending(null);
}
function showLogin(){
 const wasSignedIn=current!==null;
 sessionEpoch++;$("login").hidden=false;$("account").hidden=true;$("logout").hidden=true;current=null;
 $("greeting").textContent="你好";$("account-email").textContent="";
 $("valid-until").textContent="";$("resend").hidden=true;
 if(wasSignedIn){
  $("email-form").reset();$("code-form").reset();showEmail();
 }
}
function render(data){
 current=data;
 const account=data.account,display=statuses[account.status]||statuses.failed;
 $("login").hidden=true;$("account").hidden=false;$("logout").hidden=false;
 $("greeting").textContent=account.nickname?"你好，"+account.nickname:"你好";
 $("account-email").textContent=account.email;
 $("status-badge").textContent=display[0];$("status-badge").dataset.status=account.status;
 $("status-title").textContent=display[1];$("status-description").textContent=display[2];
 $("resend").hidden=account.status!=="active";
 const expiry=account.expires_at?new Date(account.expires_at):null;
 $("valid-until").textContent=expiry&&Number.isFinite(expiry.getTime())?
  "有效至 "+expiry.toLocaleString("zh-CN",{timeZone:"Asia/Shanghai"})+"（北京时间）":"未设置固定到期时间";
}
async function refresh(silent=false){
 const epoch=sessionEpoch;
 try{
  const data=await api("me");if(epoch!==sessionEpoch)return;
  render(data);if(!silent)notify("状态已更新");
 }catch(error){
  if(epoch!==sessionEpoch)return;
  if(error.code==="UNAUTHENTICATED")showLogin();else if(!silent)notify(error.message);
 }
}
async function submit(form,action){
 const buttons=form.querySelectorAll("button");buttons.forEach(v=>v.disabled=true);
 try{await action();}catch(error){notify(error.message);}finally{buttons.forEach(v=>v.disabled=false);}
}
$("email-form").addEventListener("submit",event=>{
 event.preventDefault();sessionEpoch++;
 submit(event.currentTarget,async()=>{
  const pending={challenge:newChallenge(),email:$("email").value.trim(),at:Date.now()};
  try{
   await api("request-code",{email:pending.email,nickname:$("nickname").value.trim(),website:$("website").value,challenge_id:pending.challenge});
  }catch(error){
   if(error.code!=="NETWORK")throw error;
   // The request may have been delivered before the connection dropped.
   showCode(pending,"网络中断，未能确认发送结果。若已收到验证码可直接填写，未收到请稍后重新获取。");
   return;
  }
  // The server answers alike for every address; only the public status differs.
  showCode(pending,registration&&registration.accepting===false?"已有用户将收到验证码；暂不接受新申请，新邮箱不会收到邮件。":"发信请求已提交，请查看收件箱。");
 });
});
$("code-form").addEventListener("submit",event=>{
 event.preventDefault();
 submit(event.currentTarget,async()=>{
  await api("verify",{challenge_id:challenge,code:$("code").value.trim()});
  $("code").value="";savePending(null);await refresh(true);
 });
});
$("change-email").addEventListener("click",showEmail);
$("refresh").addEventListener("click",()=>refresh());
$("resend").addEventListener("click",async()=>{
 const button=$("resend"),epoch=sessionEpoch;button.disabled=true;
 let wait=false;
 try{
  const data=await api("resend-subscription",{});
  if(epoch===sessionEpoch)notify("已重新发送至 "+data.email+"，请查收（也请检查垃圾邮件）。");
  wait=true;
 }catch(error){
  if(epoch===sessionEpoch)notify(error.message);
  wait=error.code==="RESEND_COOLDOWN";
 }finally{
  clearTimeout(resendTimer);
  if(wait)resendTimer=setTimeout(()=>{button.disabled=false;},RESEND_WAIT);else button.disabled=false;
 }
});
$("logout").addEventListener("click",async()=>{
 const epoch=++sessionEpoch;
 try{await api("logout",{});if(epoch===sessionEpoch)showLogin();}catch(error){if(epoch===sessionEpoch)notify(error.message);}
});
async function registrationStatus(){
 try{
  const data=await api("status"),note=$("capacity-note");registration=data;
  if(data.full){note.textContent="人员已满，稍后再试。已注册的用户仍可直接登录。";note.hidden=false;}
  else if(!data.enabled){note.textContent=data.message||"暂不接受新注册，已有用户仍可登录。";note.hidden=false;}
  else{note.hidden=true;}
 }catch{}
}
const restored=loadPending();
if(restored)showCode(restored,"请填写邮件中的6位验证码。");
refresh(true);
registrationStatus();
