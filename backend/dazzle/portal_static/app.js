"use strict";
const $ = id => document.getElementById(id);
let challenge = null, current = null, messageTimer, sessionEpoch = 0;
const statuses = {
 pending:["等待启用","订阅已准备好","管理员启用后，邮件里的同一链接即可导入。"],
 waiting_resources:["等待资源","等待分配代理资源","申请已记录，管理员准备好资源后可继续开通。"],
 provisioning:["正在开通","正在准备你的连接","管理员已确认，服务器正在检查配置和流量计量。"],
 active:["已启用","连接已准备就绪","复制对应订阅，在客户端导入或刷新即可。"],
 disabled:["已暂停","连接暂不可用","请联系管理员；额度或计量保护也可能暂停连接。"],
 rejected:["未通过","本次申请未获通过","如需重新申请，请联系管理员。"],
 revoked:["已撤销","原订阅已失效","访问凭据已撤销，请联系管理员。"],
 failed:["待处理","开通暂未完成","管理员需要检查服务器状态，请稍后刷新。"]
};
function notify(text){$("message").textContent=text;$("message").hidden=false;clearTimeout(messageTimer);messageTimer=setTimeout(()=>$("message").hidden=true,6000);}
function csrf(){const entry=document.cookie.split(";").map(v=>v.trim()).find(v=>v.startsWith("__Secure-dazzle_csrf="));return entry?decodeURIComponent(entry.split("=").slice(1).join("=")):"";}
async function api(action,data){const options={method:data===undefined?"GET":"POST",credentials:"same-origin",cache:"no-store",headers:{}};if(data!==undefined){options.headers={"Content-Type":"application/json","X-CSRF-Token":csrf()};options.body=JSON.stringify(data);}const response=await fetch("/portal/api/"+action,options);let result;try{result=await response.json();}catch{throw new Error("服务暂时不可用，请稍后再试。");}if(!result.ok){const error=new Error(result.error?.message||"请求未能完成。");error.code=result.error?.code;throw error;}return result.data;}
function showLogin(){const wasSignedIn=current!==null;sessionEpoch++;$("login").hidden=false;$("account").hidden=true;$("logout").hidden=true;current=null;for(const kind of ["clash","shadowrocket"]){$(kind+"-link").value="";document.querySelectorAll(`[data-copy="${kind}"],[data-qr="${kind}"]`).forEach(button=>button.disabled=true);}$("qr-image").removeAttribute("src");if($("qr-dialog").open)$("qr-dialog").close();$("greeting").textContent="你好";$("account-email").textContent="";if(wasSignedIn){$("email-form").reset();$("code-form").reset();$("email-form").hidden=false;$("code-form").hidden=true;challenge=null;}}
function size(value){if(!Number.isFinite(value))return "—";return value>=1e9?(value/1e9).toFixed(2)+" GB":value>=1e6?(value/1e6).toFixed(1)+" MB":Math.round(value/1000)+" KB";}
function validLink(value,kind){if(typeof value!=="string")return false;try{const url=new URL(value);return url.origin===location.origin&&new RegExp("^/[A-Za-z0-9_-]{24,128}/"+(kind==="clash"?"config\\.yaml":"nodes\\.txt")+"$").test(url.pathname)&&!url.search&&!url.hash;}catch{return false;}}
function render(data){current=data;const account=data.account;const display=statuses[account.status]||statuses.failed;$("login").hidden=true;$("account").hidden=false;$("logout").hidden=false;$("greeting").textContent=account.nickname?"你好，"+account.nickname:"你好";$("account-email").textContent=account.email;$("status-badge").textContent=display[0];$("status-badge").dataset.status=account.status;$("status-title").textContent=display[1];$("status-description").textContent=display[2];const used=(account.used_upload||0)+(account.used_download||0);$("used").textContent=account.proxy_user_id?size(used):"尚未开通";const allowance=account.allowance_bytes??((account.quota_bytes||0)+(account.topup_bytes||0));$("quota").textContent=!account.proxy_user_id?"待管理员分配额度":account.unlimited?"个人额度不限量":"周期额度 "+size(allowance);const part=!account.unlimited&&allowance?Math.min(1,used/allowance):0;$("usage-arc").setAttribute("stroke-dasharray",(part*227).toFixed(2)+" 227");for(const kind of ["clash","shadowrocket"]){const link=data.subscriptions?.[kind];const valid=validLink(link,kind);$(kind+"-link").value=valid?link:"当前无法领取订阅";document.querySelectorAll(`[data-copy="${kind}"],[data-qr="${kind}"]`).forEach(button=>button.disabled=!valid);}}
async function refresh(silent=false){const epoch=sessionEpoch;try{const data=await api("me");if(epoch!==sessionEpoch)return;render(data);if(!silent)notify("状态已更新");}catch(error){if(epoch!==sessionEpoch)return;if(error.code==="UNAUTHENTICATED")showLogin();else if(!silent)notify(error.message);}}
async function submit(form,action){const buttons=form.querySelectorAll("button");buttons.forEach(v=>v.disabled=true);try{await action();}catch(error){notify(error.message);}finally{buttons.forEach(v=>v.disabled=false);}}
$("email-form").addEventListener("submit",event=>{event.preventDefault();sessionEpoch++;submit(event.currentTarget,async()=>{const result=await api("request-code",{email:$("email").value.trim(),nickname:$("nickname").value.trim(),website:$("website").value});challenge=result.challenge_id;$("email-form").hidden=true;$("code-form").hidden=false;$("sent-to").textContent="验证码将发送至 "+$("email").value.trim();$("code").focus();notify("发信请求已提交，请查看收件箱。");});});
$("code-form").addEventListener("submit",event=>{event.preventDefault();submit(event.currentTarget,async()=>{await api("verify",{challenge_id:challenge,code:$("code").value.trim()});$("code").value="";await refresh(true);});});
$("change-email").addEventListener("click",()=>{$("email-form").hidden=false;$("code-form").hidden=true;$("code").value="";challenge=null;});
$("refresh").addEventListener("click",()=>refresh());
$("logout").addEventListener("click",async()=>{const epoch=++sessionEpoch;try{await api("logout",{});if(epoch===sessionEpoch)showLogin();}catch(error){if(epoch===sessionEpoch)notify(error.message);}});
document.querySelectorAll("[data-copy]").forEach(button=>button.addEventListener("click",async()=>{const field=$(button.dataset.copy+"-link");try{await navigator.clipboard.writeText(field.value);notify("订阅已复制；请在管理员启用后导入。");}catch{field.select();notify("请复制已选中的订阅地址。");}}));
document.querySelectorAll("[data-qr]").forEach(button=>button.addEventListener("click",()=>{$("qr-title").textContent=(button.dataset.qr==="clash"?"Clash / mihomo":"Shadowrocket")+" 订阅";$("qr-image").src="/portal/qr/"+button.dataset.qr;$("qr-dialog").showModal();}));
$("close-qr").addEventListener("click",()=>{$("qr-dialog").close();$("qr-image").removeAttribute("src");});
refresh(true);
