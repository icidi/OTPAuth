login = bytes(
    "<!DOCTYPE html><html><head><title>Login Page</title></head><style>body{display:flex;align-items:center;justify-content:center;font-family:sans-serif;line-height:2;min-height:75vh;margin:0}.login-container{background-color:#fff;box-shadow:0 0 20px rgba(0,0,0,0.2);padding:10px 10px;width:500px;text-align:center}.login-input label{display:inline-block;width:20%}.login-input select{text-align:center;width:20%}button{padding:10px;border-radius:10px;margin:20px;border:0;color:white;background-color:#00b030;width:50%;font-size:16px}</style><body><div class=login-container><h3>Login</h3><form action=\"\" method=post><div class=login-input><label for=username-input>Username:</label> <input type=text id=username-input name=username required></div><div class=login-input><select id=method-input name=method><option value=totp>TOTP</option><option value=password>Password</option></select> <input type=password id=secret-input name=secret required></div><div><button type=submit>Submit</button></div></form></div></body></html>"
    , "utf-8")

loginFailed = bytes(
    "<!DOCTYPE html><html><head><title>Login Page</title></head><style>body{display:flex;align-items:center;justify-content:center;font-family:sans-serif;line-height:2;min-height:75vh;margin:0}.login-container{background-color:#fff;box-shadow:0 0 20px rgba(0,0,0,0.2);padding:10px 10px;width:500px;text-align:center}.login-input label{display:inline-block;width:20%}.login-input select{text-align:center;width:20%}button{padding:10px;border-radius:10px;margin:20px;border:0;color:white;background-color:#00b030;width:50%;font-size:16px}</style><body><div class=login-container><h3>Login</h3><form action=\"\" method=post><div class=login-input><label for=username-input>Username:</label> <input type=text id=username-input name=username required></div><div class=login-input><select id=method-input name=method><option value=totp>TOTP</option><option value=password>Password</option></select> <input type=password id=secret-input name=secret required></div><div><button type=submit>Submit</button></div></form><p style=color:red>Login Failed</p></div></body></html>"
    , "utf-8")

loginSuccessful = bytes(
    "<!DOCTYPE html><html><head><title>Login Successful</title></head><svg fill=#00b030 height=10vh width=10vh viewBox=\"0 0 490 490\"><polygon points=\"452.253,28.326 197.831,394.674 29.044,256.875 0,292.469 207.253,461.674 490,54.528\"/></svg><h1>Login Successful</h1></html>"
    , "utf-8")

notFound = bytes(
    "<!DOCTYPE html><html><head><title>404 Not Found</title></head><h1>404 Not Found</h1></html>"
    , "utf-8")

forbidden = bytes(
    "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><h1>403 Forbidden</h1></html>"
    , "utf-8")

tools = bytes(
    "<!DOCTYPE html><html><head><title>Tools</title></head><body><h1>Tools</h1><p>PBKDF2:</p><div><label for=salt>Salt:</label> <input type=text id=salt required><label for=key> &numsp;Key:</label> <input type=password id=key required><br><br><label for=hash>Hash:</label> <input type=text id=hash value=SHA-256 size=10> <label for=bits>Bits:</label> <input type=number id=bits value=256 size=10> <label for=iter>Iter:</label> <input type=number id=iter value=6e5 size=10> <button onclick=genPBKDF2()>Generate</button><br><br><label for=pbkdf2-output>Result:</label> <input type=text id=pbkdf2-output size=68 readonly></div><br><br><p>TOTP Key:</p><div><label for=length>Length:</label> <input type=number id=length value=16><br><br><label for=totpkey>&nbsp;&numsp;Key:</label> <input type=text id=totpkey size=24 readonly> <button onclick=genKey()>Generate</button></div><script>const toHex=a=>Array.from(a,byte=>('0'+(byte&0xff).toString(16)).slice(-2)).join('');async function pbkdf2(k,a,l){let ik=await crypto.subtle.importKey('raw',k,'PBKDF2',false,['deriveBits']);let buf=await crypto.subtle.deriveBits(a,ik,l);return new Uint8Array(buf)}async function genPBKDF2(){let salt=document.getElementById('salt').value;let key=document.getElementById('key').value;let b=document.getElementById('bits').value;let s=new TextEncoder().encode(salt);let k=new TextEncoder().encode(key);let h=document.getElementById('hash').value;let i=document.getElementById('iter').value;let a={name:'PBKDF2',hash:h,salt:s,iterations:i};let r=await pbkdf2(k,a,b);document.getElementById('pbkdf2-output').value=toHex(r)}function genKey(){const b='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let l=document.getElementById('length').value;let a=new Uint8Array(l);window.crypto.getRandomValues(a);let r='';a.forEach(i=>{r+=b[i&0x1f]});document.getElementById('totpkey').value=r}</script></body></html>"
    , "utf-8")

