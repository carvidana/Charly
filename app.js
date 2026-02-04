function showTab(id){
  document.querySelectorAll(".card").forEach(x=>x.classList.add("hidden"))
  document.getElementById(id).classList.remove("hidden")
}

/////////////////////////
// SHA3
/////////////////////////

function shaHash(){
  const t = sha3_512(document.getElementById("shaInput").value)
  document.getElementById("shaOut").textContent = t
}

function shaVerify(){
  const txt = document.getElementById("shaInput").value
  const h = sha3_512(txt)
  const given = document.getElementById("shaCheck").value
  alert(h === given ? "Hash coincide ✅" : "Hash distinto ❌")
}

/////////////////////////
// ARGON2ID + AES
/////////////////////////

async function derive(pass){
  const salt = new TextEncoder().encode("cryptolab")
  const r = await argon2.hash({
    pass,
    salt,
    type: argon2.ArgonType.Argon2id,
    hashLen: 32,
    time: 2,
    mem: 64*1024,
    parallelism: 1
  })
  return crypto.subtle.importKey("raw", r.hash,{name:"AES-GCM"},false,["encrypt","decrypt"])
}

async function argonEncrypt(){
  const key = await derive(document.getElementById("argonPass").value)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const data = new TextEncoder().encode(document.getElementById("argonText").value)

  const enc = await crypto.subtle.encrypt({name:"AES-GCM",iv},key,data)

  document.getElementById("argonOut").textContent =
    btoa(String.fromCharCode(...iv))+"."+btoa(String.fromCharCode(...new Uint8Array(enc)))
}

async function argonDecrypt(){
  const key = await derive(document.getElementById("argonPass").value)
  const parts = document.getElementById("argonOut").textContent.split(".")
  const iv = Uint8Array.from(atob(parts[0]),c=>c.charCodeAt(0))
  const dat = Uint8Array.from(atob(parts[1]),c=>c.charCodeAt(0))

  const dec = await crypto.subtle.decrypt({name:"AES-GCM",iv},key,dat)
  document.getElementById("argonText").value = new TextDecoder().decode(dec)
}

/////////////////////////
// ED25519
/////////////////////////

let edKeys

function edGen(){
  edKeys = nacl.sign.keyPair()
  document.getElementById("edOut").textContent="Claves generadas"
}

function edSign(){
  const msg = new TextEncoder().encode(document.getElementById("edText").value)
  const sig = nacl.sign.detached(msg, edKeys.secretKey)
  document.getElementById("edOut").textContent =
    "Firma:"+btoa(String.fromCharCode(...sig))
}

function edVerify(){
  const msg = new TextEncoder().encode(document.getElementById("edText").value)
  const sig = Uint8Array.from(
    atob(document.getElementById("edOut").textContent.replace("Firma:","")),
    c=>c.charCodeAt(0))

  const ok = nacl.sign.detached.verify(msg,sig,edKeys.publicKey)
  alert(ok ? "Firma válida ✅" : "Firma inválida ❌")
}
