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
// ED25519 SISTEMA COMPLETO
/////////////////////////

let edKeys = null
let lastSignature = null

function b64(u8){
  return btoa(String.fromCharCode(...u8))
}

function fromB64(s){
  return Uint8Array.from(atob(s), c=>c.charCodeAt(0))
}

function edGen(){
  edKeys = nacl.sign.keyPair()

  document.getElementById("edPriv").value = b64(edKeys.secretKey)
  document.getElementById("edPub").value  = b64(edKeys.publicKey)

  document.getElementById("edOut").textContent =
    "✔ Claves generadas"
}

function edExport(){
  if(!edKeys) return alert("Genera claves primero")

  const data =
`PUBLIC:
${b64(edKeys.publicKey)}

PRIVATE:
${b64(edKeys.secretKey)}`

  const blob = new Blob([data],{type:"text/plain"})
  const a = document.createElement("a")
  a.href = URL.createObjectURL(blob)
  a.download = "ed25519_keys.txt"
  a.click()
}

function edImport(){
  try{
    const priv = fromB64(document.getElementById("edPriv").value.trim())
    const pub  = fromB64(document.getElementById("edPub").value.trim())

    edKeys = {secretKey: priv, publicKey: pub}
    document.getElementById("edOut").textContent="✔ Claves cargadas"
  }catch{
    alert("Claves inválidas")
  }
}

function edSign(){
  if(!edKeys) return alert("No hay clave privada")

  const msg = new TextEncoder().encode(
    document.getElementById("edText").value)

  const sig = nacl.sign.detached(msg, edKeys.secretKey)
  lastSignature = sig

  document.getElementById("edOut").textContent =
    "Firma Base64:\n"+b64(sig)
}

function edVerify(){
  if(!edKeys) return alert("No hay clave pública")

  const msg = new TextEncoder().encode(
    document.getElementById("edText").value)

  const sigB64 = document.getElementById("edOut")
                   .textContent.replace("Firma Base64:\n","")

  try{
    const sig = fromB64(sigB64)
    const ok = nacl.sign.detached.verify(msg, sig, edKeys.publicKey)

    alert(ok ? "✔ Firma válida" : "❌ Firma inválida")
  }catch{
    alert("Firma inválida formato")
  }
}

