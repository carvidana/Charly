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
// ED25519 — SISTEMA TIPO CONSOLA
/////////////////////////

let edKeys = null

function b64(u8){ return btoa(String.fromCharCode(...u8)) }
function fromB64(s){ return Uint8Array.from(atob(s),c=>c.charCodeAt(0)) }

function edGen(){
  edKeys = nacl.sign.keyPair()
  log("✔ Claves generadas")
}

function edSave(){
  if(!edKeys) return alert("Genera claves primero")

  const txt =
`PUBLIC=${b64(edKeys.publicKey)}
PRIVATE=${b64(edKeys.secretKey)}`

  const blob = new Blob([txt],{type:"text/plain"})
  const a = document.createElement("a")
  a.href = URL.createObjectURL(blob)
  a.download = "ed25519.keys"
  a.click()

  log("✔ Claves guardadas")
}

function edLoadFile(){
  const f = document.getElementById("keyFile").files[0]
  if(!f) return

  const r = new FileReader()
  r.onload = e=>{
    const t = e.target.result.split("\n")
    const pub = fromB64(t[0].split("=")[1])
    const priv = fromB64(t[1].split("=")[1])
    edKeys = {publicKey:pub, secretKey:priv}
    log("✔ Claves cargadas")
  }
  r.readAsText(f)
}

function edSign(){
  if(!edKeys) return alert("No hay clave privada")

  const msg = new TextEncoder().encode(
    document.getElementById("edText").value)

  const sig = nacl.sign.detached(msg, edKeys.secretKey)
  const s64 = b64(sig)

  document.getElementById("sigInput").value = s64
  log("Firma generada:\n"+s64)
}

function edVerify(){
  if(!edKeys) return alert("No hay clave pública")

  const msg = new TextEncoder().encode(
    document.getElementById("edText").value)

  const sig = fromB64(
    document.getElementById("sigInput").value.trim())

  const ok = nacl.sign.detached.verify(msg, sig, edKeys.publicKey)

  log(ok ? "✔ Firma válida" : "❌ Firma inválida")
}

function log(t){
  document.getElementById("edOut").textContent = t
}

}

