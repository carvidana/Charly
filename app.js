function showTab(id){
  document.querySelectorAll(".card")
    .forEach(x=>x.classList.add("hidden"))
  document.getElementById(id)
    .classList.remove("hidden")
}

/////////////////////////
// SHA3
/////////////////////////

function shaHash(){
  const txt0 = document.getElementById("shaInput").value
  const n = parseInt(document.getElementById("shaIter").value || 1)

  let txt = txt0

  const t0 = performance.now()

  for(let i=0;i<n;i++){
    txt = sha3_512(txt)
  }

  const t1 = performance.now()

  document.getElementById("shaTime").textContent =
    (t1-t0).toFixed(3)

  document.getElementById("shaIterUsed").textContent = n
  document.getElementById("shaOut").textContent = txt
}

function shaVerify(){
  const txt = document.getElementById("shaInput").value
  const h = sha3_512(txt)
  const given = document.getElementById("shaCheck").value
  alert(h === given ? "Coincide ✅" : "No coincide ❌")
}

/////////////////////////
// ARGON2 + AES
/////////////////////////

async function derive(pass){
  const salt = new TextEncoder().encode("cryptolab")
  const it = parseInt(document.getElementById("argonIter").value || 2)

  const d0 = performance.now()

  const r = await argon2.hash({
    pass,
    salt,
    type: argon2.ArgonType.Argon2id,
    hashLen: 32,
    time: it,
    mem: 64*1024,
    parallelism: 1
  })

  const d1 = performance.now()

  document.getElementById("argonDeriveTime").textContent =
    (d1-d0).toFixed(2)

  document.getElementById("argonIterUsed").textContent = it

  return crypto.subtle.importKey(
    "raw", r.hash,
    {name:"AES-GCM"},
    false,
    ["encrypt","decrypt"]
  )
}

async function argonEncrypt(){

  const t0 = performance.now()

  const key = await derive(
    document.getElementById("argonPass").value)

  const iv = crypto.getRandomValues(new Uint8Array(12))

  const data = new TextEncoder().encode(
    document.getElementById("argonText").value)

  const a0 = performance.now()

  const enc = await crypto.subtle.encrypt(
    {name:"AES-GCM",iv}, key, data)

  const a1 = performance.now()

  document.getElementById("argonAesTime").textContent =
    (a1-a0).toFixed(3)

  const t1 = performance.now()

  document.getElementById("argonTime").textContent =
    (t1-t0).toFixed(2)

  document.getElementById("argonOut").textContent =
    btoa(String.fromCharCode(...iv))+"."+
    btoa(String.fromCharCode(...new Uint8Array(enc)))
}

async function argonDecrypt(){

  const t0 = performance.now()

  const key = await derive(
    document.getElementById("argonPass").value)

  const parts = document.getElementById("argonOut")
    .textContent.split(".")

  const iv = Uint8Array.from(atob(parts[0]),
    c=>c.charCodeAt(0))

  const dat = Uint8Array.from(atob(parts[1]),
    c=>c.charCodeAt(0))

  const a0 = performance.now()

  const dec = await crypto.subtle.decrypt(
    {name:"AES-GCM",iv}, key, dat)

  const a1 = performance.now()

  document.getElementById("argonAesTime").textContent =
    (a1-a0).toFixed(3)

  const t1 = performance.now()

  document.getElementById("argonTime").textContent =
    (t1-t0).toFixed(2)

  document.getElementById("argonText").value =
    new TextDecoder().decode(dec)
}

/////////////////////////
// ED25519
/////////////////////////

let edKeys = null

function b64(u8){ return btoa(String.fromCharCode(...u8)) }
function fromB64(s){
  return Uint8Array.from(atob(s),
    c=>c.charCodeAt(0))
}

function edGen(){
  edKeys = nacl.sign.keyPair()
  log("✔ Claves generadas")
}

function edLoadFile(){
  const f = document.getElementById("keyFile").files[0]
  if(!f) return
  const r = new FileReader()
  r.onload = e=>{
    const t = e.target.result.split("\n")
    edKeys = {
      publicKey: fromB64(t[0].split("=")[1]),
      secretKey: fromB64(t[1].split("=")[1])
    }
    log("✔ Claves cargadas")
  }
  r.readAsText(f)
}

function edSign(){

  if(!edKeys) return alert("No hay clave privada")

  const msg = new TextEncoder().encode(
    document.getElementById("edText").value)

  const n = parseInt(document.getElementById("edIter").value || 1)

  const t0 = performance.now()

  let sig
  for(let i=0;i<n;i++){
    sig = nacl.sign.detached(msg, edKeys.secretKey)
  }

  const t1 = performance.now()

  document.getElementById("edTime").textContent =
    (t1-t0).toFixed(3)

  document.getElementById("edIterUsed").textContent = n

  document.getElementById("sigInput").value = b64(sig)

  log("Firma generada")
}

function edVerify(){

  if(!edKeys) return alert("No hay clave pública")

  const msg = new TextEncoder().encode(
    document.getElementById("edText").value)

  const sig = fromB64(
    document.getElementById("sigInput").value.trim())

  const ok = nacl.sign.detached.verify(
    msg, sig, edKeys.publicKey)

  log(ok ? "✔ Firma válida" : "❌ Firma inválida")
}

function log(t){
  document.getElementById("edOut").textContent = t
}
