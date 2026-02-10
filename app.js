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
  const txt = document.getElementById("shaInput").value

  const t0 = performance.now()
  const h = sha3_512(txt)
  const t1 = performance.now()

  document.getElementById("shaTime").textContent =
    (t1-t0).toFixed(3)

  document.getElementById("shaOut").textContent = h

  // ✅ AGREGADO — iteraciones basadas en tamaño
  const iter = Math.max(1, txt.length)
  const iterBox = document.getElementById("shaIter")
  if(iterBox) iterBox.textContent = iter
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

  // ✅ AGREGADO — iteraciones dinámicas por tamaño contraseña
  const dynIter = Math.max(2, Math.ceil(pass.length / 4))
  const iterBox = document.getElementById("argonIter")
  if(iterBox) iterBox.textContent = dynIter

  const salt = new TextEncoder().encode("cryptolab")

  const r = await argon2.hash({
    pass,
    salt,
    type: argon2.ArgonType.Argon2id,
    hashLen: 32,
    time: dynIter,           // ← usa iteraciones dinámicas
    mem: 64*1024,
    parallelism: 1
  })

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

  const enc = await crypto.subtle.encrypt(
    {name:"AES-GCM",iv}, key, data)

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

  const dec = await crypto.subtle.decrypt(
    {name:"AES-GCM",iv}, key, dat)

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

function b64(u8){
  return btoa(String.fromCharCode(...u8))
}

function fromB64(s){
  return Uint8Array.from(atob(s),
    c=>c.charCodeAt(0))
}

function edGen(){
  edKeys = nacl.sign.keyPair()
  log("✔ Claves generadas")
}

function edSave(){
  if(!edKeys) return alert("Genera claves primero")

  const txt =
`PUBLIC=${b64(edKeys.publicKey)}
PRIVATE=${b64(edKeys.secretKey)}`

  const blob = new Blob([txt],
    {type:"text/plain"})

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

  const msgText = document.getElementById("edText").value
  const msg = new TextEncoder().encode(msgText)

  const t0 = performance.now()
  const sig = nacl.sign.detached(
    msg, edKeys.secretKey)
  const t1 = performance.now()

  document.getElementById("edTime").textContent =
    (t1-t0).toFixed(3)

  document.getElementById("sigInput").value =
    b64(sig)

  // ✅ AGREGADO — iteraciones basadas en tamaño mensaje
  const iterBox = document.getElementById("edIter")
  if(iterBox) iterBox.textContent = msgText.length

  log("Firma generada")
}

function edVerify(){

  if(!edKeys) return alert("No hay clave pública")

  const msgText = document.getElementById("edText").value
  const msg = new TextEncoder().encode(msgText)

  const sig = fromB64(
    document.getElementById("sigInput").value.trim())

  const t0 = performance.now()
  const ok = nacl.sign.detached.verify(
    msg, sig, edKeys.publicKey)
  const t1 = performance.now()

  document.getElementById("edTime").textContent =
    (t1-t0).toFixed(3)

  // ✅ AGREGADO
  const iterBox = document.getElementById("edIter")
  if(iterBox) iterBox.textContent = msgText.length

  log(ok ? "✔ Firma válida" : "❌ Firma inválida")
}

function log(t){
  document.getElementById("edOut").textContent = t
}
