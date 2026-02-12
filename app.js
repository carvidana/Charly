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

  const iter = Math.max(2, Math.ceil(pass.length / 4))

  const iterBox = document.getElementById("argonIter")
  if(iterBox) iterBox.textContent = iter

  const salt = new TextEncoder().encode("cryptolab")

  const r = await argon2.hash({
    pass: pass,
    salt: salt,
    type: argon2.ArgonType.Argon2id,
    hashLen: 32,
    time: iter,
    mem: 64*1024,
    parallelism: 1
  })

  return crypto.subtle.importKey(
    "raw",
    r.hash,
    {name:"AES-GCM"},
    false,
    ["encrypt","decrypt"]
  )
}

async function argonEncrypt(){

  const pass = document.getElementById("argonPass").value
  const text = document.getElementById("argonText").value

  if(!pass || !text){
    alert("Falta contraseña o texto")
    return
  }

  const t0 = performance.now()

  const key = await derive(pass)

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const data = new TextEncoder().encode(text)

  const enc = await crypto.subtle.encrypt(
    {name:"AES-GCM", iv},
    key,
    data
  )

  const out =
    btoa(String.fromCharCode(...iv)) + "." +
    btoa(String.fromCharCode(...new Uint8Array(enc)))

  document.getElementById("argonOut").textContent = out



  const t1 = performance.now()
  document.getElementById("argonTime").textContent =
    (t1-t0).toFixed(2)
}

async function argonDecrypt(){

  const pass = document.getElementById("argonPass").value

  const src =
    document.getElementById("argonCipher")?.value ||
    document.getElementById("argonOut").textContent

  if(!pass || !src){
    alert("Falta contraseña o cifrado")
    return
  }

  const parts = src.split(".")

  if(parts.length !== 2){
    alert("Formato inválido")
    return
  }

  const iv = Uint8Array.from(atob(parts[0]),
    c=>c.charCodeAt(0))

  const dat = Uint8Array.from(atob(parts[1]),
    c=>c.charCodeAt(0))

  const t0 = performance.now()

  const key = await derive(pass)

  try{
    const dec = await crypto.subtle.decrypt(
      {name:"AES-GCM", iv},
      key,
      dat
    )

    document.getElementById("argonText").value =
      new TextDecoder().decode(dec)

  }catch{
    alert("Contraseña incorrecta o datos dañados")
    return
  }

  const t1 = performance.now()
  document.getElementById("argonTime").textContent =
    (t1-t0).toFixed(2)
}


/////////////////////////
// ED25519
/////////////////////////

/////////////////////////
// ED25519 TEXTO
/////////////////////////

let edKeys = null

function b64(u8){
  return btoa(String.fromCharCode(...u8))
}

function fromB64(s){
  return Uint8Array.from(atob(s),
    c=>c.charCodeAt(0))
}


// generar claves
function edGen(){

  edKeys = nacl.sign.keyPair()

  document.getElementById("pubKeyBox").value =
    b64(edKeys.publicKey)

  document.getElementById("privKeyBox").value =
    b64(edKeys.secretKey)

  log("✔ Claves generadas")
}


// cargar claves pegadas
function edLoadFromText(){

  const pub = document.getElementById("pubKeyBox").value.trim()
  const priv = document.getElementById("privKeyBox").value.trim()

  if(!pub){
    alert("Falta clave pública")
    return
  }

  edKeys = {
    publicKey: fromB64(pub),
    secretKey: priv ? fromB64(priv) : null
  }

  log("✔ Claves cargadas desde texto")
}


// firmar
function edSign(){

  if(!edKeys || !edKeys.secretKey)
    return alert("No hay clave privada")

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

  document.getElementById("edIter").textContent =
    msgText.length

  log("✔ Firma generada")
}


// verificar
function edVerify(){

  if(!edKeys || !edKeys.publicKey)
    return alert("No hay clave pública")

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

  document.getElementById("edIter").textContent =
    msgText.length

  log(ok ? "✔ Firma válida" : "❌ Firma inválida")
}


function log(t){
  document.getElementById("edOut").textContent = t
}

