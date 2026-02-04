function showTab(id){
  document.querySelectorAll(".card").forEach(c=>c.classList.add("hidden"))
  document.getElementById(id).classList.remove("hidden")
}

/* SHA3-512 */
function doHash(){
  let txt = document.getElementById("hashInput").value
  document.getElementById("hashOut").textContent = sha3_512(txt)
}

/* Argon2id → AES key */
async function deriveKey(password){
  const salt = new TextEncoder().encode("cryptolab-salt")
  const res = await argon2.hash({
    pass: password,
    salt,
    type: argon2.ArgonType.Argon2id,
    hashLen: 32,
    time: 2,
    mem: 64*1024,
    parallelism: 1
  })
  return crypto.subtle.importKey(
    "raw", res.hash,
    {name:"AES-GCM"},
    false,
    ["encrypt","decrypt"]
  )
}

/* Encrypt */
async function encrypt(){
  const text = document.getElementById("encText").value
  const pass = document.getElementById("password").value
  const key = await deriveKey(pass)

  const iv = crypto.getRandomValues(new Uint8Array(12))
  const data = new TextEncoder().encode(text)

  const enc = await crypto.subtle.encrypt({name:"AES-GCM",iv}, key, data)

  const out = btoa(String.fromCharCode(...iv)) + ":" +
              btoa(String.fromCharCode(...new Uint8Array(enc)))

  document.getElementById("encOut").textContent = out
}

/* Decrypt */
async function decrypt(){
  const pass = document.getElementById("password").value
  const key = await deriveKey(pass)

  const [ivB, dataB] = document.getElementById("encOut").textContent.split(":")
  const iv = Uint8Array.from(atob(ivB),c=>c.charCodeAt(0))
  const data = Uint8Array.from(atob(dataB),c=>c.charCodeAt(0))

  const dec = await crypto.subtle.decrypt({name:"AES-GCM",iv}, key, data)
  document.getElementById("encText").value =
    new TextDecoder().decode(dec)
}

/* Ed25519 */
let keypair

function genKeys(){
  keypair = nacl.sign.keyPair()
  document.getElementById("signOut").textContent =
    "Claves generadas"
}

function signMsg(){
  const msg = new TextEncoder().encode(
    document.getElementById("signText").value)

  const sig = nacl.sign.detached(msg, keypair.secretKey)
  document.getElementById("signOut").textContent =
    "Firma: " + btoa(String.fromCharCode(...sig))
}

function verifyMsg(){
  const msg = new TextEncoder().encode(
    document.getElementById("signText").value)

  const sig = Uint8Array.from(
    atob(document.getElementById("signOut").textContent.replace("Firma: ","")),
    c=>c.charCodeAt(0))

  const ok = nacl.sign.detached.verify(msg, sig, keypair.publicKey)

  alert(ok ? "Firma válida ✅" : "Firma inválida ❌")
}
