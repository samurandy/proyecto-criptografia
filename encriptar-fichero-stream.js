const { createCipheriv, createECDH } = require("crypto")
const args = require("yargs").argv
const fs = require("fs")

if (!args.private && !args.public &&!args.data) {
    console.log("faltan parámetros")
    process.exit(0)
}

const origen = createECDH("secp521r1")
const key = fs.readFileSync("./data/" + args.private + ".key").toString()
origen.setPrivateKey(key, "hex")
console.log(key)

const pub = fs.readFileSync("./data/" + args.public + ".pb").toString()

//Creación de la clave secreta compartida
const secret = Uint8Array.from(origen.computeSecret(pub, "hex", 'hex'))
console.log(secret)

//Cifrado del fichero
const alg = "aes-256-cbc"
var cifrador = createCipheriv(alg, secret.slice(0, 32), secret.slice(0, 16))

//Añadir stream y pipes para que gestione la memoria del fichero y no colapsar el webserver
fs.createReadStream("./data/" + args.data)
.pipe(cifrador)
.pipe(new fs.createWriteStream("./data/" + args.public + "-" + args.data + ".enc"))

//Y cambiamos el fichero al que llamamos: node encriptar-fichero-stream.js --private acd --public emt --data fichero.txt
//que va a crear el fichero emt-fichero-txt.enc