const { createECDH, createDecipheriv } = require("crypto")
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
var descifrador = createDecipheriv(alg, secret.slice(0, 32), secret.slice(0, 16))
const inputFile = "./data/" + args.private + "-" + args.data + ".enc"
const outputFile = "./data/" + args.private + "-" + args.data + ".des"

//Añadir stream y pipes para que gestione la memoria del fichero y no colapsar el webserver
fs.createReadStream("./data/" + args.data)
.pipe(descifrador)
.pipe(new fs.createWriteStream(outputFile))

//Lanzar el comando: node desencriptar-fichero-stream.js --private emt --public des --data fichero.txt
//Se crea el fichero emt-fichero.txt.des en data con el texto ya desencriptado