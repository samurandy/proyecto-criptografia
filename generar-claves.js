const { createECDH } = require("crypto")
const args = require("yargs").argv
const fs = require("fs")

console.log(args.name)
if(!args.name) {
    console.log("falta el argumento --name")
    process.exit(0)
}

const parejaDeClaves = createECDH("secp521r1")
const clavePublica = parejaDeClaves.generateKeys("hex")
const clavePrivada = parejaDeClaves.getPrivateKey("hex")

fs.writeFileSync("./data/"+ args.name + ".key", clavePrivada)
fs.writeFileSync("./data/"+ args.name + ".pb", clavePublica)

//Para crear claves, en la terminal lanzar: node generar-claves.js --name acd, donde acd puede ser cambiado y poner otro nombre.