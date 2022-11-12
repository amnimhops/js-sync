// Algorithm to be used in HMAC calculation
const HMAC_ALG = "sha256";

// Stop execution if not enough params
if(process.argv.length < 5){
    console.log("Wrong param number\n");
    console.log("Usage:\n")
    console.log('node sync.js <url> <filename> <key>\n');
    console.log('  url - service url');
    console.log('  filename - path of the file with the updates');
    console.log('  key - private key to generate the signature');
    process.exit(-1);
}

(async ()=>{

    const { readFileSync } = require("fs");
    const { gzip } = require("node-gzip");
    const { createHmac } = require("crypto");
    const https = require("https");
    const axios = require("axios");
    
    const url = process.argv[2];
    const filename = process.argv[3];
    const secret = process.argv[4];
    // Read the file from disk
    const data = readFileSync(filename);
    // Compress the content
    const compressed = await gzip(data);
    // Calculate the signature using the key provided
    const signature = createHmac(HMAC_ALG,secret).update(compressed).digest("hex");
    // Create the network client
    const client = axios.create({
        httpsAgent: new https.Agent({  
            rejectUnauthorized: false
        })
    });
    // Send the compressed data with POST
    client.post(url,compressed,{
        timeout:5000,
        headers:{
            "X-Token":signature,
            "Content-Type":"application/octet-stream"
        }
    }).then( result => {
        console.log(result.data);
    }).catch( err => {
        console.error(err.data);
    })
})();
