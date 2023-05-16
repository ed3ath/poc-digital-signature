const crypto = require('crypto');

const server = crypto.createECDH('secp256k1');
const client = crypto.createECDH('secp256k1');
server.generateKeys();
client.generateKeys();


function signMessage(message, sharedKey) {
    const hmac = crypto.createHmac('sha256', sharedKey);
    hmac.update(message);
    return hmac.digest('hex');
}

function verifySignature(message, signature, sharedKey) {
    const hmac = crypto.createHmac('sha256', sharedKey);
    hmac.update(message);
    const calculatedSignature = hmac.digest('hex');
    return signature === calculatedSignature;
}

const data = {
    data: "hello"
};

// client sending signed message to server using client shared key
const clientSharedKey = client.computeSecret(server.getPublicKey('hex'), 'hex');
const signature = signMessage(JSON.stringify(data), clientSharedKey.toString('hex'));

// server verifying signature using server shared key
const serverSharedKey = server.computeSecret(client.getPublicKey('hex'), 'hex');
console.log("un-tampered data is valid:", verifySignature(JSON.stringify(data), signature, serverSharedKey.toString('hex')));
// client submitted a tampered data
console.log("tampered data is valid:", verifySignature(JSON.stringify({...data, data: "hello1"}), signature, serverSharedKey.toString('hex')));