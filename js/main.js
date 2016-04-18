// https://github.com/tomwmarshall/nodejs-crypto.git

var crypto = require('crypto'),
    algorithm = 'aes-256-ctr',
    password = 'd6F3Efeq';

var prompt = require('prompt');
prompt.start();

function encrypt(text){
    var cipher = crypto.createCipher(algorithm,password);
    var encrypted = cipher.update(text,'utf8','hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decrypt(text){
    var decipher = crypto.createDecipher(algorithm,password);
    var decrypted = decipher.update(text,'hex','utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function hash() {
    const hash = crypto.createHash('sha256');
    hash.update('Hash digest of Enki!');
    var hash_final = hash.digest('hex');
    return hash_final;
}

prompt.get(['message'], function (err, result) {
    console.log('Message: ' + result.message);
    var m = encrypt(result.message);
    console.log('Encrypted: ' + m);
    console.log('Decrypted: ' + decrypt(m));
    console.log('Hash: ' + hash());
});