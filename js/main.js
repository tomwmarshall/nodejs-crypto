// https://github.com/tomwmarshall/nodejs-crypto.git

var crypto = require('crypto'),
    algorithm = 'aes-256-ctr',
    password = 'd6F3Efeq';

var prompt = require('prompt');
prompt.start();

function encrypt(text){
    var cipher = crypto.createCipher(algorithm,password);
    var crypted = cipher.update(text,'utf8','hex');
    crypted += cipher.final('hex');
    return crypted;
}

function decrypt(text){
    var decipher = crypto.createDecipher(algorithm,password);
    var dec = decipher.update(text,'hex','utf8');
    dec += decipher.final('utf8');
    return dec;
}

prompt.get(['message'], function (err, result) {
    console.log('Message: ' + result.message);
    var m = encrypt(result.message);
    console.log('Encrypted: ' + m);
    console.log('Decrypted: ' + decrypt(m));
});