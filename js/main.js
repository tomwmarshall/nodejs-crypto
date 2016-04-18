// https://github.com/tomwmarshall/nodejs-crypto.git

var crypto = require('crypto'),
    algorithm = 'aes-256-ctr',
    password = 'd6F3Efeq';

var prompt = require('prompt');
prompt.start();

function e_text(text){
    var cipher = crypto.createCipher(algorithm,password);
    var encrypted = cipher.update(text,'utf8','hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function d_text(text){
    var decipher = crypto.createDecipher(algorithm,password);
    var decrypted = decipher.update(text,'hex','utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function e_buffer(buffer) {
    var cipher = crypto.createCipher(algorithm, password);
    var encrypt = Buffer.concat([cipher.update(buffer), cipher.final()]);
    return encrypt;
}

function d_buffer(buffer) {
    var decipher = crypto.createDecipher(algorithm, password);
    var decrypt = Buffer.concat([decipher.update(buffer), decipher.final()]);
    return decrypt;
}

function hash() {
    const hash = crypto.createHash('sha256');
    hash.update('Hash digest of Enki!');
    var hash_final = hash.digest('hex');
    return hash_final;
}

function hmac() {
    const hmac = crypto.createHmac('sha256', 'a secret');
    hmac.update('test');
    console.log(hmac.digest('hex'));
}

function signature() {
    const sign = crypto.createSign('RSA-SHA256');
    sign.update('Digital Signature Required.');

    // example, needs real getters implementation
    // const private_key = getThePrivateKey();
    // var digi_sign = (sign.sign(private_key, 'hex'));
    return digi_sign;
}

function verifySign() {
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update('Data to sign.');

    // example, needs real getters implementation
    // const public_key = getPublicKey();
    // const signature = getSignature();
    // var verified = (verify.verify(public_key, signature));
    return verified;
}


prompt.get(['message'], function (err, result) {
    console.log('Message: ' + result.message);
    var m = e_text(result.message);
    console.log('Encrypted text: ' + m);
    console.log('Decrypted text: ' + d_text(m));
    console.log('Hash: ' + hash());
    console.log('Hmac: ' + hmac());
    // console.log('Digital Signature: ' + signature());
    // console.log('Verified Signature: ' + verifySign());

    var b = e_buffer(new Buffer("Enki encrypts", 'utf8'));

    console.log('Encrypted buffer: ' + b);
    console.log('Decrypted buffer: ' + d_buffer(b).toString('utf8'));
});