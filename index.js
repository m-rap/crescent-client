import forge from 'node-forge';

class CrescentClient {
    
    state = {
        privKey: null,
        pubKey: null,
        symKey: null,
        negoState: 0,
        dataIsSent: false,
    }

    
    async post(path, data) {
        this.state.dataIsSent = false;
        let retry = 0;

        while (!this.state.dataIsSent && retry < 5) {
            console.log("nego state: " + this.state.negoState);
            await this.doState(path, data);
            retry++;
        }
    }

    async doState0(path) {
        let opts = null;
        const rsa = forge.pki.rsa;
        const pki = forge.pki;

        const keypair = rsa.generateKeyPair({bits: 2048});
        let pubKeyPem = pki.publicKeyToPem(keypair.publicKey);
        this.state.privKey = keypair.privateKey;
        this.state.pubKey = keypair.publicKey;
        
        opts = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({d1: pubKeyPem, d5: this.state.negoState}),
            credentials: 'include'
        }

        const res = await fetch(path, opts);
        const resJson = await res.json();

        console.log("got response " + JSON.stringify(resJson));

        let encryptedSymKey = forge.util.decode64(resJson.d4);
        this.state.symKey = keypair.privateKey.decrypt(encryptedSymKey, 'RSA-OAEP', {md: forge.md.sha256.create()});

        console.log("decrypted symkey: " + this.state.symKey + " len " + this.state.symKey.length);

        this.state.negoState = 1;
    }

    async doState1(path, data) {
        let opts = null;
        const rsa = forge.pki.rsa;
        const pki = forge.pki;

        console.log("encrypting data before send to server");

        let iv = forge.random.getBytesSync(16);

        let symKeyBuff = forge.util.createBuffer(this.state.symKey);
        let ivBuff = forge.util.createBuffer(iv);
        console.log("create encryption cipher key "+ symKeyBuff.toHex() +" iv " + ivBuff.toHex());
        let cipher = forge.cipher.createCipher('AES-CBC', this.state.symKey);

        console.log("start cipher");
        cipher.start({iv: iv});
        cipher.update(forge.util.createBuffer(JSON.stringify(data)));
        cipher.finish();
        console.log("cipher finished");

        let encryptedData = cipher.output.bytes();
        let encryptedData64 = forge.util.encode64(encryptedData);
        let iv64 = forge.util.encode64(iv);
        let d2 = iv64+"\\n"+encryptedData64;
        console.log("iv " + iv64 + " d2 " + d2);

        opts = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({d2: d2, d5: this.state.negoState}),
            credentials: 'include'
        }

        console.log("sending to server");

        const res = await fetch(path, opts);
        const resJson = await res.json();

        console.log("got response from server " + JSON.stringify(resJson));

        console.log("decoding base64");
        let tmp = forge.util.decode64(resJson.d2);
        let resEncryptedData = forge.util.createBuffer(tmp);
        console.log("resEncryptedData " + resEncryptedData.toHex() + " len " + resEncryptedData.length());

        console.log("creating decipher, key "+ symKeyBuff.toHex() + " iv " + ivBuff.toHex());
        //console.log("creating decipher, mode unpad true, key "+ symKeyBuff.toHex() + " iv " + ivBuff.toHex());
        let decipher = forge.cipher.createDecipher('AES-CBC', this.state.symKey);
        //decipher.mode.unpad = true;
        console.log("start decipher");
        decipher.start({iv: iv});
        decipher.update(resEncryptedData);
        let result = decipher.finish();
        let resDecryptedData = decipher.output.bytes();
        console.log("decipher finished aaa "+result);
        console.log("resDecryptedData " + typeof resDecryptedData + ", " + resDecryptedData + " " + decipher.output.toHex() + " len " +
            decipher.output.length());
        //let resDecryptedDataStr = String.fromCharCode(resDecryptedData);
        //console.log("resDecryptedData string: " + resDecryptedDataStr);
        let resData = JSON.parse(resDecryptedData);
        console.log("res from server: " + resData);
        this.state.dataIsSent = true;
    }

    async doState(path, data) {
        if (this.state.negoState == 0) {
            await this.doState0(path);
        } else if (this.state.negoState == 1) {
            await this.doState1(path, data);
        }
    }
}

export default CrescentClient;