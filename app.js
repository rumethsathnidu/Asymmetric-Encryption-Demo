// Helper functions
function ab2b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b642ab(b64) {
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
async function exportKeyPEM(key, type) {
  const exported = await window.crypto.subtle.exportKey(type, key);
  const b64 = ab2b64(exported);
  let pem = '';
  if (type === 'spki') {
    pem = `-----BEGIN PUBLIC KEY-----\n`;
  } else {
    pem = `-----BEGIN PRIVATE KEY-----\n`;
  }
  for (let i = 0; i < b64.length; i += 64) {
    pem += b64.slice(i, i + 64) + '\n';
  }
  pem += type === 'spki' ? '-----END PUBLIC KEY-----' : '-----END PRIVATE KEY-----';
  return pem;
}
async function importPublicKeyPEM(pem, algo = 'RSA-OAEP') {
  const b64 = pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '');
  const buf = b642ab(b64);
  return await window.crypto.subtle.importKey(
    'spki',
    buf,
    {
      name: algo,
      hash: 'SHA-256',
    },
    true,
    [algo === 'RSA-OAEP' ? 'encrypt' : 'verify']
  );
}
async function importPrivateKeyPEM(pem, algo = 'RSA-OAEP') {
  const b64 = pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '');
  const buf = b642ab(b64);
  return await window.crypto.subtle.importKey(
    'pkcs8',
    buf,
    {
      name: algo,
      hash: 'SHA-256',
    },
    true,
    [algo === 'RSA-OAEP' ? 'decrypt' : 'sign']
  );
}
function setStatus(el, msg, type = 'info') {
  el.innerHTML = msg;
  el.className = 'status' + (type === 'error' ? ' error' : '');
}
function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text);
  btn.textContent = 'Copied!';
  setTimeout(() => { btn.textContent = 'Copy'; }, 1200);
}
function toggleShowHide(btn, row, value, labelShow, labelHide, setValue) {
  value = !value;
  if (value) {
    row.classList.remove('hide');
    setValue();
    btn.textContent = labelHide;
  } else {
    row.classList.add('hide');
    btn.textContent = labelShow;
  }
  return value;
}

document.addEventListener('DOMContentLoaded', () => {
  // State objects
  const receiver = {
    publicKey: undefined, privateKey: undefined, exportedPub: undefined, exportedPriv: undefined,
    pubShown: false, privShown: false,
    lastBase64: undefined, lastEncrypted: undefined, lastDecrypted: undefined, lastDecoded: undefined
  };
  const sender = {
    publicKey: undefined, privateKey: undefined, exportedPub: undefined, exportedPriv: undefined,
    pubShown: false, privShown: false,
    lastPlain: undefined, lastEncoded: undefined, lastEncrypted: undefined, lastBase64: undefined, lastRecvPub: undefined
  };
  const signer = {
    publicKey: undefined, privateKey: undefined, exportedPub: undefined, exportedPriv: undefined,
    pubShown: false, privShown: false,
    lastSignature: undefined
  };

  // Receiver panel
  const recv = receiver;
  document.getElementById('recvGenKeysBtn').onclick = async () => {
    setStatus(document.getElementById('recvKeyStatus'), '<span class="icon">⏳</span>Generating keys...');
    document.getElementById('recvGenKeysBtn').disabled = true;
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
        }, true, ['encrypt', 'decrypt']
      );
      recv.publicKey = keyPair.publicKey;
      recv.privateKey = keyPair.privateKey;
      recv.exportedPub = await exportKeyPEM(recv.publicKey, 'spki');
      recv.exportedPriv = await exportKeyPEM(recv.privateKey, 'pkcs8');
      setStatus(document.getElementById('recvKeyStatus'), '<span class="icon">✅</span>Key pair generated!');
    } catch (e) {
      setStatus(document.getElementById('recvKeyStatus'), '<span class="icon">❌</span>Failed to generate keys.', 'error');
      document.getElementById('recvGenKeysBtn').disabled = false;
    }
  };
  document.getElementById('recvTogglePub').onclick = function() {
    recv.pubShown = toggleShowHide(
      this,
      document.getElementById('recvPublicKeyRow'),
      recv.pubShown,
      'Show Public Key',
      'Hide Public Key',
      () => { document.getElementById('recvPublicKey').textContent = recv.exportedPub || ''; }
    );
  };
  document.getElementById('recvTogglePriv').onclick = function() {
    recv.privShown = toggleShowHide(
      this,
      document.getElementById('recvPrivateKey'),
      recv.privShown,
      'Show Private Key',
      'Hide Private Key',
      () => { document.getElementById('recvPrivateKey').textContent = recv.exportedPriv || ''; }
    );
  };
  document.getElementById('recvCopyPubBtn').onclick = function() {
    if (recv.exportedPub) {
      const b64 = recv.exportedPub.replace(/-----.*?-----/g, '').replace(/\s+/g, '');
      copyToClipboard(b64, this);
    }
  };
  document.getElementById('recvDecryptBtn').onclick = async () => {
    document.getElementById('recvDecPreview').style.display = 'none';
    document.getElementById('recvDecrypted').textContent = '';
    const b64 = document.getElementById('recvPasteEnc').value.trim();
    if (!b64) {
      setStatus(document.getElementById('recvKeyStatus'), '<span class="icon">❗</span>Please paste the encrypted message.', 'error');
      return;
    }
    if (!recv.privateKey) {
      setStatus(document.getElementById('recvKeyStatus'), '<span class="icon">❗</span>Generate your key pair first.', 'error');
      return;
    }
    try {
      setStatus(document.getElementById('recvKeyStatus'), '<span class="icon">⏳</span>Decrypting...');
      recv.lastBase64 = b64;
      recv.lastEncrypted = b642ab(b64);
      recv.lastDecrypted = await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' }, recv.privateKey, recv.lastEncrypted
      );
      const dec = new TextDecoder();
      recv.lastDecoded = dec.decode(recv.lastDecrypted);
      document.getElementById('recvDecrypted').textContent = recv.lastDecoded;
      setStatus(document.getElementById('recvKeyStatus'), '<span class="icon">✅</span>Message decrypted!');
    } catch (e) {
      setStatus(document.getElementById('recvKeyStatus'), '<span class="icon">❌</span>Decryption failed.', 'error');
    }
  };
  document.getElementById('recvDecPreviewToggle').onclick = function() {
    const box = document.getElementById('recvDecPreview');
    if (box.style.display === 'block') {
      box.style.display = 'none';
      this.textContent = 'Show Decryption Steps';
    } else {
      let preview = '';
      if (recv.lastBase64 !== undefined) preview += `1. Encrypted (Base64): ${recv.lastBase64}\n`;
      if (recv.lastEncrypted !== undefined) preview += `2. Encrypted (raw bytes): [${Array.from(new Uint8Array(recv.lastEncrypted || []))}]\n`;
      if (recv.lastDecrypted !== undefined) preview += `3. Decrypted (UTF-8 bytes): [${Array.from(new Uint8Array(recv.lastDecrypted || []))}]\n`;
      if (recv.lastDecoded !== undefined) preview += `4. Plaintext: "${recv.lastDecoded}"`;
      box.textContent = preview;
      box.style.display = 'block';
      this.textContent = 'Hide Decryption Steps';
    }
  };
  document.getElementById('recvResetBtn').onclick = () => {
    Object.assign(recv, {
      publicKey: undefined, privateKey: undefined, exportedPub: undefined, exportedPriv: undefined,
      pubShown: false, privShown: false, lastBase64: undefined, lastEncrypted: undefined, lastDecrypted: undefined, lastDecoded: undefined
    });
    document.getElementById('recvPublicKeyRow').classList.add('hide');
    document.getElementById('recvPrivateKey').classList.add('hide');
    document.getElementById('recvTogglePub').textContent = 'Show Public Key';
    document.getElementById('recvTogglePriv').textContent = 'Show Private Key';
    setStatus(document.getElementById('recvKeyStatus'), '');
    document.getElementById('recvGenKeysBtn').disabled = false;
    document.getElementById('recvPasteEnc').value = '';
    document.getElementById('recvDecrypted').textContent = '';
    document.getElementById('recvDecPreview').style.display = 'none';
  };

  // Sender panel
  const send = sender;
  document.getElementById('sendGenKeysBtn').onclick = async () => {
    setStatus(document.getElementById('sendKeyStatus'), '<span class="icon">⏳</span>Generating keys...');
    document.getElementById('sendGenKeysBtn').disabled = true;
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
        }, true, ['encrypt', 'decrypt']
      );
      send.publicKey = keyPair.publicKey;
      send.privateKey = keyPair.privateKey;
      send.exportedPub = await exportKeyPEM(send.publicKey, 'spki');
      send.exportedPriv = await exportKeyPEM(send.privateKey, 'pkcs8');
      setStatus(document.getElementById('sendKeyStatus'), '<span class="icon">✅</span>Key pair generated!');
    } catch (e) {
      setStatus(document.getElementById('sendKeyStatus'), '<span class="icon">❌</span>Failed to generate keys.', 'error');
      document.getElementById('sendGenKeysBtn').disabled = false;
    }
  };
  document.getElementById('sendTogglePub').onclick = function() {
    send.pubShown = toggleShowHide(
      this,
      document.getElementById('sendPublicKey'),
      send.pubShown,
      'Show Public Key',
      'Hide Public Key',
      () => { document.getElementById('sendPublicKey').textContent = send.exportedPub || ''; }
    );
  };
  document.getElementById('sendTogglePriv').onclick = function() {
    send.privShown = toggleShowHide(
      this,
      document.getElementById('sendPrivateKey'),
      send.privShown,
      'Show Private Key',
      'Hide Private Key',
      () => { document.getElementById('sendPrivateKey').textContent = send.exportedPriv || ''; }
    );
  };
  document.getElementById('sendEncryptBtn').onclick = async () => {
    document.getElementById('sendEncPreview').style.display = 'none';
    document.getElementById('sendEncrypted').textContent = '';
    const recvPubPEM = document.getElementById('sendRecvPub').value.trim();
    const msg = document.getElementById('sendMessage').value;
    if (!recvPubPEM) {
      setStatus(document.getElementById('sendKeyStatus'), '<span class="icon">❗</span>Paste the receiver\'s public key.', 'error');
      return;
    }
    if (!msg) {
      setStatus(document.getElementById('sendKeyStatus'), '<span class="icon">❗</span>Type a message to encrypt.', 'error');
      return;
    }
    try {
      setStatus(document.getElementById('sendKeyStatus'), '<span class="icon">⏳</span>Encrypting...');
      send.lastRecvPub = recvPubPEM;
      const pubKey = await importPublicKeyPEM(recvPubPEM);
      send.lastPlain = msg;
      const enc = new TextEncoder();
      send.lastEncoded = enc.encode(msg);
      send.lastEncrypted = await window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' }, pubKey, send.lastEncoded
      );
      send.lastBase64 = ab2b64(send.lastEncrypted);
      document.getElementById('sendEncrypted').textContent = send.lastBase64;
      setStatus(document.getElementById('sendKeyStatus'), '<span class="icon">✅</span>Message encrypted!');
    } catch (e) {
      setStatus(document.getElementById('sendKeyStatus'), '<span class="icon">❌</span>Encryption failed.', 'error');
    }
  };
  document.getElementById('sendEncPreviewToggle').onclick = function() {
    const box = document.getElementById('sendEncPreview');
    if (box.style.display === 'block') {
      box.style.display = 'none';
      this.textContent = 'Show Encryption Steps';
    } else {
      let preview = '';
      if (send.lastPlain !== undefined) preview += `1. Plaintext: "${send.lastPlain}"\n`;
      if (send.lastEncoded !== undefined) preview += `2. Encoded (UTF-8 bytes): [${Array.from(send.lastEncoded || [])}]\n`;
      if (send.lastEncrypted !== undefined) preview += `3. Encrypted (raw bytes): [${Array.from(new Uint8Array(send.lastEncrypted || []))}]\n`;
      if (send.lastBase64 !== undefined) preview += `4. Encrypted (Base64): ${send.lastBase64}`;
      box.textContent = preview;
      box.style.display = 'block';
      this.textContent = 'Hide Encryption Steps';
    }
  };
  document.getElementById('sendCopyEncBtn').onclick = function() {
    const text = document.getElementById('sendEncrypted').textContent;
    if (!text) return;
    copyToClipboard(text, this);
  };
  document.getElementById('sendResetBtn').onclick = () => {
    Object.assign(send, {
      publicKey: undefined, privateKey: undefined, exportedPub: undefined, exportedPriv: undefined,
      pubShown: false, privShown: false, lastPlain: undefined, lastEncoded: undefined, lastEncrypted: undefined, lastBase64: undefined, lastRecvPub: undefined
    });
    document.getElementById('sendPublicKey').classList.add('hide');
    document.getElementById('sendPrivateKey').classList.add('hide');
    document.getElementById('sendTogglePub').textContent = 'Show Public Key';
    document.getElementById('sendTogglePriv').textContent = 'Show Private Key';
    setStatus(document.getElementById('sendKeyStatus'), '');
    document.getElementById('sendGenKeysBtn').disabled = false;
    document.getElementById('sendRecvPub').value = '';
    document.getElementById('sendMessage').value = '';
    document.getElementById('sendEncrypted').textContent = '';
    document.getElementById('sendEncPreview').style.display = 'none';
  };

  // Sign & Verify panel
  const sign = signer;
  document.getElementById('signGenKeysBtn').onclick = async () => {
    setStatus(document.getElementById('signKeyStatus'), '<span class="icon">⏳</span>Generating signing keys...');
    document.getElementById('signGenKeysBtn').disabled = true;
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256',
        }, true, ['sign', 'verify']
      );
      sign.publicKey = keyPair.publicKey;
      sign.privateKey = keyPair.privateKey;
      sign.exportedPub = await exportKeyPEM(sign.publicKey, 'spki');
      sign.exportedPriv = await exportKeyPEM(sign.privateKey, 'pkcs8');
      setStatus(document.getElementById('signKeyStatus'), '<span class="icon">✅</span>Signing key pair generated!');
    } catch (e) {
      setStatus(document.getElementById('signKeyStatus'), '<span class="icon">❌</span>Failed to generate signing keys.', 'error');
      document.getElementById('signGenKeysBtn').disabled = false;
    }
  };
  document.getElementById('signTogglePub').onclick = function() {
    sign.pubShown = toggleShowHide(
      this,
      document.getElementById('signPublicKeyRow'),
      sign.pubShown,
      'Show Signing Public Key',
      'Hide Signing Public Key',
      () => { document.getElementById('signPublicKey').textContent = sign.exportedPub || ''; }
    );
  };
  document.getElementById('signTogglePriv').onclick = function() {
    sign.privShown = toggleShowHide(
      this,
      document.getElementById('signPrivateKeyRow'),
      sign.privShown,
      'Show Signing Private Key',
      'Hide Signing Private Key',
      () => { document.getElementById('signPrivateKey').textContent = sign.exportedPriv || ''; }
    );
  };
  document.getElementById('signCopyPubBtn').onclick = function() {
    if (sign.exportedPub) copyToClipboard(sign.exportedPub, this);
  };
  document.getElementById('signCopyPrivBtn').onclick = function() {
    if (sign.exportedPriv) copyToClipboard(sign.exportedPriv, this);
  };
  document.getElementById('signBtn').onclick = async () => {
    document.getElementById('signStatus').textContent = '';
    document.getElementById('signature').textContent = '';
    const msg = document.getElementById('signMessage').value;
    if (!msg) {
      setStatus(document.getElementById('signStatus'), '<span class="icon">❗</span>Type a message to sign.', 'error');
      return;
    }
    if (!sign.privateKey) {
      setStatus(document.getElementById('signStatus'), '<span class="icon">❗</span>Generate the signing key pair first.', 'error');
      return;
    }
    try {
      setStatus(document.getElementById('signStatus'), '<span class="icon">⏳</span>Signing...');
      const enc = new TextEncoder();
      const data = enc.encode(msg);
      const signature = await window.crypto.subtle.sign(
        { name: 'RSA-PSS', saltLength: 32 }, sign.privateKey, data
      );
      sign.lastSignature = signature;
      const b64 = ab2b64(signature);
      document.getElementById('signature').textContent = b64;
      setStatus(document.getElementById('signStatus'), '<span class="icon">✅</span>Message signed!');
    } catch (e) {
      setStatus(document.getElementById('signStatus'), '<span class="icon">❌</span>Signing failed.', 'error');
    }
  };
  document.getElementById('copySignBtn').onclick = function() {
    const text = document.getElementById('signature').textContent;
    if (!text) return;
    copyToClipboard(text, this);
  };
  document.getElementById('verifyBtn').onclick = async () => {
    document.getElementById('verifyStatus').textContent = '';
    const msg = document.getElementById('verifyMessage').value;
    const b64sig = document.getElementById('verifySignature').value.trim();
    const pubPEM = document.getElementById('verifyPubKey').value.trim();
    if (!msg || !b64sig || !pubPEM) {
      setStatus(document.getElementById('verifyStatus'), '<span class="icon">❗</span>Fill in all fields.', 'error');
      return;
    }
    try {
      setStatus(document.getElementById('verifyStatus'), '<span class="icon">⏳</span>Verifying...');
      const enc = new TextEncoder();
      const data = enc.encode(msg);
      const sig = b642ab(b64sig);
      const pubKey = await importPublicKeyPEM(pubPEM, 'RSA-PSS');
      const valid = await window.crypto.subtle.verify(
        { name: 'RSA-PSS', saltLength: 32 }, pubKey, sig, data
      );
      if (valid) {
        setStatus(document.getElementById('verifyStatus'), '<span class="icon">✅</span>Signature is valid!');
      } else {
        setStatus(document.getElementById('verifyStatus'), '<span class="icon">❌</span>Signature is NOT valid!', 'error');
      }
    } catch (e) {
      setStatus(document.getElementById('verifyStatus'), '<span class="icon">❌</span>Verification failed.', 'error');
    }
  };
}); 