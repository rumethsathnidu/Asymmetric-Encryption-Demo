# Asymmetric Encryption Demo: Sender & Receiver

This web app demonstrates how asymmetric (public-key) encryption and digital signatures work, using real cryptography in your browser. It is designed for beginners and educational use, with interactive panels for both sender and receiver, as well as a digital signature section.

## Features

- **Sender & Receiver Panels:**
  - Generate real RSA key pairs for both sender and receiver.
  - Encrypt messages with the receiver's public key.
  - Decrypt messages with the receiver's private key.
  - Show/hide and copy public/private keys.
  - Step-by-step encryption/decryption previews.

- **Sign & Verify Panel:**
  - Generate a separate signing key pair (RSA-PSS) for digital signatures.
  - Sign messages with the signing private key.
  - Verify signatures with the signing public key.
  - Show/hide and copy signing keys.
  - Clear note that signing keys are separate from encryption keys.

- **User-Friendly UI:**
  - All cryptography is performed in the browser using the Web Crypto API.
  - No data is sent to any server.
  - Responsive and accessible design.

## Setup & Usage

1. **Clone or Download** this repository.
2. **Open `asymmetric-demo.html`** in any modern web browser (Chrome, Firefox, Edge, Safari).
3. **No installation or backend required.**

## File Structure

- `asymmetric-demo.html` — Main HTML file (UI only, no inline JS/CSS)
- `style.css` — All styles for the app
- `app.js` — All JavaScript logic (encryption, signing, UI)
- `README.md` — This file

## How It Works

- **Encryption:**
  - Sender encrypts a message with the receiver's public key (RSA-OAEP).
  - Only the receiver can decrypt it with their private key.
- **Digital Signatures:**
  - Sender signs a message with their signing private key (RSA-PSS).
  - Anyone can verify the signature with the sender's signing public key.
- **Key Pairs:**
  - Encryption and signing use separate key pairs for security and best practice.

## Security Notes

- All cryptographic operations use the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).
- Keys and messages never leave your browser.
- This app is for educational/demo purposes and is not intended for production use or sensitive data.

## License

MIT License 