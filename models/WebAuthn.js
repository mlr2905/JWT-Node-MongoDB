// models/WebAuthnCredential.js
const mongoose = require('mongoose');

const webAuthnCredentialSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  credentialID: {
    type: String,
    required: true,
    unique: true
  },
  publicKey: {
    type: String,
    required: true
  },
  counter: {
    type: Number,
    default: 0
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { versionKey: false });

const WebAuthnCredential = mongoose.model('WebAuthn', webAuthnCredentialSchema);
module.exports = WebAuthnCredential;
