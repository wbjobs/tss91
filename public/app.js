const webauthnUI = (function () {
  function b64urlToBuffer(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
    const bin = atob(b64 + pad);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  function bufferToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function regOptsToPublicKey(options) {
    const pubKey = {
      challenge: b64urlToBuffer(options.challenge),
      rp: options.rp,
      user: {
        ...options.user,
        id: b64urlToBuffer(options.user.id),
      },
      pubKeyCredParams: options.pubKeyCredParams,
      timeout: options.timeout,
      excludeCredentials: (options.excludeCredentials || []).map(c => ({
        ...c,
        id: b64urlToBuffer(c.id),
      })),
      authenticatorSelection: options.authenticatorSelection,
      attestation: options.attestation,
      extensions: options.extensions,
    };
    return pubKey;
  }

  function authOptsToPublicKey(options) {
    return {
      challenge: b64urlToBuffer(options.challenge),
      timeout: options.timeout,
      rpId: options.rpId,
      allowCredentials: (options.allowCredentials || []).map(c => ({
        ...c,
        id: b64urlToBuffer(c.id),
      })),
      userVerification: options.userVerification,
      extensions: options.extensions,
    };
  }

  function regResponseToJSON(cred) {
    const response = cred.response;
    return {
      id: cred.id,
      rawId: bufferToB64url(cred.rawId),
      response: {
        attestationObject: bufferToB64url(response.attestationObject),
        clientDataJSON: bufferToB64url(response.clientDataJSON),
        transports: response.getTransports ? response.getTransports() : [],
      },
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults(),
      authenticatorAttachment: cred.authenticatorAttachment || null,
    };
  }

  function authResponseToJSON(cred) {
    const response = cred.response;
    return {
      id: cred.id,
      rawId: bufferToB64url(cred.rawId),
      response: {
        authenticatorData: bufferToB64url(response.authenticatorData),
        clientDataJSON: bufferToB64url(response.clientDataJSON),
        signature: bufferToB64url(response.signature),
        userHandle: response.userHandle ? bufferToB64url(response.userHandle) : null,
      },
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults(),
      authenticatorAttachment: cred.authenticatorAttachment || null,
    };
  }

  return {
    b64urlToBuffer,
    bufferToB64url,
    regOptsToPublicKey,
    authOptsToPublicKey,
    regResponseToJSON,
    authResponseToJSON,
  };
})();
