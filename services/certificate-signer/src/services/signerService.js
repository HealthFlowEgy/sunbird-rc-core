const Mustache = require('mustache');
const {signJSON} = require('certificate-signer-library');
const {customLoader, KeyType} = require('certificate-signer-library/signer');
const jsigs = require('jsonld-signatures');
const {Ed25519KeyPair, RSAKeyPair} = require('crypto-ld');
const {Ed25519Signature2018, RsaSignature2018} = jsigs.suites;
const {publicKeyPem, publicKeyBase58} = require('../../config/keys');
const {CERTIFICATE_DID, CERTIFICATE_CONTROLLER_ID, CUSTOM_TEMPLATE_DELIMITERS} = require('../../config/config');
const vc = require('vc-js');
const Handlebars = require("handlebars");
const delimiters = require('handlebars-delimiters');
const hash = require('object-hash');
const {cacheInstance} = require( "../utils" );
delimiters(Handlebars, CUSTOM_TEMPLATE_DELIMITERS);

const getHandleBarTemplate = (credentialTemplate) => {
    const credentialTemplateHash = hash(credentialTemplate);
    if (cacheInstance.has(credentialTemplateHash)) {
        console.debug("Credential template loaded from cache");
        return cacheInstance.get(credentialTemplateHash);
    } else {
        let handleBarTemplate = Handlebars.compile(credentialTemplate);
        cacheInstance.set(credentialTemplateHash, handleBarTemplate);
        console.debug("Credential template stored in cache");
        return handleBarTemplate;
    }
};
/**
 * Remove prototype pollution keys from an object recursively.
 */
function sanitizeData(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.map(sanitizeData);
    const clean = {};
    for (const key of Object.keys(obj)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
        clean[key] = sanitizeData(obj[key]);
    }
    return clean;
}

const generateCredentials = async (data, credentialTemplate = "") => {
    console.log("Credential generation request received");
    const sanitizedData = sanitizeData(data);
    const template = getHandleBarTemplate(credentialTemplate);
    let renderedTemplate = template(sanitizedData);
    //TODO: find better ways to escape literals
    renderedTemplate = renderedTemplate.replaceAll("\\","\\\\");
    const credentialData = JSON.parse(renderedTemplate);
    console.log("Credential data prepared for signing");
    return await signJSON(credentialData);
};

const getPublicKey = (signingKeyType, publicKey = null) => {
    switch (signingKeyType) {
        case KeyType.RSA:
            return {
                '@context': jsigs.SECURITY_CONTEXT_URL,
                id: CERTIFICATE_DID,
                type: 'RsaVerificationKey2018',
                controller: CERTIFICATE_CONTROLLER_ID,
                publicKeyPem: publicKey || publicKeyPem
            };
        case KeyType.ED25519:
            return {
                '@context': jsigs.SECURITY_CONTEXT_URL,
                id: CERTIFICATE_DID,
                type: 'Ed25519VerificationKey2018',
                controller: CERTIFICATE_CONTROLLER_ID,
                publicKeyBase58: publicKey || publicKeyBase58
            };
    }
};

const verifyCredentials = async (signedCredentials, signingKeyType, externalPublicKey=null) => {
    const publicKey = getPublicKey(signingKeyType, externalPublicKey);
    const controller = {
        '@context': jsigs.SECURITY_CONTEXT_URL,
        id: CERTIFICATE_CONTROLLER_ID,
        publicKey: [publicKey],
        // this authorizes this key to be used for making assertions
        assertionMethod: [publicKey.id]
    };
    switch (signingKeyType) {
        case KeyType.RSA:
            return await verifyRSACredentials(controller, signedCredentials, signingKeyType, externalPublicKey);
        case KeyType.ED25519:
            return await verifyED25519Credentials(controller, signedCredentials, signingKeyType, externalPublicKey);
    }
    console.log(result);
    return result;
};

const verifyRSACredentials = async (controller, signedCredentials, signingKeyType, externalPublicKey) => {
    const key = new RSAKeyPair({...getPublicKey(signingKeyType, externalPublicKey)});
    const {AssertionProofPurpose} = jsigs.purposes;
    return await jsigs.verify(signedCredentials, {
        suite: new RsaSignature2018({key}),
        purpose: new AssertionProofPurpose({controller}),
        compactProof: false,
        documentLoader: customLoader
    });
};


async function verifyED25519Credentials(controller, signedCredentials, signingKeyType, externalPublicKey) {
    const key = new Ed25519KeyPair({...getPublicKey(signingKeyType, externalPublicKey)});
    const {AssertionProofPurpose} = jsigs.purposes;
    const purpose = new AssertionProofPurpose({
        controller: controller
    });
    return await vc.verifyCredential({
        credential: signedCredentials,
        suite: new Ed25519Signature2018({key}),
        purpose: purpose,
        documentLoader: customLoader,
        compactProof: false
    });
}

module.exports = {
    generateCredentials,
    verifyCredentials
};