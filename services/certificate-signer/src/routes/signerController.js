const {getRequestBody, isValidHttpUrl, fetchTemplate} = require("../utils");
const {generateCredentials, verifyCredentials} = require("../services/signerService");
const {signingKeyType} = require('../../config/keys');

/**
 * Check if a URL is allowed (not targeting private/internal networks).
 * Rejects URLs containing private IPs, localhost, and cloud metadata endpoints.
 */
function isAllowedUrl(urlString) {
    try {
        const parsed = new URL(urlString);
        const hostname = parsed.hostname.toLowerCase();
        const disallowedPatterns = [
            '169.254',
            '127.0.0.1',
            'localhost',
            '10.',
            '192.168',
            '0.0.0.0',
        ];
        for (const pattern of disallowedPatterns) {
            if (hostname.includes(pattern)) return false;
        }
        // Check 172.16.0.0 - 172.31.255.255 range
        const match172 = hostname.match(/^172\.(\d+)\./);
        if (match172) {
            const second = parseInt(match172[1], 10);
            if (second >= 16 && second <= 31) return false;
        }
        return true;
    } catch (e) {
        return false;
    }
}

const generateCredentialsRoute = async (req) => {
    const reqBody = await getRequestBody(req);
    if (!reqBody || !reqBody.data || !reqBody.credentialTemplate) {
        throw new Error("Missing required fields: 'data' and 'credentialTemplate' must be provided");
    }
    const {data, credentialTemplate} = reqBody;
    let template = credentialTemplate;
    if (typeof template === "string" && isValidHttpUrl(template)) {
        if (!isAllowedUrl(template)) {
            throw new Error("Template URL is not allowed: private or internal network addresses are rejected");
        }
        template = await fetchTemplate(template)
    }

    if (typeof template !== "string") {
        template = JSON.stringify(template)
    }

    return await generateCredentials(data, template);
};


const verifyCredentialsRoute = async (req) => {
    const reqBody = await getRequestBody(req);
    const {signedCredentials, publicKey } = reqBody;

    return await verifyCredentials(signedCredentials, signingKeyType, publicKey);
};


module.exports = {
    generateCredentialsRoute,
    verifyCredentialsRoute,
    isAllowedUrl
};