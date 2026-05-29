document.addEventListener('DOMContentLoaded', () => {
    const usernameInput = document.getElementById('username');
    const registerBtn = document.getElementById('registerBtn');
    const authenticateBtn = document.getElementById('authenticateBtn');
    const resultsPre = document.getElementById('results');


    // 1. ArrayBuffer to Base64URL converter (needed for displaying raw data)
    function arrayBufferToBase64Url(buffer) {
        // base64url encoding standard
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, ''); // Remove padding
    }
    
    // 2. Base64URL to ArrayBuffer converter (needed for setting 'allowCredentials')
    function base64UrlToArrayBuffer(base64url) {
        const padding = '='.repeat((4 - base64url.length % 4) % 4);
        const base64 = (base64url + padding)
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray.buffer;
    }

    // 3. Display Results
    const displayResult = (data) => {
        resultsPre.textContent = JSON.stringify(data, null, 2);
    };

    // --- Core WebAuthn Response Parsing Function ---
    
  
    function parseWebAuthnResponse(credential, type) {
        const response = credential.response;
        const rawIdBase64 = arrayBufferToBase64Url(credential.rawId);
        
        let authenticatorDataBuffer;

        if (type === 'registration') {
           
            //authenticatorDataBuffer = response.attestationObject.slice(0, 53); 
            const decodedAttestation = CBOR.decode(response.attestationObject);
            authenticatorDataBuffer = decodedAttestation.authData;
        } else { // authentication
            authenticatorDataBuffer = response.authenticatorData;
        }

        const authenticatorData = new Uint8Array(authenticatorDataBuffer);

        const flags = authenticatorData[32]; 

        const userPresenceFlag = (flags & 0b00000001) > 0;
        const userVerificationFlag = (flags & 0b00000100) > 0;

        // --- Extract AAGUID (Only present in Registration when attested) ---
        //let aaguidBase64 = 'N/A (Not Registered)';
        // Check if the Attested Credential Data (AT) flag (Bit 6) is set
        //if (type === 'registration' && (flags & 0b01000000) > 0) {
            // AAGUID starts after the RP ID Hash (32 bytes), Flags (1 byte), and Sign Count (4 bytes) -> at index 37
          //  const aaguidBytes = authenticatorData.slice(37, 53);
            //aaguidBase64 = arrayBufferToBase64Url(aaguidBytes.buffer);
       // }
        let aaguidBase64 = 'N/A (Not Registered)';
    if (type === 'registration') {
        try {
            // Decode the CBOR-encoded attestationObject
            const decodedAttestation = CBOR.decode(response.attestationObject);
            // authData is inside the decoded object
            const authData = new Uint8Array(decodedAttestation.authData);
            // AAGUID is at bytes 37–53 of the real authData
            const aaguidBytes = authData.slice(37, 53);
            aaguidBase64 = arrayBufferToBase64Url(aaguidBytes.buffer);
        } catch(e) {
            aaguidBase64 = 'CBOR decode failed: ' + e.message;
        }
    }    
        
        // --- Output ---
        return {
            type: type,
            id: rawIdBase64,
            authenticatorDataBase64: arrayBufferToBase64Url(authenticatorDataBuffer),
            // --- Key Analysis Parameters for Thesis ---
            '1. AAGUID (Provider ID)': aaguidBase64, // Used for Metadata Service lookup
            '2. User Presence (UP) Flag': userPresenceFlag, // Was biometric/tap required?
            '3. User Verification (UV) Flag': userVerificationFlag, // Was PIN/biometric check performed?
            '4. Authenticator Data Flags Byte (Decimal)': flags, // Raw flag value
            
            // Raw data for manual inspection
            rawResponseObject: arrayBufferToBase64Url(credential.response.attestationObject || credential.response.authenticatorData)
        };
    }

    // --- 1. Registration Logic ---
    registerBtn.addEventListener('click', async () => {
        const username = usernameInput.value;
        if (!username) { alert("Please enter a username."); return; }

        //const rpId = window.location.hostname; 
        const rpId = window.location.hostname === '127.0.0.1' ? 'localhost' : window.location.hostname;
        console.log(rpId);
        const userId = new TextEncoder().encode(username);

        // WebAuthn Creation Options: Set to request secure features for comparison
        const publicKeyCredentialCreationOptions = {
            challenge: new Uint8Array(32), // Simple 32-byte challenge (needs server-side generation for security)
            rp: { id: rpId, name: 'Thesis RP' },
            user: { id: userId, name: username, displayName: username },
            // Requesting modern algorithms (ES256, EdDSA)
            pubKeyCredParams: [
                { type: 'public-key', alg: -7 },   // ES256 (P-256 curve)
                { type: 'public-key', alg: -8 },   // EdDSA (Ed25519)
                { type: 'public-key', alg: -257 }  // RS256 (for compatibility)
            ],
            authenticatorSelection: {
                userVerification: 'required', // Request biometric/PIN
                requireResidentKey: true,     // Request a discoverable passkey
                // FIX: Setting to 'cross-platform' prioritizes roaming authenticators like Bitwarden extension
                authenticatorAttachment: 'cross-platform', 
            },
            attestation: 'direct', // Request attestation for AAGUID analysis
            timeout: 60000
        };

        try {
            resultsPre.textContent = "Waiting for passkey registration... (Follow the prompt)";
            const credential = await navigator.credentials.create({
                publicKey: publicKeyCredentialCreationOptions
            });
            
            const parsedResponse = parseWebAuthnResponse(credential, 'registration'); 
            displayResult(parsedResponse);
            
            // Store the credential ID for the next authentication step
            localStorage.setItem('credentialId', parsedResponse.id); 

        } catch (error) {
            displayResult({ error: 'Registration failed or cancelled', details: error.message });
        }
    });

    // --- 2. Authentication Logic ---
    authenticateBtn.addEventListener('click', async () => {
        const credentialId = localStorage.getItem('credentialId');
        const allowCredentials = [];

        if (credentialId) {
            // Use the stored ID for targeted authentication
            allowCredentials.push({ 
                id: base64UrlToArrayBuffer(credentialId), 
                type: 'public-key' 
            });
        }
        
        // WebAuthn Request Options:
        const publicKeyCredentialRequestOptions = {
            challenge: new Uint8Array(32), // Simple 32-byte challenge
            allowCredentials: allowCredentials, // Use stored ID, or leave empty for discoverable
            userVerification: 'preferred',
            timeout: 60000,
            //rpId: window.location.hostname
            rpId: window.location.hostname === '127.0.0.1' ? 'localhost' : window.location.hostname,
        };

        try {
            resultsPre.textContent = "Waiting for passkey authentication... (Follow the prompt)";
            const assertion = await navigator.credentials.get({
                publicKey: publicKeyCredentialRequestOptions
            });
            
            const parsedResponse = parseWebAuthnResponse(assertion, 'authentication');
            displayResult(parsedResponse);

        } catch (error) {
            displayResult({ error: 'Authentication failed or cancelled', details: error.message });
        }
    });
});

