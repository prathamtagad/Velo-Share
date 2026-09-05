/**
 * Velo Share - Network & ICE Configuration
 * 
 * Provides STUN and TURN server configuration for WebRTC NAT traversal.
 * Implements real merging:
 * DEFAULT STUN + DEPLOYMENT TURN + OPTIONAL USER TURN CONFIG
 * 
 * Deduplicates equivalent ICE servers and validates structures before
 * passing to PeerJS. Supports dynamic ephemeral TURN token endpoints.
 */

(function () {
    // Standard public STUN servers (free, high availability)
    const DEFAULT_STUN_SERVERS = [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' }
    ];

    const VALID_SCHEMES = ['stun:', 'stuns:', 'turn:', 'turns:'];

    /**
     * Validates a single ICE server object.
     * Returns a sanitized RTCIceServer object, or null if invalid.
     * @param {any} server
     * @returns {RTCIceServer|null}
     */
    function validateIceServer(server) {
        if (!server || typeof server !== 'object') return null;

        let urls = server.urls || server.url;
        if (!urls) return null;

        let urlList = Array.isArray(urls) ? urls : [urls];
        if (urlList.length === 0) return null;

        // Ensure every URL is a non-empty string with a valid scheme
        const validUrls = [];
        for (const u of urlList) {
            if (typeof u !== 'string') continue;
            const trimmed = u.trim();
            const hasValidScheme = VALID_SCHEMES.some(scheme => trimmed.toLowerCase().startsWith(scheme));
            if (hasValidScheme) {
                validUrls.push(trimmed);
            }
        }

        if (validUrls.length === 0) return null;

        const isTurn = validUrls.some(u => {
            const lower = u.toLowerCase();
            return lower.startsWith('turn:') || lower.startsWith('turns:');
        });

        const sanitized = {
            urls: validUrls.length === 1 ? validUrls[0] : validUrls
        };

        if (isTurn) {
            // TURN servers must have valid string username and credential
            const username = typeof server.username === 'string' ? server.username.trim() : '';
            const credential = typeof server.credential === 'string' ? server.credential.trim() : '';

            if (!username || !credential) {
                console.warn('[VeloConfig] Discarding TURN server missing username or credential:', validUrls);
                return null;
            }

            sanitized.username = username;
            sanitized.credential = credential;
        }

        return sanitized;
    }

    /**
     * Merges and deduplicates multiple ICE server arrays:
     * DEFAULT STUN + DEPLOYMENT TURN + USER TURN CONFIG
     * 
     * @param {Array<any>} defaultStun
     * @param {Array<any>} deploymentServers
     * @param {Array<any>} userServers
     * @returns {Array<RTCIceServer>}
     */
    function mergeIceServers(defaultStun = [], deploymentServers = [], userServers = []) {
        const rawPool = [
            ...(Array.isArray(defaultStun) ? defaultStun : []),
            ...(Array.isArray(deploymentServers) ? deploymentServers : []),
            ...(Array.isArray(userServers) ? userServers : [])
        ];

        const validatedList = [];
        const seenKeys = new Set();

        for (const raw of rawPool) {
            const valid = validateIceServer(raw);
            if (!valid) continue;

            // Generate deterministic deduplication fingerprint
            const urlsArray = Array.isArray(valid.urls) ? [...valid.urls].sort() : [valid.urls];
            const urlsKey = urlsArray.map(u => u.toLowerCase()).join('|');
            const userKey = valid.username ? valid.username.toLowerCase() : '';
            const credKey = valid.credential ? valid.credential : '';
            const dedupeFingerprint = `${urlsKey}#${userKey}#${credKey}`;

            if (!seenKeys.has(dedupeFingerprint)) {
                seenKeys.add(dedupeFingerprint);
                validatedList.push(valid);
            }
        }

        // Guarantee at least default STUN fallback if all servers were invalid
        if (validatedList.length === 0) {
            return [...DEFAULT_STUN_SERVERS];
        }

        return validatedList;
    }

    /**
     * Fetches ephemeral/short-lived TURN credentials from a backend or token service if configured.
     * e.g., /api/turn-credentials or Cloudflare Calls / Twilio Network Traversal Service.
     * @param {string} endpoint
     * @returns {Promise<Array<RTCIceServer>>}
     */
    async function fetchEphemeralTurnCredentials(endpoint) {
        if (!endpoint || typeof endpoint !== 'string') return [];
        try {
            const res = await fetch(endpoint, {
                method: 'GET',
                headers: { 'Accept': 'application/json' },
                cache: 'no-store'
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            const servers = Array.isArray(data.iceServers) ? data.iceServers : (Array.isArray(data) ? data : []);
            return servers;
        } catch (err) {
            console.warn('[VeloConfig] Failed to fetch ephemeral TURN credentials:', err);
            return [];
        }
    }

    /**
     * Get the active ICE configuration.
     * Real merge: DEFAULT STUN + DEPLOYMENT TURN + USER TURN CONFIG
     */
    function getIceConfig() {
        let deploymentServers = [];
        let userServers = [];

        // 1. Check for deployment-level configuration
        if (typeof window !== 'undefined' && window.VELO_CONFIG) {
            if (Array.isArray(window.VELO_CONFIG.iceServers)) {
                deploymentServers = window.VELO_CONFIG.iceServers;
            } else if (Array.isArray(window.VELO_CONFIG.turnServers)) {
                deploymentServers = window.VELO_CONFIG.turnServers;
            }
        }

        // 2. Check for user-defined localStorage override
        if (typeof localStorage !== 'undefined') {
            try {
                const saved = localStorage.getItem('velo_custom_ice_servers');
                if (saved) {
                    const parsed = JSON.parse(saved);
                    if (Array.isArray(parsed) && parsed.length > 0) {
                        userServers = parsed;
                    }
                }
            } catch (e) {
                console.warn('[VeloConfig] Failed to parse custom ICE servers from localStorage:', e);
            }
        }

        const iceServers = mergeIceServers(DEFAULT_STUN_SERVERS, deploymentServers, userServers);

        return {
            iceServers,
            iceCandidatePoolSize: 10,
            iceTransportPolicy: 'all' // Allows both direct and relay (TURN) candidates
        };
    }

    /**
     * Save custom ICE servers to localStorage.
     * @param {Array<RTCIceServer>} servers 
     */
    function setCustomIceServers(servers) {
        if (typeof localStorage === 'undefined') return;
        if (!servers || !Array.isArray(servers) || servers.length === 0) {
            localStorage.removeItem('velo_custom_ice_servers');
        } else {
            // Validate before saving
            const validated = servers.map(validateIceServer).filter(Boolean);
            if (validated.length === 0) {
                localStorage.removeItem('velo_custom_ice_servers');
            } else {
                localStorage.setItem('velo_custom_ice_servers', JSON.stringify(validated));
            }
        }
    }

    const configExport = {
        getIceConfig,
        setCustomIceServers,
        mergeIceServers,
        validateIceServer,
        fetchEphemeralTurnCredentials,
        DEFAULT_STUN_SERVERS
    };

    if (typeof window !== 'undefined') {
        window.VeloConfig = configExport;
    }

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = configExport;
    }
})();
