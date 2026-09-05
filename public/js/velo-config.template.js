/**
 * Velo Share - Deployment Configuration Template
 * 
 * Copy or rename this file to `velo-config.js` or inject window.VELO_CONFIG
 * in your deployment build process (e.g. Netlify/Vercel/Docker env injection).
 * 
 * In production:
 * 1. Ephemeral TURN Token Service (Recommended):
 *    Provide `turnTokenEndpoint` returning short-lived credentials from your
 *    backend or managed provider (e.g. Metered, Twilio NTS, Cloudflare Calls).
 * 
 * 2. Static / Self-Hosted TURN (Coturn):
 *    Supply `iceServers` with coturn credentials.
 */

window.VELO_CONFIG = {
    // Option A: Backend endpoint delivering ephemeral TURN credentials
    // turnTokenEndpoint: '/api/turn-credentials',

    // Option B: Static deployment-configured TURN server(s)
    // Replace with your actual coturn or managed TURN provider details.
    // Notice: Never commit private production passwords to public git repositories.
    iceServers: [
        // STUN is automatically included by default in config.js.
        // Add your production TURN servers below:
        /*
        {
            urls: [
                "turn:turn.yourdomain.com:3478?transport=udp",
                "turn:turn.yourdomain.com:3478?transport=tcp",
                "turns:turn.yourdomain.com:5349?transport=tcp"
            ],
            username: "velo-user",
            credential: "your-turn-password"
        }
        */
    ]
};
