# Velo - Instant P2P File Transfer

**Velo** is a peer-to-peer file transfer app that works entirely in the browser. No upload limits, no server storage, just instant streaming between devices.

## 🚀 Features

- **Instant Transfers**: Files stream directly between browsers using WebRTC
- **No Server Storage**: Your files never touch any server
- **Unlimited Size**: No artificial file size limits
- **Works Everywhere**: Deploy on Vercel, Netlify, GitHub Pages, or any static host

## 📦 Deployment

### Vercel (Recommended)

1. Push this repo to GitHub
2. Import to [Vercel](https://vercel.com/new)
3. Set:
   - **Framework Preset**: Other
   - **Root Directory**: `public`
   - **Build Command**: (leave empty)
   - **Output Directory**: `.`
4. Deploy!

### Netlify

1. Push this repo to GitHub
2. Import to [Netlify](https://app.netlify.com/start)
3. Set:
   - **Publish Directory**: `public`
4. Deploy!

### Local Development

```bash
npm install
npm run dev
```

Then open http://localhost:3000

## 🔧 How It Works

Velo uses [PeerJS](https://peerjs.com/) for WebRTC signaling. When you host:

1. You get a unique Peer ID (e.g., `VELO-ABC123`)
2. Share this ID with the person you want to connect
3. They enter your ID to establish a direct connection
4. Files transfer directly between browsers

## 📁 Project Structure

```
public/
├── index.html      # Landing page
├── app.html        # Main application
├── css/
│   └── style.css   # Design system
└── js/
    ├── theme.js    # Light/Dark mode
    └── velo-app.js # Main app logic (PeerJS)
```

## 🎨 Tech Stack

- **Frontend**: Vanilla HTML/CSS/JS
- **P2P**: PeerJS (WebRTC wrapper)
- **Design**: Custom CSS with Light/Dark themes
- **Fonts**: Outfit, Space Grotesk

## 📄 License

MIT
