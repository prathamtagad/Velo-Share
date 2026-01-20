const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Room management
const rooms = new Map();

// Generate unique room code
function generateRoomCode() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    for (let i = 0; i < 6; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return code;
}

// Generate unique user ID
function generateUserId() {
    return 'user_' + Math.random().toString(36).substr(2, 9);
}

wss.on('connection', (ws) => {
    const userId = generateUserId();
    ws.userId = userId;
    ws.roomCode = null;

    console.log(`User connected: ${userId}`);

    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data);
            handleMessage(ws, message);
        } catch (error) {
            console.error('Invalid message:', error);
        }
    });

    ws.on('close', () => {
        console.log(`User disconnected: ${ws.userId}`);
        leaveRoom(ws);
    });

    // Send user their ID
    ws.send(JSON.stringify({
        type: 'connected',
        userId: userId
    }));
});

function handleMessage(ws, message) {
    switch (message.type) {
        case 'create-room':
            createRoom(ws, message.username);
            break;
        case 'join-room':
            joinRoom(ws, message.roomCode, message.username);
            break;
        case 'leave-room':
            leaveRoom(ws);
            break;
        case 'offer':
        case 'answer':
        case 'ice-candidate':
            relaySignaling(ws, message);
            break;
        case 'file-info':
            broadcastToRoom(ws, message);
            break;
        case 'file-request':
        case 'file-chunk':
        case 'file-complete':
            relayToUser(ws, message);
            break;
    }
}

function createRoom(ws, username) {
    let roomCode = generateRoomCode();
    while (rooms.has(roomCode)) {
        roomCode = generateRoomCode();
    }

    rooms.set(roomCode, {
        code: roomCode,
        users: new Map([[ws.userId, { ws, username, userId: ws.userId }]]),
        createdAt: Date.now()
    });

    ws.roomCode = roomCode;
    ws.username = username;

    ws.send(JSON.stringify({
        type: 'room-created',
        roomCode: roomCode,
        users: [{ id: ws.userId, username }]
    }));

    console.log(`Room created: ${roomCode} by ${username}`);
}

function joinRoom(ws, roomCode, username) {
    const room = rooms.get(roomCode.toUpperCase());

    if (!room) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Room not found'
        }));
        return;
    }

    // Leave current room if in one
    if (ws.roomCode) {
        leaveRoom(ws);
    }

    // Add user to room
    room.users.set(ws.userId, { ws, username, userId: ws.userId });
    ws.roomCode = roomCode.toUpperCase();
    ws.username = username;

    // Get list of all users in room
    const userList = Array.from(room.users.values()).map(u => ({
        id: u.userId,
        username: u.username
    }));

    // Notify the joining user
    ws.send(JSON.stringify({
        type: 'room-joined',
        roomCode: roomCode.toUpperCase(),
        users: userList
    }));

    // Notify other users in the room
    room.users.forEach((user, oderId) => {
        if (user.userId !== ws.userId) {
            user.ws.send(JSON.stringify({
                type: 'user-joined',
                user: { id: ws.userId, username },
                users: userList
            }));
        }
    });

    console.log(`${username} joined room: ${roomCode}`);
}

function leaveRoom(ws) {
    if (!ws.roomCode) return;

    const room = rooms.get(ws.roomCode);
    if (!room) return;

    room.users.delete(ws.userId);

    // Notify other users
    const userList = Array.from(room.users.values()).map(u => ({
        id: u.userId,
        username: u.username
    }));

    room.users.forEach((user) => {
        user.ws.send(JSON.stringify({
            type: 'user-left',
            userId: ws.userId,
            users: userList
        }));
    });

    // Delete room if empty
    if (room.users.size === 0) {
        rooms.delete(ws.roomCode);
        console.log(`Room deleted: ${ws.roomCode}`);
    }

    ws.roomCode = null;
}

function relaySignaling(ws, message) {
    const room = rooms.get(ws.roomCode);
    if (!room) return;

    const targetUser = room.users.get(message.targetId);
    if (targetUser) {
        targetUser.ws.send(JSON.stringify({
            ...message,
            senderId: ws.userId,
            senderName: ws.username
        }));
    }
}

function broadcastToRoom(ws, message) {
    const room = rooms.get(ws.roomCode);
    if (!room) return;

    room.users.forEach((user) => {
        if (user.userId !== ws.userId) {
            user.ws.send(JSON.stringify({
                ...message,
                senderId: ws.userId,
                senderName: ws.username
            }));
        }
    });
}

function relayToUser(ws, message) {
    const room = rooms.get(ws.roomCode);
    if (!room) return;

    const targetUser = room.users.get(message.targetId);
    if (targetUser) {
        targetUser.ws.send(JSON.stringify({
            ...message,
            senderId: ws.userId
        }));
    }
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🚀 PyShare P2P Server Running!                          ║
║                                                           ║
║   Local:   http://localhost:${PORT}                         ║
║                                                           ║
║   Share files at lightning speed! ⚡                      ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
});
