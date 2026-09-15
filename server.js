/**
 * SUMBANE SHARE — VPS Tunnel Relay Server
 *
 * Architecture:
 *   Owner Android → WebSocket (WSS) → This Server → Internet
 *   Guest Android  → WebSocket (WSS) → This Server → Internet
 *
 * The server:
 *   1. Authenticates clients via JWT (validated against PHP API)
 *   2. Associates Owner and Guest sessions
 *   3. Forwards IP packets between Owner and Internet
 *   4. Forwards IP packets between Guest and Internet
 *   5. Tracks usage statistics
 *
 * Requirements:
 *   - Node.js >= 18
 *   - ws library
 *   - jsonwebtoken library
 *   - Root privileges (for raw socket / TUN operations)
 *
 * Deployment:
 *   npm install
 *   node server.js
 *
 * For production, use PM2 or systemd.
 */

require('dotenv').config();
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const http = require('http');
const url = require('url');
const crypto = require('crypto');

// =============================================================================
// CONFIGURATION
// =============================================================================
const CONFIG = {
  port: Number.isInteger(Number(process.env.PORT)) && Number(process.env.PORT) > 0
  ? Number(process.env.PORT)
  : (Number.isInteger(Number(process.env.TUNNEL_PORT)) && Number(process.env.TUNNEL_PORT) > 0
    ? Number(process.env.TUNNEL_PORT)
    : 10000),
  host: process.env.TUNNEL_HOST || '0.0.0.0',
  jwtSecret: process.env.JWT_SECRET || 'change-me-in-production',
  apiBaseUrl: process.env.API_BASE_URL || 'http://localhost:8000/api',
  pingInterval: 15000,
  pingTimeout: 30000,
  maxFrameSize: 65535,
};

// =============================================================================
// TUNNEL SESSION MANAGEMENT
// =============================================================================

/**
 * Represents an active tunnel session.
 * Each session has an Owner and optionally a Guest.
 */
class TunnelSession {
  constructor(sessionId, ownerClient) {
    this.sessionId = sessionId;
    this.owner = ownerClient;
    this.guest = null;
    this.status = 'connecting';
    this.startedAt = Date.now();
    this.lastHeartbeat = Date.now();
    this.bytesUp = 0;
    this.bytesDown = 0;
    this.packetsUp = 0;
    this.packetsDown = 0;
  }

  setGuest(client) {
    this.guest = client;
    this.status = 'active';
    this.lastHeartbeat = Date.now();
  }

  removeGuest() {
    this.guest = null;
    this.status = 'owner_only';
  }

  heartbeat() {
    this.lastHeartbeat = Date.now();
  }

  isExpired(timeoutMs = 600000000) {
    return Date.now() - this.lastHeartbeat > timeoutMs;
  }

  getStats() {
    return {
      sessionId: this.sessionId,
      status: this.status,
      bytesUp: this.bytesUp,
      bytesDown: this.bytesDown,
      packetsUp: this.packetsUp,
      packetsDown: this.packetsDown,
      duration: Math.floor((Date.now() - this.startedAt) / 1000),
    };
  }
}

// =============================================================================
// CLIENT CONNECTION
// =============================================================================

class TunnelClient {
  constructor(ws, sessionId, role) {
    this.ws = ws;
    this.sessionId = sessionId;
    this.role = role; // 'owner' or 'guest'
    this.authenticated = false;
    this.userId = null;
    this.deviceId = null;
    this.connectedAt = Date.now();
    this.lastPing = Date.now();
  }

  send(data) {
    try {
      // Frame format: 4-byte little-endian length + payload
      const frame = Buffer.alloc(4 + data.length);
      frame.writeUInt32LE(data.length, 0);
      data.copy(frame, 4);
      this.ws.send(frame, { binary: true });
    } catch (e) {
      console.error(`[Tunnel] Send error to ${this.role}:`, e.message);
    }
  }

  sendText(text) {
    try {
      this.ws.send(text);
    } catch (e) {
      console.error(`[Tunnel] Send text error to ${this.role}:`, e.message);
    }
  }

  close(code = 1000, reason = 'normal') {
    try {
      this.ws.close(code, reason);
    } catch (e) {
      // ignore
    }
  }
}

// =============================================================================
// TUNNEL SERVER
// =============================================================================

class TunnelServer {
  constructor() {
    this.sessions = new Map(); // sessionId -> TunnelSession
    this.clients = new Map(); // ws -> TunnelClient
    this.pendingAuth = new Map(); // ws -> { sessionId, role }
  }

  /**
   * Validates a JWT token by calling the PHP API.
   * Falls back to local validation if API is unreachable.
   */
  async validateToken(token) {
    try {
      // Try to validate via PHP API
      const response = await fetch(`${CONFIG.apiBaseUrl}/auth/validate?token=${encodeURIComponent(token)}`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success && data.data) {
          return {
            valid: true,
            userId: data.data.user_id,
            username: data.data.username,
          };
        }
      }
    } catch (e) {
      console.warn('[Tunnel] API validation failed, trying local:', e.message);
    }

    // Fallback: local JWT validation
    try {
      const decoded = jwt.verify(token, CONFIG.jwtSecret);
      if (decoded && decoded.sub) {
        return {
          valid: true,
          userId: decoded.sub,
          username: decoded.username || `user_${decoded.sub}`,
        };
      }
    } catch (e) {
      console.warn('[Tunnel] Local JWT validation failed:', e.message);
    }

    return { valid: false };
  }

  /**
   * Validates a session with the PHP API.
   */
  async validateSession(sessionId, guestUserId) {
    try {
      const response = await fetch(`${CONFIG.apiBaseUrl}/sharing/validate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          session_id: sessionId,
          guest_user_id: guestUserId,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        return data.success && data.data;
      }
    } catch (e) {
      console.warn('[Tunnel] Session validation failed:', e.message);
    }
    return false;
  }

  /**
   * Handles a new WebSocket connection.
   */
  handleConnection(ws, req) {
    const params = new URLSearchParams(url.parse(req.url).query);
    const token = params.get('token');
    const sessionId = params.get('session_id');
    const role = params.get('role') || 'owner';

    console.log(`[Tunnel] New connection: role=${role}, session=${sessionId}`);

    if (!token || !sessionId) {
      console.warn('[Tunnel] Missing token or session_id');
      ws.close(4001, 'Missing token or session_id');
      return;
    }

    // Store pending auth info
    this.pendingAuth.set(ws, { sessionId, role });

    // Send auth request
    ws.send(JSON.stringify({
      type: 'auth_request',
      message: 'Please authenticate',
    }));

    // Set timeout for auth
    ws.authTimeout = setTimeout(() => {
      console.warn('[Tunnel] Auth timeout');
      ws.close(4002, 'Auth timeout');
      this.pendingAuth.delete(ws);
    }, 10000);
  }

  /**
   * Handles authentication message from client.
   */
  async handleAuth(ws, message) {
    const pending = this.pendingAuth.get(ws);
    if (!pending) {
      ws.close(4003, 'No pending auth');
      return;
    }

    clearTimeout(ws.authTimeout);

    const { sessionId, role } = pending;
    const token = message.token;

    if (!token) {
      ws.close(4004, 'Missing token');
      this.pendingAuth.delete(ws);
      return;
    }

    // Validate token
    const authResult = await this.validateToken(token);
    if (!authResult.valid) {
      console.warn(`[Tunnel] Invalid token for ${role}`);
      ws.close(4005, 'Invalid token');
      this.pendingAuth.delete(ws);
      return;
    }

    // Create client
    const client = new TunnelClient(ws, sessionId, role);
    client.authenticated = true;
    client.userId = authResult.userId;
    client.deviceId = message.device_id;

    this.clients.set(ws, client);
    this.pendingAuth.delete(ws);

    console.log(`[Tunnel] Authenticated: ${role} user=${authResult.userId} session=${sessionId}`);

    // Send auth success
    client.sendText(JSON.stringify({
      type: 'auth_success',
      user_id: authResult.userId,
      session_id: sessionId,
    }));

    // Handle session logic
    this.handleSessionAuth(client);
  }

  /**
   * Handles session association after authentication.
   */
  async handleSessionAuth(client) {
    const session = this.sessions.get(client.sessionId);

    if (client.role === 'owner') {
      if (session) {
        // Session already exists, close old owner
        console.log(`[Tunnel] Replacing owner for session ${client.sessionId}`);
        session.owner?.close(1000, 'Replaced by new owner');
      }

      const newSession = new TunnelSession(client.sessionId, client);
      this.sessions.set(client.sessionId, newSession);

      client.sendText(JSON.stringify({
        type: 'session_started',
        session_id: client.sessionId,
        message: 'Owner connected',
      }));

      console.log(`[Tunnel] Owner started session ${client.sessionId}`);

    } else if (client.role === 'guest') {
      if (!session) {
        console.warn(`[Tunnel] No session found for guest ${client.sessionId}`);
        client.sendText(JSON.stringify({
          type: 'session_error',
          message: 'Session not found',
        }));
        client.close(4006, 'Session not found');
        return;
      }

      // Validate guest authorization via API
      const authorized = await this.validateSession(client.sessionId, client.userId);
      if (!authorized) {
        console.warn(`[Tunnel] Guest not authorized: user=${client.userId} session=${client.sessionId}`);
        client.sendText(JSON.stringify({
          type: 'session_error',
          message: 'Not authorized for this session',
        }));
        client.close(4007, 'Not authorized');
        return;
      }

      session.setGuest(client);
      client.sendText(JSON.stringify({
        type: 'session_started',
        session_id: client.sessionId,
        message: 'Guest connected',
      }));

      // Notify owner
      session.owner?.sendText(JSON.stringify({
        type: 'guest_connected',
        session_id: client.sessionId,
        user_id: client.userId,
      }));

      console.log(`[Tunnel] Guest joined session ${client.sessionId}: user=${client.userId}`);
    }
  }

  /**
   * Handles binary IP packet from client.
   */
  handlePacket(client, data) {
    const session = this.sessions.get(client.sessionId);
    if (!session) {
      console.warn(`[Tunnel] Packet for unknown session: ${client.sessionId}`);
      return;
    }

    // Update stats
    if (client.role === 'owner') {
      session.bytesUp += data.length;
      session.packetsUp++;
    } else if (client.role === 'guest') {
      session.bytesUp += data.length;
      session.packetsUp++;
    }

    session.heartbeat();

    // In a real implementation, this is where we would:
    // 1. Parse the IP packet
    // 2. Route it to the appropriate destination
    // 3. Send it to the Internet via the VPS's network interface
    // 4. Receive the response
    // 5. Send it back through the WebSocket

    // For now, we log the packet and echo it back (placeholder)
    console.log(`[Tunnel] Packet: ${client.role} → ${data.length} bytes (session=${client.sessionId})`);

    // TODO: Implement actual packet forwarding
    // This requires:
    // - Raw sockets or TUN interface on the VPS
    // - NAT/routing configuration
    // - IP packet parsing and reassembly
  }

  /**
   * Handles text messages (control messages).
   */
  handleTextMessage(client, text) {
    try {
      const msg = JSON.parse(text);

      switch (msg.type) {
        case 'auth':
          this.handleAuth(client.ws, msg);
          break;

        case 'start_session':
          client.sendText(JSON.stringify({
            type: 'session_started',
            session_id: client.sessionId,
          }));
          break;

        case 'heartbeat':
          client.lastPing = Date.now();
          client.sendText(JSON.stringify({
            type: 'pong',
            ts: Date.now(),
          }));
          const session = this.sessions.get(client.sessionId);
          if (session) session.heartbeat();
          break;

        case 'usage_update':
          // Forward usage to PHP API
          this.reportUsage(client, msg.data);
          break;

        default:
          console.log(`[Tunnel] Unknown message type: ${msg.type}`);
      }
    } catch (e) {
      console.error('[Tunnel] Message parse error:', e.message);
    }
  }

  /**
   * Reports usage statistics to the PHP API.
   */
  async reportUsage(client, data) {
    try {
      await fetch(`${CONFIG.apiBaseUrl}/usage/update`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          session_id: client.sessionId,
          upload_bytes: data.upload_bytes || 0,
          download_bytes: data.download_bytes || 0,
        }),
      });
    } catch (e) {
      console.warn('[Tunnel] Usage report failed:', e.message);
    }
  }

  /**
   * Cleans up expired sessions.
   */
  cleanup() {
    const now = Date.now();
    for (const [sessionId, session] of this.sessions) {
      if (session.isExpired()) {
        console.log(`[Tunnel] Cleaning up expired session: ${sessionId}`);
        session.owner?.close(1001, 'Session expired');
        session.guest?.close(1001, 'Session expired');
        this.sessions.delete(sessionId);
      }
    }
  }

  /**
   * Gets server statistics.
   */
  getStats() {
    return {
      activeSessions: this.sessions.size,
      totalClients: this.clients.size,
      sessions: Array.from(this.sessions.values()).map(s => s.getStats()),
    };
  }
}

// =============================================================================
// MAIN SERVER
// =============================================================================

const tunnelServer = new TunnelServer();

// Create HTTP server for health checks
const server = http.createServer((req, res) => {
  if (req.url === '/health' || req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      ...tunnelServer.getStats(),
    }));
  } else {
    res.writeHead(404);
    res.end('Not Found');
  }
});

// Create WebSocket server
const wss = new WebSocket.Server({ server, path: '/ws/tunnel' });

wss.on('connection', (ws, req) => {
  console.log('[Tunnel] Client connected');
  tunnelServer.handleConnection(ws, req);

  ws.on('message', (data) => {
    const client = tunnelServer.clients.get(ws);
    if (!client) {
      // Not yet authenticated, might be auth message
      if (typeof data === 'string') {
        try {
          const msg = JSON.parse(data);
          if (msg.type === 'auth') {
            tunnelServer.handleAuth(ws, msg);
          }
        } catch (e) {
          console.warn('[Tunnel] Unexpected message before auth');
        }
      }
      return;
    }

    if (Buffer.isBuffer(data) || data instanceof Buffer) {
      // Binary packet
      tunnelServer.handlePacket(client, data);
    } else {
      // Text message
      tunnelServer.handleTextMessage(client, data.toString());
    }
  });

  ws.on('close', () => {
    const client = tunnelServer.clients.get(ws);
    if (client) {
      console.log(`[Tunnel] Client disconnected: ${client.role} session=${client.sessionId}`);
      const session = tunnelServer.sessions.get(client.sessionId);
      if (session) {
        if (client.role === 'owner') {
          session.owner = null;
          session.status = 'disconnected';
          session.guest?.close(1001, 'Owner disconnected');
          tunnelServer.sessions.delete(client.sessionId);
        } else if (client.role === 'guest') {
          session.removeGuest();
          session.owner?.sendText(JSON.stringify({
            type: 'guest_disconnected',
            session_id: client.sessionId,
          }));
        }
      }
      tunnelServer.clients.delete(ws);
    }
    tunnelServer.pendingAuth.delete(ws);
  });

  ws.on('error', (err) => {
    console.error('[Tunnel] WebSocket error:', err.message);
  });
});

// Start server
server.listen(CONFIG.port, CONFIG.host, () => {
  console.log(`[Tunnel] SUMBANE SHARE Tunnel Server listening on ${CONFIG.host}:${CONFIG.port}`);
  console.log(`[Tunnel] WebSocket endpoint: ws://${CONFIG.host}:${CONFIG.port}/ws/tunnel`);
  console.log(`[Tunnel] API base: ${CONFIG.apiBaseUrl}`);
});

// Cleanup expired sessions periodically
setInterval(() => {
  tunnelServer.cleanup();
}, 30000);

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[Tunnel] Shutting down...');
  wss.clients.forEach((ws) => {
    ws.close(1001, 'Server shutting down');
  });
  server.close(() => {
    console.log('[Tunnel] Server closed');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\n[Tunnel] Received SIGTERM');
  wss.clients.forEach((ws) => {
    ws.close(1001, 'Server shutting down');
  });
  server.close(() => {
    process.exit(0);
  });
});
