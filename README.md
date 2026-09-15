# SUMBANE SHARE — VPS Tunnel Server

Serveur de relais tunnel pour le partage de connexion Internet à distance.

## Architecture

```
Owner Android ──WSS──► VPS Tunnel Server ──► Internet
Guest Android ──WSS──► VPS Tunnel Server ──► Internet
```

## Prérequis

- Node.js >= 18
- npm ou yarn
- Accès root sur le VPS (pour la configuration réseau)
- Port 8443 ouvert (ou le port configuré)

## Installation

```bash
cd vps/tunnel-server
npm install
cp .env.example .env
# Éditer .env avec vos paramètres
```

## Configuration

Éditez `.env` :

```env
TUNNEL_HOST=0.0.0.0
TUNNEL_PORT=8443
JWT_SECRET=your-secret-key
API_BASE_URL=https://api.sumbaneshare.com/api
```

## Démarrage

```bash
# Développement
npm run dev

# Production
npm start
```

## Déploiement avec PM2

```bash
npm install -g pm2
pm2 start server.js --name sumbane-tunnel
pm2 save
pm2 startup
```

## Firewall

```bash
# UFW
ufw allow 8443/tcp

# iptables
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
```

## Notes importantes

1. **Ce serveur ne transporte PAS chaque paquet Internet via PHP.**
   PHP/MySQL reste le control plane (authentification, sessions, quotas).
   Ce serveur est le data plane (relais de paquets IP).

2. **Pour un déploiement production**, il faut :
   - Configurer SSL/TLS (Let's Encrypt)
   - Mettre en place le forwarding de paquets IP (raw sockets ou TUN)
   - Configurer NAT sur le VPS
   - Limiter les connexions par IP/utilisateur

3. **Sécurité** :
   - Le JWT secret doit être identique à celui du backend PHP
   - Les sessions sont validées via l'API PHP
   - Les timeouts empêchent les connexions orphelines
