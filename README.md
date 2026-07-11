# MTK Livraison — backend réel

Application Node.js/Express avec inscription, connexion et espace admin
(photos de profil + pièces d'identité/permis, visibles uniquement par l'administrateur).

## Démarrer en local

```bash
npm install
npm start
```

Le site est servi sur http://localhost:3000

Compte admin créé automatiquement au premier lancement :
- Email : `admin@mtklivraison.sn`
- Mot de passe : `admin123`

**⚠️ Changez ce mot de passe avant la mise en ligne** (variable d'environnement `ADMIN_PASSWORD`, voir plus bas).

## Important à propos de mtklivraison.isroot.in

isroot.in fournit uniquement un **nom de domaine gratuit** (gestion DNS) — ce n'est pas un hébergeur.
Il vous faut donc, en plus :

1. **Un hébergeur qui exécute du Node.js** (ce site n'est pas un simple HTML statique,
   c'est une application avec une base de données). Options simples et gratuites/pas chères :
   - [Render.com](https://render.com) (offre gratuite, le plus simple pour démarrer)
   - [Railway.app](https://railway.app)
   - Un VPS (Contabo, DigitalOcean, Hostinger VPS...) si vous voulez tout contrôler

2. **Pointer le DNS** de `mtklivraison.isroot.in` vers cet hébergeur :
   - Sur Render/Railway : ils vous donnent une adresse (ex: `xxxx.onrender.com`) →
     dans le dashboard isroot.in, ajoutez un enregistrement **CNAME** :
     `mtklivraison` → `xxxx.onrender.com`
   - Sur un VPS : ajoutez un enregistrement **A** pointant vers l'adresse IP du VPS

## Déploiement sur Render (le plus simple)

1. Mettez ce dossier dans un dépôt GitHub (public ou privé).
2. Sur render.com → "New Web Service" → connectez le dépôt.
3. Render détecte Node automatiquement. Réglages :
   - Build command : `npm install`
   - Start command : `npm start`
4. Dans "Environment", ajoutez ces variables :
   - `ADMIN_PASSWORD` = un mot de passe fort pour l'admin
   - `SESSION_SECRET` = une longue chaîne aléatoire secrète
5. Déployez. Une fois en ligne, ajoutez le CNAME dans isroot.in comme expliqué ci-dessus.

**Attention** : sur les hébergeurs gratuits type Render, le disque n'est pas toujours permanent
(il peut être réinitialisé à chaque redéploiement). Pour un vrai usage en production avec des
inscriptions durables, prévoyez soit un plan avec disque persistant, soit migrez `db.json` et
les photos vers un stockage externe (ex: une vraie base PostgreSQL + un service de stockage
comme Cloudinary ou S3 pour les images). Je peux vous aider à faire cette migration si besoin.

## Structure

```
server.js          → le serveur (routes /api/register, /api/login, /api/admin/users...)
public/index.html  → le site (frontend)
uploads/            → photos de profil et permis envoyés par les utilisateurs
db.json             → base de données (créée automatiquement)
```
