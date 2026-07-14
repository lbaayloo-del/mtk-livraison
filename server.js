// MTK Livraison — serveur backend (Express + fichier JSON comme base de données)
// -----------------------------------------------------------------------------
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const DB_FILE = path.join(__dirname, 'db.json');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const ADMIN_EMAIL = 'admin@mtklivraison.sn';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// ---------- Envoi d'emails (via un compte Gmail + mot de passe d'application) ----------
// GMAIL_USER et GMAIL_APP_PASSWORD sont à définir dans les variables d'environnement
// Render (Settings > Environment) — jamais écrits en dur ici.
const GMAIL_USER = process.env.GMAIL_USER || '';
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || '';
const EMAIL_ACTIF = !!(GMAIL_USER && process.env.BREVO_API_KEY);
async function envoyerEmail(to, subject, html) {
  if (!EMAIL_ACTIF) {
    console.log('⚠️ Envoi d\'email ignoré (BREVO_API_KEY non configurée). Destinataire: ' + to);
    return false;
  }
  try {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'api-key': process.env.BREVO_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: JSON.stringify({
        sender: { name: 'MTK Livraison', email: GMAIL_USER },
        to: [{ email: to }],
        subject,
        htmlContent: html
      })
    });
    if (!r.ok) {
      const err = await r.text();
      console.log('❌ Erreur envoi email:', r.status, err);
      return false;
    }
    return true;
  } catch (e) {
    console.log('❌ Erreur envoi email:', e.message);
    return false;
  }
}

// ---------- petite "base de données" fichier JSON ----------
function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { users: [] };
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch (e) { return { users: [] }; }
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function seedAdmin() {
  const db = loadDB();
  if (!db.users.find(u => u.email === ADMIN_EMAIL)) {
    db.users.push({
      id: 'admin',
      role: 'admin',
      prenom: 'Admin',
      nom: 'MTK',
      email: ADMIN_EMAIL,
      password: bcrypt.hashSync(ADMIN_PASSWORD, 10),
      telephone: '',
      photo: '',
      permis: '',
      vehicule: '',
      zone: '',
      dateInscription: new Date().toLocaleDateString('fr-FR')
    });
    saveDB(db);
  }
}
seedAdmin();

function publicUser(u) {
  const { password, tokenVerification, ...rest } = u;
  return rest;
}

// ---------- upload de fichiers (photo de profil / permis) ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname || '').slice(0, 10))
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5 Mo max par fichier
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Seules les images sont acceptées'));
    cb(null, true);
  }
});

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));

app.use(session({
  secret: process.env.SESSION_SECRET || 'mtk-livraison-changez-ce-secret-en-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 jours
    sameSite: 'lax'
  }
}));

// ---------- routes API ----------
app.post('/api/register', (req, res, next) => {
  upload.fields([{ name: 'photo', maxCount: 1 }, { name: 'permis', maxCount: 1 }])(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    next();
  });
}, (req, res) => {
  const { role, prenom, nom, email, telephone, password, vehicule, zone } = req.body;

  if (!['client', 'livreur'].includes(role)) {
    return res.status(400).json({ error: 'Rôle invalide' });
  }
  if (!prenom || !nom || !email || !telephone || !password) {
    return res.status(400).json({ error: 'Merci de remplir tous les champs obligatoires' });
  }
  const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!EMAIL_REGEX.test(String(email).trim())) {
    return res.status(400).json({ error: 'Adresse email invalide (format attendu: nom@exemple.com)' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères' });
  }
  if (!/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins une lettre et un chiffre' });
  }

  const db = loadDB();
  const emailNorm = String(email).trim().toLowerCase();
  if (db.users.find(u => u.email === emailNorm)) {
    return res.status(409).json({ error: 'Un compte existe déjà avec cet email' });
  }
  if (role === 'livreur' && !(req.files && req.files.permis)) {
    return res.status(400).json({ error: 'La photo de la pièce d’identité / permis est obligatoire pour les livreurs' });
  }

  const photo = req.files && req.files.photo ? '/uploads/' + req.files.photo[0].filename : '';
  const permis = req.files && req.files.permis ? '/uploads/' + req.files.permis[0].filename : '';
  const tokenVerification = crypto.randomBytes(24).toString('hex');

  const user = {
    id: 'u' + Date.now() + Math.floor(Math.random() * 1000),
    role,
    prenom: String(prenom).trim(),
    nom: String(nom).trim(),
    email: emailNorm,
    telephone: String(telephone).trim(),
    password: bcrypt.hashSync(password, 10),
    photo,
    permis,
    vehicule: vehicule || '',
    zone: zone || '',
    statut: role === 'livreur' ? 'en_attente' : 'approuve',
    emailVerifie: !EMAIL_ACTIF, // si l'envoi d'email n'est pas configuré, on ne bloque personne
    tokenVerification,
    dateInscription: new Date().toLocaleDateString('fr-FR')
  };
  db.users.push(user);
  saveDB(db);

  if (EMAIL_ACTIF) {
    const lienVerif = req.protocol + '://' + req.get('host') + '/?verifier=' + tokenVerification;
    envoyerEmail(
      user.email,
      'Confirmez votre email — MTK Livraison',
      `<div style="font-family:sans-serif;max-width:480px;margin:auto">
        <h2 style="color:#FF6B00">MTK Livraison</h2>
        <p>Bonjour ${user.prenom},</p>
        <p>Merci de vous être inscrit(e). Cliquez sur le bouton ci-dessous pour confirmer votre adresse email :</p>
        <p style="text-align:center;margin:28px 0">
          <a href="${lienVerif}" style="background:#FF6B00;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold">Confirmer mon email</a>
        </p>
        <p style="font-size:12px;color:#888">Si le bouton ne fonctionne pas, copiez ce lien : ${lienVerif}</p>
      </div>`
    );
  }

  req.session.userId = user.id;
  res.json({ user: publicUser(user) });
});

app.get('/api/verifier-email/:token', (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.tokenVerification === req.params.token);
  if (!user) return res.status(400).json({ error: 'Lien de vérification invalide ou déjà utilisé' });
  user.emailVerifie = true;
  user.tokenVerification = null;
  saveDB(db);
  res.json({ ok: true, email: user.email });
});

app.post('/api/renvoyer-verification', requireLogin, async (req, res) => {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.currentUser.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  if (user.emailVerifie) return res.status(400).json({ error: 'Cet email est déjà vérifié' });
  if (!EMAIL_ACTIF) return res.status(400).json({ error: 'L’envoi d’email n’est pas encore configuré sur le serveur' });

  if (!user.tokenVerification) {
    user.tokenVerification = crypto.randomBytes(24).toString('hex');
    saveDB(db);
  }
  const lienVerif = req.protocol + '://' + req.get('host') + '/?verifier=' + user.tokenVerification;
  const envoye = await envoyerEmail(
    user.email,
    'Confirmez votre email — MTK Livraison',
    `<div style="font-family:sans-serif;max-width:480px;margin:auto">
      <h2 style="color:#FF6B00">MTK Livraison</h2>
      <p>Bonjour ${user.prenom},</p>
      <p>Voici votre nouveau lien de confirmation :</p>
      <p style="text-align:center;margin:28px 0">
        <a href="${lienVerif}" style="background:#FF6B00;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold">Confirmer mon email</a>
      </p>
    </div>`
  );
  if (!envoye) return res.status(500).json({ error: 'Échec de l’envoi de l’email, réessayez plus tard' });
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const db = loadDB();
  const user = db.users.find(u => u.email === String(email || '').trim().toLowerCase());
  if (!user || !bcrypt.compareSync(String(password || ''), user.password)) {
    return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  }
  req.session.userId = user.id;
  res.json({ user: publicUser(user) });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  res.json({ user: user ? publicUser(user) : null });
});

function requireAdmin(req, res, next) {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Accès réservé à l’administrateur' });
  next();
}

function requireLogin(req, res, next) {
  const db = loadDB();
  const user = db.users.find(u => u.id === req.session.userId);
  if (!user) return res.status(401).json({ error: 'Merci de vous connecter' });
  req.currentUser = user;
  next();
}

// ---------- Livreurs disponibles (approuvés) ----------
app.get('/api/livreurs/disponibles', requireLogin, (req, res) => {
  const db = loadDB();
  const livreurs = db.users
    .filter(u => u.role === 'livreur' && u.statut === 'approuve')
    .map(u => ({ id: u.id, prenom: u.prenom, nom: u.nom, photo: u.photo, vehicule: u.vehicule, zone: u.zone }));
  res.json({ livreurs });
});

// ---------- Géocodage & distance réelle (OpenStreetMap Nominatim + OSRM, gratuits) ----------
// Un timeout court est indispensable ici : si le service externe est lent ou injoignable
// (fréquent sur les hébergeurs gratuits), on ne doit jamais bloquer la création de la commande.
async function fetchAvecTimeout(url, options = {}, timeoutMs = 4000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function geocoderAdresse(adresse) {
  try {
    const q = encodeURIComponent(adresse + ', Sénégal');
    const url = `https://nominatim.openstreetmap.org/search?format=json&limit=1&q=${q}`;
    const r = await fetchAvecTimeout(url, { headers: { 'User-Agent': 'MTK-Livraison/1.0 (contact@mtk-sn.com)' } });
    if (!r.ok) return null;
    const data = await r.json();
    if (!data || !data[0]) return null;
    return { lat: parseFloat(data[0].lat), lon: parseFloat(data[0].lon) };
  } catch (e) {
    return null; // timeout, service injoignable, adresse non trouvée... on retombe sur l'estimation
  }
}

async function distanceRouteKm(depart, arrivee) {
  try {
    const url = `https://router.project-osrm.org/route/v1/driving/${depart.lon},${depart.lat};${arrivee.lon},${arrivee.lat}?overview=false`;
    const r = await fetchAvecTimeout(url);
    if (!r.ok) return null;
    const data = await r.json();
    if (!data.routes || !data.routes[0]) return null;
    return Math.round((data.routes[0].distance / 1000) * 10) / 10; // km, arrondi à 0.1
  } catch (e) {
    return null;
  }
}

// Calcule une distance réelle (OSM) si possible, sinon retombe sur l'estimation donnée par le client
async function estimerDistance(depart, arrivee, distanceKmClient) {
  const [pointDepart, pointArrivee] = await Promise.all([geocoderAdresse(depart), geocoderAdresse(arrivee)]);
  if (pointDepart && pointArrivee) {
    const km = await distanceRouteKm(pointDepart, pointArrivee);
    if (km !== null) return { distanceKm: km, source: 'auto' };
  }
  return { distanceKm: Math.max(0, Number(distanceKmClient) || 0), source: 'estimee' };
}

// ---------- Commandes ----------
const TARIF_KM = 150; // FCFA par km, tarif de référence (le livreur peut ensuite proposer un prix différent)

function calculerPrix(prixBase, distanceKm) {
  const base = Number(prixBase) || 500;
  const dist = Math.max(0, Number(distanceKm) || 0);
  return base + Math.round(dist * TARIF_KM);
}

app.post('/api/commandes', requireLogin, async (req, res) => {
  if (req.currentUser.role !== 'client') {
    return res.status(403).json({ error: 'Seuls les clients peuvent passer commande' });
  }
  const { depart, arrivee, typeColis, prixBase, distanceKm, poids, description, telephone, paiement } = req.body || {};
  if (!depart || !arrivee || !typeColis || !telephone) {
    return res.status(400).json({ error: 'Merci de remplir les champs obligatoires (départ, arrivée, type de colis, téléphone)' });
  }

  const { distanceKm: distanceFinale, source: distanceSource } = await estimerDistance(depart, arrivee, distanceKm);

  const db = loadDB();
  if (!db.commandes) db.commandes = [];
  const commande = {
    id: 'c' + Date.now() + Math.floor(Math.random() * 1000),
    clientId: req.currentUser.id,
    depart: String(depart).trim(),
    arrivee: String(arrivee).trim(),
    typeColis: String(typeColis).trim(),
    poids: poids || '',
    description: description || '',
    telephone: String(telephone).trim(),
    paiement: paiement || 'Espèces à la livraison',
    distanceKm: distanceFinale,
    distanceSource, // 'auto' (calculée réellement) ou 'estimee' (donnée par le client, adresse non trouvée)
    prixBase: Number(prixBase) || 500,
    prixSuggere: calculerPrix(prixBase, distanceFinale),
    prix: null, // fixé uniquement quand le client accepte une proposition de livreur
    statut: 'en_attente', // en_attente -> acceptee -> en_route -> livree (ou annulee)
    livreurId: null,
    propositions: [], // [{ livreurId, prix, message, date }]
    dateCreation: new Date().toISOString(),
    dateCreationAffichage: new Date().toLocaleString('fr-FR')
  };
  db.commandes.push(commande);
  saveDB(db);
  res.json({ commande });
});

app.get('/api/commandes/mes', requireLogin, (req, res) => {
  const db = loadDB();
  const commandes = (db.commandes || [])
    .filter(c => c.clientId === req.currentUser.id)
    .sort((a, b) => new Date(b.dateCreation) - new Date(a.dateCreation));
  res.json({ commandes: commandes.map(c => enrichirCommande(c, 'client')) });
});

// Commandes ouvertes, visibles par les livreurs approuvés pour qu'ils proposent un prix
// (routes littérales déclarées AVANT /api/commandes/:id, sinon Express interprète
// "disponibles" ou "livreur" comme une valeur de :id)
app.get('/api/commandes/disponibles', requireLogin, (req, res) => {
  if (req.currentUser.role !== 'livreur') return res.status(403).json({ error: 'Accès réservé aux livreurs' });
  const db = loadDB();
  const commandes = (db.commandes || [])
    .filter(c => c.statut === 'en_attente')
    .sort((a, b) => new Date(b.dateCreation) - new Date(a.dateCreation))
    .map(c => enrichirCommande(c, 'livreur', req.currentUser.id));
  res.json({ commandes });
});

app.get('/api/commandes/livreur', requireLogin, (req, res) => {
  if (req.currentUser.role !== 'livreur') return res.status(403).json({ error: 'Accès réservé aux livreurs' });
  const db = loadDB();
  const commandes = (db.commandes || [])
    .filter(c => c.livreurId === req.currentUser.id)
    .sort((a, b) => new Date(b.dateCreation) - new Date(a.dateCreation));
  res.json({ commandes: commandes.map(c => enrichirCommande(c, 'livreur', req.currentUser.id)) });
});

// Détail d'une commande précise (pour que le client suive les propositions reçues)
// Doit rester APRÈS les routes littérales ci-dessus.
app.get('/api/commandes/:id', requireLogin, (req, res) => {
  const db = loadDB();
  const commande = (db.commandes || []).find(c => c.id === req.params.id);
  if (!commande) return res.status(404).json({ error: 'Commande introuvable' });
  if (commande.clientId !== req.currentUser.id && req.currentUser.role !== 'admin') {
    return res.status(403).json({ error: 'Accès refusé' });
  }
  res.json({ commande: enrichirCommande(commande, 'client') });
});

// vue: 'client' (voit tout, y compris les propositions détaillées) ou 'livreur' (ne voit pas les coordonnées du
// client tant que la commande ne lui est pas attribuée, ni les prix proposés par les autres livreurs)
function enrichirCommande(c, vue, livreurIdCourant) {
  const db = loadDB();
  const client = db.users.find(u => u.id === c.clientId);
  const livreur = c.livreurId ? db.users.find(u => u.id === c.livreurId) : null;
  const estAssigneAMoi = vue === 'livreur' && c.livreurId === livreurIdCourant;

  const base = {
    ...c,
    livreur: livreur ? { id: livreur.id, prenom: livreur.prenom, nom: livreur.nom, photo: livreur.photo, telephone: livreur.telephone, vehicule: livreur.vehicule } : null
  };

  if (vue === 'client') {
    base.client = client ? { prenom: client.prenom, nom: client.nom, telephone: client.telephone } : null;
    base.propositions = (c.propositions || []).map(p => {
      const l = db.users.find(u => u.id === p.livreurId);
      return { ...p, livreur: l ? { id: l.id, prenom: l.prenom, nom: l.nom, photo: l.photo, vehicule: l.vehicule, zone: l.zone } : null };
    });
  } else {
    // vue livreur : coordonnées client cachées tant que la course ne lui est pas attribuée
    base.client = estAssigneAMoi && client ? { prenom: client.prenom, nom: client.nom, telephone: client.telephone } : null;
    base.nbPropositions = (c.propositions || []).length;
    base.maProposition = (c.propositions || []).find(p => p.livreurId === livreurIdCourant) || null;
    delete base.propositions;
  }
  return base;
}

// Un livreur approuvé propose son propre prix pour une commande en attente
app.post('/api/commandes/:id/proposer', requireLogin, (req, res) => {
  if (req.currentUser.role !== 'livreur') return res.status(403).json({ error: 'Accès réservé aux livreurs' });
  if (req.currentUser.statut !== 'approuve') return res.status(403).json({ error: 'Votre compte doit être approuvé avant de proposer un prix' });
  const { prix, message } = req.body || {};
  const prixNum = Number(prix);
  if (!prixNum || prixNum <= 0) return res.status(400).json({ error: 'Merci d’indiquer un prix valide' });

  const db = loadDB();
  const commande = (db.commandes || []).find(c => c.id === req.params.id);
  if (!commande) return res.status(404).json({ error: 'Commande introuvable' });
  if (commande.statut !== 'en_attente') return res.status(400).json({ error: 'Cette commande n’est plus disponible' });

  if (!commande.propositions) commande.propositions = [];
  const existante = commande.propositions.find(p => p.livreurId === req.currentUser.id);
  if (existante) {
    existante.prix = prixNum;
    existante.message = message || '';
    existante.date = new Date().toISOString();
  } else {
    commande.propositions.push({
      livreurId: req.currentUser.id,
      prix: prixNum,
      message: message || '',
      date: new Date().toISOString()
    });
  }
  saveDB(db);
  res.json({ commande: enrichirCommande(commande, 'livreur', req.currentUser.id) });
});

// Le client accepte la proposition d'un livreur précis
app.post('/api/commandes/:id/choisir', requireLogin, (req, res) => {
  const { livreurId } = req.body || {};
  const db = loadDB();
  const commande = (db.commandes || []).find(c => c.id === req.params.id);
  if (!commande) return res.status(404).json({ error: 'Commande introuvable' });
  if (commande.clientId !== req.currentUser.id) return res.status(403).json({ error: 'Cette commande ne vous appartient pas' });
  if (commande.statut !== 'en_attente') return res.status(400).json({ error: 'Cette commande a déjà été attribuée' });

  const proposition = (commande.propositions || []).find(p => p.livreurId === livreurId);
  if (!proposition) return res.status(400).json({ error: 'Proposition introuvable pour ce livreur' });
  const livreur = db.users.find(u => u.id === livreurId && u.role === 'livreur' && u.statut === 'approuve');
  if (!livreur) return res.status(400).json({ error: 'Ce livreur n’est plus disponible' });

  commande.livreurId = livreur.id;
  commande.prix = proposition.prix;
  commande.statut = 'acceptee';
  saveDB(db);
  res.json({ commande: enrichirCommande(commande, 'client') });
});

app.patch('/api/commandes/:id/statut', requireLogin, (req, res) => {
  const { statut } = req.body || {};
  const etapesValides = ['en_route', 'livree', 'annulee'];
  if (!etapesValides.includes(statut)) return res.status(400).json({ error: 'Statut invalide' });
  const db = loadDB();
  const commande = (db.commandes || []).find(c => c.id === req.params.id);
  if (!commande) return res.status(404).json({ error: 'Commande introuvable' });

  const estLivreurAssigne = commande.livreurId === req.currentUser.id;
  const estClientProprietaire = commande.clientId === req.currentUser.id;

  if (statut === 'annulee') {
    if (!estClientProprietaire) return res.status(403).json({ error: 'Seul le client peut annuler sa commande' });
    if (commande.statut === 'livree') return res.status(400).json({ error: 'Impossible d’annuler une commande déjà livrée' });
  } else {
    if (!estLivreurAssigne) return res.status(403).json({ error: 'Seul le livreur assigné peut mettre à jour cette commande' });
  }
  commande.statut = statut;
  saveDB(db);
  res.json({ commande: enrichirCommande(commande, 'client') });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const db = loadDB();
  res.json({ users: db.users.map(publicUser) });
});

app.patch('/api/admin/users/:id/statut', requireAdmin, (req, res) => {
  const { statut } = req.body || {};
  if (!['en_attente', 'approuve', 'refuse'].includes(statut)) {
    return res.status(400).json({ error: 'Statut invalide' });
  }
  const db = loadDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  user.statut = statut;
  saveDB(db);
  res.json({ user: publicUser(user) });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const db = loadDB();
  const target = db.users.find(u => u.id === req.params.id);
  if (target && target.role === 'admin') {
    return res.status(400).json({ error: 'Impossible de supprimer le compte administrateur' });
  }
  db.users = db.users.filter(u => u.id !== req.params.id);
  saveDB(db);
  res.json({ ok: true });
});

// ---------- fichiers statiques du site + fallback SPA ----------
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('✅ MTK Livraison lancé sur le port ' + PORT);
  console.log('   Admin : ' + ADMIN_EMAIL + ' / ' + ADMIN_PASSWORD);
});
