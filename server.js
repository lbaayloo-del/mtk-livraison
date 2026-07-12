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
  const { password, ...rest } = u;
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
  if (password.length < 4) {
    return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 4 caractères' });
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
    dateInscription: new Date().toLocaleDateString('fr-FR')
  };
  db.users.push(user);
  saveDB(db);

  req.session.userId = user.id;
  res.json({ user: publicUser(user) });
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
