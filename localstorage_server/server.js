const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();
const PORT = 5000;

const db = new sqlite3.Database(":memory:", (err) => {
  if (err) {
    console.error("Erreur lors de la connexion à la base de données :", err);
  } else {
    console.log("Connexion réussie à la base de données SQLite");
  }
});

db.serialize(() => {
  db.run(
    "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)"
  );
});

app.use(bodyParser.json());
app.use(cookieParser());
app.use(
    cors({
      origin: "http://localhost:3000",
      credentials: true,
    })
  );  
app.use(
  session({
    key: "localstorage_user_sid",
    secret: "s3cr3t_cloud_campusDFS",
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: 600000,
    },
  })
);

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Nom d'utilisateur et mot de passe requis");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashedPassword],
    (err) => {
      if (err) {
        res.status(500).send("Erreur lors de l'enregistrement de l'utilisateur");
      } else {
        res.status(201).send("Utilisateur enregistré avec succès");
      }
    }
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err) {
      return res.status(500).send("Erreur lors de la récupération de l'utilisateur");
    }

    if (!user) {
      return res.status(400).send("Utilisateur non trouvé");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send("Mot de passe incorrect");
    }

    req.session.user = {
      id: user.id,
      username: user.username,
    };
    res.status(200).send({
      id: user.id,
      username: user.username,
    });
  });
});

app.post("/logout", (req, res) => {
  if (req.session.user && req.cookies.localstorage_user_sid) {
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).send("Erreur lors de la déconnexion");
      }
      res.clearCookie("localstorage_user_sid");
      res.status(200).send("Déconnexion réussie");
    });
  } else {
    res.status(400).send("Utilisateur non connecté");
  }
});

app.get("/checkAuth", (req, res) => {
  if (req.session.user && req.cookies.localstorage_user_sid) {
    res.send(req.session.user);
  } else {
    res.status(401).send("Non autorisé");
  }
});

app.listen(PORT, () => {
  console.log(`Serveur en écoute sur le port ${PORT}`);
});
