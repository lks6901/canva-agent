import express from "express";
import multer from "multer";
import crypto from "crypto";

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Page d'accueil simple
app.get("/", (req, res) => {
  res.send(`
    <h1>Canva Agent</h1>
    <p>Le serveur fonctionne ✅</p>
    <p>Prochaine étape : connexion à Canva</p>
  `);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Serveur lancé sur le port", PORT);
});
