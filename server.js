// server.js
// Backend real compatível com Termux

import express from "express";
import cors from "cors";
import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import bcrypt from "bcryptjs";
import { nanoid } from "nanoid";
import { Resend } from "resend";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = 3001;

/* ================== MIDDLEWARE ================== */
app.use(cors());
app.use(express.json());
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname, "public")));

/* ================== DATABASE ================== */
const adapter = new JSONFile("db.json");
const db = new Low(adapter, {
  users: [],
  resetCodes: []
});

await db.read();
await db.write();

/* ================== RESEND ================== */
const resend = new Resend("re_YWQS4epQ_AsuV4f1YdzVFhdnX4azBdB5k");

/* ================== REGISTER ================== */
app.post("/register", async (req, res) => {
  const { username, email, phone, password, confirmPassword } = req.body;

  if (!username || !email || !phone || !password || !confirmPassword) {
    return res.status(400).json({ error: "Preencha todos os campos" });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: "As senhas não coincidem" });
  }

  const exists = db.data.users.find(u => u.email === email);
  if (exists) {
    return res.status(400).json({ error: "Email já cadastrado" });
  }

  const hash = await bcrypt.hash(password, 10);

  db.data.users.push({
    id: nanoid(),
    username,
    email,
    phone,
    password: hash
  });

  await db.write();
  res.json({ success: true });
});

/* ================== LOGIN ================== */
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Preencha todos os campos" });
  }

  const user = db.data.users.find(u => u.email === email);
  if (!user) {
    return res.status(400).json({ error: "Usuário não encontrado" });
  }

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    return res.status(400).json({ error: "Senha incorreta" });
  }

  res.json({
    success: true,
    username: user.username
  });
});

/* ================== FORGOT PASSWORD ================== */
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Informe o email" });
  }

  const user = db.data.users.find(u => u.email === email);
  if (!user) {
    return res.status(400).json({ error: "Email não encontrado" });
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString();

  db.data.resetCodes = db.data.resetCodes.filter(c => c.email !== email);
  db.data.resetCodes.push({ email, code });

  await db.write();

  await resend.emails.send({
    from: "starsapis@outlook.com.br",
    to: email,
    subject: "Código de verificação",
    html: `<h2>Seu código:</h2><h1>${code}</h1>`
  });

  res.json({ success: true });
});

/* ================== VERIFY CODE ================== */
app.post("/verify-code", async (req, res) => {
  const { email, code } = req.body;

  const valid = db.data.resetCodes.find(
    c => c.email === email && c.code === code
  );

  if (!valid) {
    return res.status(400).json({ error: "Código inválido" });
  }

  res.json({ success: true });
});

/* ================== START ================== */
app.listen(PORT, () => {
  console.log(`API rodando em http://localhost:${PORT}`);
});
