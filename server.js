// server.js — Calendario WFG con Supabase + Login + Roles + "posteado"
import express from "express";
import cors from "cors";
import session from "express-session";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

// ===============================
// Path helpers
// ===============================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===============================
// Express app
// ===============================
const app = express();
const PORT = process.env.PORT || 3000;

// Render usa proxy → necesario para que funcionen cookies
app.set("trust proxy", 1);

app.use(express.json());
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

// ===============================
// Sesión (login persistente)
// ===============================
// secure: false para que la cookie se guarde bien en Render y local.
app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret-wfg",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      sameSite: "lax",
    },
  })
);

// ===============================
// Supabase
// ===============================
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  console.error("❌ Faltan SUPABASE_URL o SUPABASE_SERVICE_ROLE_KEY");
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);

// ===============================
// Static frontend
// ===============================
app.use(express.static(path.join(__dirname, "public")));

// ===============================
// Middlewares de autenticación
// ===============================
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "No autenticado" });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "No autenticado" });
  if (req.session.user.role !== "admin") {
    return res.status(403).json({ error: "No autorizado (admin requerido)" });
  }
  next();
}

// ===============================
// Rutas de login
// ===============================

// POST /api/login  — { email, password }
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: "Email y contraseña obligatorios" });
  }

  const { data: user, error } = await supabase
    .from("marketing_users")
    .select("id, email, password, role, active")
    .eq("email", email)
    .maybeSingle();

  if (error) {
    console.error("Supabase error login:", error);
    return res.status(500).json({ error: "Error interno" });
  }

  if (!user || !user.active) {
    return res.status(401).json({ error: "Credenciales inválidas" });
  }

  if (user.password !== password) {
    return res.status(401).json({ error: "Credenciales inválidas" });
  }

  // Guardar sesión
  req.session.user = {
    id: user.id,
    email: user.email,
    role: user.role,
  };

  res.json({ success: true, user: req.session.user });
});

// POST /api/logout
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// ===============================
// Rutas de eventos (CRUD)
// ===============================

// GET /api/events?start=YYYY-MM-DD&end=YYYY-MM-DD
app.get("/api/events", requireAuth, async (req, res) => {
  const { start, end } = req.query;

  if (!start || !end) {
    return res.status(400).json({ error: "start y end son obligatorios" });
  }

  const { data, error } = await supabase
    .from("marketing_events")
    .select("*")
    .gte("date", start)
    .lte("date", end)
    .order("date", { ascending: true })
    .order("time", { ascending: true });

  if (error) {
    console.error("Supabase error leyendo eventos:", error);
    return res.status(500).json({ error: "Error al obtener eventos" });
  }

  res.json(data || []);
});

// POST /api/events — Crea evento
app.post("/api/events", requireAuth, async (req, res) => {
  const { date, time, title, channel, platform, notes } = req.body;

  if (!date || !time || !title) {
    return res.status(400).json({ error: "date, time, title obligatorios" });
  }

  const { data, error } = await supabase
    .from("marketing_events")
    .insert({
      date,
      time,
      title,
      channel: channel || null,
      platform: platform || null,
      notes: notes || null,
      created_by: req.session.user.id,
      // posted usa default false en la DB
    })
    .select("*")
    .single();

  if (error) {
    console.error("Supabase error creando evento:", error);
    return res.status(500).json({ error: "Error al crear evento" });
  }

  res.json(data);
});

// PUT /api/events/:id — editor/admin
app.put("/api/events/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { date, time, title, channel, platform, notes } = req.body;

  if (!date || !time || !title) {
    return res.status(400).json({ error: "date, time, title obligatorios" });
  }

  const { data, error } = await supabase
    .from("marketing_events")
    .update({
      date,
      time,
      title,
      channel: channel || null,
      platform: platform || null,
      notes: notes || null,
    })
    .eq("id", id)
    .select("*")
    .maybeSingle();

  if (error) {
    console.error("Supabase error editando evento:", error);
    return res.status(500).json({ error: "Error al actualizar evento" });
  }

  if (!data) return res.status(404).json({ error: "No existe" });

  res.json(data);
});

// POST /api/events/:id/toggle-posted — marcar / desmarcar posteado
app.post("/api/events/:id/toggle-posted", requireAuth, async (req, res) => {
  const { id } = req.params;

  const { data: existing, error: fetchError } = await supabase
    .from("marketing_events")
    .select("id, posted")
    .eq("id", id)
    .maybeSingle();

  if (fetchError) {
    console.error("Supabase error leyendo evento (toggle):", fetchError);
    return res.status(500).json({ error: "Error interno" });
  }

  if (!existing) {
    return res.status(404).json({ error: "Evento no encontrado" });
  }

  const newPosted = !existing.posted;

  const { data, error: updateError } = await supabase
    .from("marketing_events")
    .update({ posted: newPosted })
    .eq("id", id)
    .select("*")
    .maybeSingle();

  if (updateError) {
    console.error("Supabase error toggling posted:", updateError);
    return res.status(500).json({ error: "Error al actualizar estado" });
  }

  res.json(data);
});

// DELETE /api/events/:id — SOLO admin
app.delete("/api/events/:id", requireAdmin, async (req, res) => {
  const { id } = req.params;

  const { error } = await supabase
    .from("marketing_events")
    .delete()
    .eq("id", id);

  if (error) {
    console.error("Supabase error eliminando evento:", error);
    return res.status(500).json({ error: "Error al eliminar evento" });
  }

  res.json({ success: true });
});

// ===============================
// Start server
// ===============================
app.listen(PORT, () => {
  console.log(`🚀 Calendario WFG corriendo en http://localhost:${PORT}`);
});
