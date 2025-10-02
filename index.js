import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import upload from './config/multer.js';
import { createClient } from "@supabase/supabase-js";
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Swagger
import swaggerUI from 'swagger-ui-express';
import swaggerDocumentation from './swagger.json' with { type: 'json' };

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

// Middlewares
app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static('uploads'));
app.use(express.json());

// Swagger docs
app.use(
  '/documentacion-api-animalbeats',
  swaggerUI.serve,
  swaggerUI.setup(swaggerDocumentation)
);

// ✅ Cliente Supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// Headers de la API
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', '*');
  next();
});

/* ==========================
*  Rutas de gestión de Usuarios
* ========================== */

// Registro de usuario
app.post('/registro', async (req, res) => {
  const { n_documento, correoelectronico, contrasena, id_documento, nombre } = req.body;

  if (!n_documento || !correoelectronico || !contrasena || !id_documento || !nombre) {
    return res.status(400).json({ mensaje: 'Faltan campos' });
  }

  if (contrasena.length < 8) {
    return res.status(400).json({ mensaje: 'La contraseña debe tener al menos 8 caracteres' });
  }

  try {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(contrasena, salt);

    let id_rol, rolTexto;
    if (correoelectronico.toLowerCase() === 'administrador@animalbeats.com') {
      id_rol = 1; rolTexto = 'admin';
    } else if (correoelectronico.toLowerCase() === 'veterinario@animalbeats.com') {
      id_rol = 3; rolTexto = 'veterinario';
    } else {
      id_rol = 2; rolTexto = 'cliente';
    }

    const { error } = await supabase.from("usuarios").insert([
      {
        n_documento,
        correoelectronico,
        contrasena: hash,
        id_documento,
        nombre,
        id_rol,
        estado: "Activo"
      }
    ]);

    if (error) throw error;

    res.status(201).json({ mensaje: 'Usuario registrado exitosamente', rol: rolTexto });
  } catch (err) {
    console.error("Error en registro:", err);
    res.status(500).json({ mensaje: 'Error al registrar usuario' });
  }
});

// Obtener tipos de documento
app.get('/tiposDocumento', async (req, res) => {
  try {
    const { data, error } = await supabase.from("documento").select("id, tipo");
    if (error) throw error;
    res.status(200).json(data);
  } catch (err) {
    console.error("Error en getTiposDocumento:", err);
    res.status(500).json({ mensaje: 'Error al obtener tipos de documento' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { correoelectronico, contrasena } = req.body;

  try {
    const { data: usuarios, error } = await supabase
      .from("usuarios")
      .select("*")
      .eq("correoelectronico", correoelectronico);

    if (error) throw error;

    if (!usuarios || usuarios.length === 0) {
      return res.status(404).json({ mensaje: 'Usuario no encontrado' });
    }

    const usuario = usuarios[0];
    const esCorrecta = await bcrypt.compare(contrasena, usuario.contrasena);
    if (!esCorrecta) {
      return res.status(401).json({ mensaje: 'Contraseña incorrecta' });
    }

    let rolTexto;
    switch (usuario.id_rol) {
      case 1: rolTexto = 'admin'; break;
      case 2: rolTexto = 'cliente'; break;
      case 3: rolTexto = 'veterinario'; break;
      default: rolTexto = 'desconocido';
    }

    const payload = {
      n_documento: usuario.n_documento,
      nombre: usuario.nombre,
      rol: usuario.id_rol
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    res.json({
      mensaje: 'Inicio de sesión exitoso',
      usuario: {
        n_documento: usuario.n_documento,
        nombre: usuario.nombre,
        correoelectronico: usuario.correoelectronico,
        rol: usuario.id_rol
      },
      rol: rolTexto,
      token
    });

  } catch (err) {
    console.error("Error en login:", err);
    res.status(500).json({ mensaje: 'Error interno al iniciar sesión' });
  }
});

// Listar Usuarios
app.get('/usuario/Listado', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("usuarios")
      .select("n_documento, nombre, correoelectronico, estado, id_rol, documento(tipo)")
      .neq("estado", "Suspendido");

    if (error) throw error;

    res.json({ Usuarios: data });
  } catch (err) {
    console.error('Error al obtener Usuarios:', err);
    res.status(500).json({ error: 'Error al obtener Usuarios' });
  }
});

// Obtener usuario por documento
app.get('/usuario/:n_documento', async (req, res) => {
  const { n_documento } = req.params;
  try {
    const { data, error } = await supabase
      .from("usuarios")
      .select("n_documento, nombre, correoelectronico, documento(tipo)")
      .eq("n_documento", n_documento)
      .maybeSingle();

    if (error) throw error;
    res.json(data || 'Usuario no encontrado');
  } catch (err) {
    console.error('Error al obtener usuario:', err);
    res.status(500).json({ error: 'Error al obtener usuario' });
  }
});

// Crear usuario
app.post('/usuario/Crear', async (req, res) => {
  const { n_documento, nombre, correoelectronico, contrasena, id_documento, id_rol } = req.body;

  try {
    if (id_rol == 1 && correoelectronico.toLowerCase() !== 'administrador@animalbeats.com') {
      return res.status(400).json({ error: 'Solo se permite el correo predeterminado para rol Administrador' });
    }

    const hashedPassword = await bcrypt.hash(contrasena, 10);

    const { error } = await supabase.from("usuarios").insert([
      {
        n_documento,
        nombre,
        correoelectronico,
        contrasena: hashedPassword,
        id_documento,
        id_rol,
        estado: "Activo"
      }
    ]);

    if (error) throw error;

    res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
  } catch (err) {
    console.error('Error al registrar usuario:', err);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// Actualizar usuario
app.put('/usuario/Actualizar/:n_documento', async (req, res) => {
  const { nombre, correoelectronico, id_documento, id_rol } = req.body;
  const { n_documento } = req.params;

  try {
    const { error } = await supabase
      .from("usuarios")
      .update({
        nombre,
        correoelectronico,
        id_documento,
        id_rol,
        estado: "Activo"
      })
      .eq("n_documento", n_documento);

    if (error) throw error;

    res.json({ mensaje: 'Usuario actualizado correctamente' });
  } catch (err) {
    console.error('Error al actualizar usuario:', err);
    res.status(500).json({ error: 'Error al actualizar usuario' });
  }
});

// Suspender usuario
app.put('/usuario/Suspender/:n_documento', async (req, res) => {
  const { n_documento } = req.params;
  try {
    const { error } = await supabase
      .from("usuarios")
      .update({ estado: "Suspendido" })
      .eq("n_documento", n_documento);

    if (error) throw error;
    res.json({ mensaje: 'Usuario suspendido correctamente' });
  } catch (err) {
    console.error('Error al suspender usuario:', err);
    res.status(500).json({ error: 'Error al suspender usuario' });
  }
});

// Reactivar usuario
app.put('/usuario/Reactivar/:n_documento', async (req, res) => {
  const { n_documento } = req.params;
  try {
    const { error } = await supabase
      .from("usuarios")
      .update({ estado: "Activo" })
      .eq("n_documento", n_documento);

    if (error) throw error;
    res.json({ mensaje: 'Usuario reactivado correctamente' });
  } catch (err) {
    console.error('Error al reactivar usuario:', err);
    res.status(500).json({ error: 'Error al reactivar usuario' });
  }
});

// Usuario Pendiente
app.put('/usuario/Pendiente/:n_documento', async (req, res) => {
  const { n_documento } = req.params;
  try {
    const { error } = await supabase
      .from("usuarios")
      .update({ estado: "Pendiente" })
      .eq("n_documento", n_documento);

    if (error) throw error;
    res.json({ mensaje: 'Usuario puesto en estado pendiente correctamente' });
  } catch (err) {
    console.error('Error al poner usuario en pendiente:', err);
    res.status(500).json({ error: 'Error al poner usuario en pendiente' });
  }
});

/* ==========================
*  Rutas de gestión de Roles
* ========================== */

// Listar Roles
app.get('/roles/Listado', async (req, res) => {
  try {
    const { data, error } = await supabase.from("rol").select("id, rol");
    if (error) throw error;
    res.json({ roles: data });
  } catch (err) {
    console.error('Error al obtener roles:', err);
    res.status(500).json({ error: 'Error al obtener roles' });
  }
});

// Crear Rol
app.post('/roles/Crear', async (req, res) => {
  const { rol } = req.body;
  if (!rol || rol.trim() === '') {
    return res.status(400).json({ error: 'El rol es obligatorio' });
  }
  try {
    const { data, error } = await supabase.from("rol").insert([{ rol: rol.trim() }]).select("id").single();
    if (error) throw error;
    res.json({ message: 'Rol creado correctamente', id: data.id });
  } catch (err) {
    console.error('Error al crear rol:', err);
    res.status(500).json({ error: 'Error al crear rol' });
  }
});

// Eliminar Rol
app.delete('/roles/Eliminar/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase.from("rol").delete().eq("id", id);
    if (error) throw error;
    res.json({ message: 'Rol eliminado correctamente' });
  } catch (err) {
    console.error('Error al eliminar rol:', err);
    res.status(500).json({ error: 'Error al eliminar rol' });
  }
});



// ==========================
// Perfil Veterinario
// ==========================

/**
 * Crear veterinario
 */
app.post("/veterinarios/crear", upload.single("imagen"), async (req, res) => {
  try {
    const {
      nombre_completo,
      estudios_especialidad,
      edad: edadRaw,
      altura: alturaRaw,
      anios_experiencia: aniosRaw,
    } = req.body;

    // Validación básica
    if (!nombre_completo || !estudios_especialidad || !edadRaw || !alturaRaw || !aniosRaw) {
      return res.status(400).json({ mensaje: "Faltan campos obligatorios" });
    }

    // Conversión de tipos
    const edad = parseInt(edadRaw, 10);
    const altura = parseFloat(alturaRaw);
    const anios_experiencia = parseInt(aniosRaw, 10);

    if (Number.isNaN(edad) || Number.isNaN(altura) || Number.isNaN(anios_experiencia)) {
      return res.status(400).json({
        mensaje: "Edad, altura o años de experiencia tienen formato inválido",
      });
    }

    // Subida de imagen a Supabase Storage
    let imagen_url = null;
    if (req.file) {
      const fileName = `veterinarios/${Date.now()}_${req.file.originalname}`;

      const { error: uploadError } = await supabase.storage
        .from("img-animalbeats")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: true,
        });

      if (uploadError) throw uploadError;

      const { data: publicUrl } = supabase.storage
        .from("img-animalbeats")
        .getPublicUrl(fileName);

      imagen_url = publicUrl.publicUrl;
    }

    // Insertar en la base de datos con Supabase
    const { data, error } = await supabase
      .from("veterinarios")
      .insert([
        {
          nombre_completo,
          estudios_especialidad,
          edad,
          altura,
          anios_experiencia,
          imagen_url,
          activo: true,
        },
      ])
      .select("id");

    if (error) throw error;

    res.status(201).json({
      mensaje: "Veterinario creado correctamente",
      id: data[0].id,
      imagen_url,
    });
  } catch (err) {
    console.error("🔥 Error al crear veterinario:", err?.message ?? err);
    res.status(500).json({
      error: "Error al crear veterinario",
      details: err?.message || String(err),
    });
  }
});

/**
 * Listar veterinarios activos
 */
app.get("/veterinarios", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("veterinarios")
      .select("*")
      .order("creado_en", { ascending: false });

    if (error) throw error;

    res.json(data);
  } catch (error) {
    console.error("❌ Error al consultar veterinarios:", error?.message ?? error);
    res.status(500).json({ mensaje: "Error al consultar veterinarios" });
  }
});

/**
 * Consultar veterinario por id
 */
app.get("/veterinarios/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase
      .from("veterinarios")
      .select("*")
      .eq("id", id)
      .single();

    if (error) {
      if (error.code === "PGRST116") {
        return res.status(404).json({ mensaje: "Veterinario no encontrado" });
      }
      throw error;
    }

    res.json(data);
  } catch (error) {
    console.error("❌ Error al consultar veterinario:", error?.message ?? error);
    res.status(500).json({ mensaje: "Error al consultar veterinario" });
  }
});

/**
 * Eliminar veterinario (soft delete)
 */
app.delete("/veterinarios/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from("veterinarios")
      .update({ activo: false })
      .eq("id", id);

    if (error) throw error;
    if (!data || data.length === 0) {
      return res.status(404).json({ mensaje: "Veterinario no encontrado" });
    }

    res.json({ mensaje: "Veterinario marcado como eliminado" });
  } catch (error) {
    console.error("❌ Error al eliminar veterinario:", error?.message ?? error);
    res.status(500).json({ mensaje: "Error al eliminar veterinario" });
  }
});

// ==========================
// Dashboards
// ==========================

/**
 * Dashboard Admin
 */
app.get("/admin/dashboard", async (req, res) => {
  try {
    const { data: adminRows, error: adminError } = await supabase
      .from("usuarios")
      .select("nombre, correoelectronico")
      .eq("id_rol", 1)
      .limit(1);

    if (adminError) throw adminError;
    if (!adminRows || adminRows.length === 0) {
      return res.status(404).json({ error: "No se encontró ningún admin" });
    }

    const { count, error: countError } = await supabase
      .from("usuarios")
      .select("*", { count: "exact", head: true })
      .in("id_rol", [2, 3]);

    if (countError) throw countError;

    res.json({
      usuario: {
        nombre: adminRows[0].nombre,
        correo: adminRows[0].correoelectronico,
      },
      total_clientes: count,
    });
  } catch (error) {
    console.error("Error en /admin/dashboard:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

/**
 * Dashboard Cliente
 */
app.get("/cliente/dashboard/:n_documento", async (req, res) => {
  try {
    const { n_documento } = req.params;

    const { data: cliente, error: clienteError } = await supabase
      .from("usuarios")
      .select("nombre, correoelectronico")
      .eq("n_documento", n_documento)
      .eq("id_rol", 2)
      .single();

    if (clienteError) {
      return res.status(404).json({ error: "No se encontró el cliente" });
    }

    const { data: citasPendientes, error: citasError } = await supabase
      .from("citas")
      .select("id_mascota, mascota(nombre), servicios(servicio), fecha, descripcion")
      .eq("id_cliente", n_documento)
      .gte("fecha", new Date().toISOString());

    if (citasError) throw citasError;

    const { data: mascotas, error: mascotasError } = await supabase
      .from("mascota")
      .select("id, nombre, especie(especie), raza(raza), fecha_nacimiento, estado")
      .eq("id_cliente", n_documento);

    if (mascotasError) throw mascotasError;

    res.json({
      usuario: cliente,
      citas_pendientes: citasPendientes,
      mascotas,
    });
  } catch (error) {
    console.error("Error en /cliente/dashboard:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

/**
 * Dashboard Veterinario
 */
app.get("/veterinario/dashboard/:n_documento", async (req, res) => {
  try {
    const { n_documento } = req.params;

    const { data: veterinario, error: vetError } = await supabase
      .from("usuarios")
      .select("nombre, correoelectronico")
      .eq("n_documento", n_documento)
      .eq("id_rol", 3)
      .single();

    if (vetError) {
      return res.status(404).json({ error: "No se encontró el veterinario" });
    }

    const { data: mascotas, error: mascotasError } = await supabase
      .from("mascota")
      .select("id, nombre, especie(especie), raza(raza), fecha_nacimiento, estado");

    if (mascotasError) throw mascotasError;

    const { data: citasPendientes, error: citasError } = await supabase
      .from("citas")
      .select("id_mascota, mascota(nombre), servicios(servicio), fecha, descripcion")
      .order("fecha", { ascending: true });

    if (citasError) throw citasError;

    res.json({
      usuario: { ...veterinario, mascotas: mascotas.length },
      stats: {
        mascotas_agregadas: mascotas.length,
        citas_pendientes: citasPendientes.length,
      },
      mascotas,
      citas_pendientes: citasPendientes,
    });
  } catch (error) {
    console.error("Error en /veterinario/dashboard:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

/*-------------------------------
* Rutas de Gestión de Mascotas
-------------------------------*/

// Mostrar todas las mascotas registradas
app.get("/mascotas", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("mascota")
      .select(`
        id,
        nombre,
        fecha_nacimiento,
        estado,
        id_cliente,
        especie(especie),
        raza(raza)
      `)
      .neq("estado", "Suspendido");

    if (error) throw error;

    if (data.length > 0) res.json(data);
    else res.json("No hay mascotas registradas");
  } catch (err) {
    console.error("Error al obtener mascotas:", err.message);
    res.status(500).json({ error: "Error al obtener mascotas" });
  }
});

// Mostrar una mascota en específico
app.get("/Mascotas/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("mascota")
      .select(
        `id, nombre, fecha_nacimiento, usuarios(nombre), especie(especie), raza(raza)`
      )
      .eq("id", id)
      .single();

    if (error) throw error;

    if (data) res.json(data);
    else res.status(404).json("No hay mascota registrada con ese ID");
  } catch (err) {
    console.error("Error al obtener mascota:", err.message);
    res.status(500).json({ error: "Error al obtener mascota" });
  }
});

// Registrar una mascota
app.post("/Mascotas/Registro", async (req, res) => {
  const { nombre, id_especie, id_raza, estado, fecha_nacimiento, id_cliente } =
    req.body;
  try {
    const { data, error } = await supabase.from("mascota").insert([
      { nombre, id_especie, id_raza, estado, fecha_nacimiento, id_cliente },
    ]);

    if (error) throw error;

    res.status(201).json({ mensaje: "Mascota ingresada correctamente", data });
  } catch (err) {
    console.error("Error al registrar mascota:", err.message);
    res.status(500).json({ error: "Error al registrar mascota" });
  }
});

// Actualizar mascota
app.put("/Mascotas/Actualizar/:id", async (req, res) => {
  const { id } = req.params;
  const { nombre, estado } = req.body;
  try {
    const { data, error } = await supabase
      .from("mascota")
      .update({ nombre, estado })
      .eq("id", id);

    if (error) throw error;

    if (data.length > 0) {
      res.json({ mensaje: "Mascota actualizada correctamente", data });
    } else {
      res.status(404).json({ mensaje: "No hay mascota registrada con ese ID" });
    }
  } catch (err) {
    console.error("Error al actualizar mascota:", err.message);
    res.status(500).json({ error: "Error al actualizar mascota" });
  }
});

// Eliminar mascota (suspender)
app.put("/Mascotas/Eliminar/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("mascota")
      .update({ estado: "Suspendido" })
      .eq("id", id);

    if (error) throw error;

    if (data.length > 0) {
      res.json({ mensaje: "Mascota eliminada correctamente", data });
    } else {
      res.status(404).json({ mensaje: "No hay mascota registrada con ese ID" });
    }
  } catch (err) {
    console.error("Error al eliminar mascota:", err.message);
    res.status(500).json({ error: "Error al eliminar mascota" });
  }
});

/*-------------------------------
* Citas y Recordatorios
-------------------------------*/

// Citas de una mascota
app.get("/Citas/mascota/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("citas")
      .select(
        `id, id_mascota, id_cliente, id_servicio, id_veterinario, fecha, descripcion, estado, servicios(servicio)`
      )
      .eq("id_mascota", id);

    if (error) throw error;

    if (data.length > 0) res.json(data);
    else res.status(404).json({ mensaje: "Cita no encontrada" });
  } catch (err) {
    console.error("Error al buscar la cita:", err.message);
    res.status(500).json({ error: "Error al buscar la cita" });
  }
});

// Recordatorios de una mascota
app.get("/recordatorio/mascota/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("recordatorios")
      .select("fecha, descripcion, estado")
      .eq("id_mascota", id);

    if (error) throw error;

    if (data.length > 0) res.json(data);
    else res
      .status(404)
      .json({ mensaje: "No hay recordatorios para esta mascota" });
  } catch (err) {
    console.error("Error al buscar recordatorio:", err.message);
    res.status(500).json({ error: "Error al buscar recordatorio" });
  }
});

/*-------------------------------
* Especies
-------------------------------*/

// Listar especies
app.get("/Especies/Listado", async (req, res) => {
  try {
    const { data, error } = await supabase.from("especie").select("*");
    if (error) throw error;

    if (data.length > 0) res.json(data);
    else res.json({ mensaje: "No hay especies registradas" });
  } catch (err) {
    console.error("Error al obtener especies:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Obtener especie por ID
app.get("/Especies/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("especie")
      .select("*")
      .eq("id", id)
      .single();

    if (error) throw error;

    if (data) res.json(data);
    else res.status(404).json({ mensaje: "Especie no encontrada" });
  } catch (err) {
    console.error("Error al obtener especie:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Crear especie con imagen
app.post("/Especies/Crear", upload.single("imagen"), async (req, res) => {
  try {
    let imagenUrl = null;

    if (req.file) {
      const fileName = `especies/${Date.now()}_${req.file.originalname}`;

      const { error: uploadError } = await supabase.storage
        .from("img-animalbeats")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: true,
        });

      if (uploadError) throw uploadError;

      const { data: publicUrl } = supabase.storage
        .from("img-animalbeats")
        .getPublicUrl(fileName);

      imagenUrl = publicUrl.publicUrl;
    }

    const { data, error } = await supabase
      .from("especie")
      .insert([{ especie: req.body.Especie, imagen: imagenUrl }])
      .select();

    if (error) throw error;

    res.json({ mensaje: "Especie creada", data });
  } catch (err) {
    console.error("Error creando especie:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Actualizar especie
app.put("/Especies/Actualizar/:id", upload.single("imagen"), async (req, res) => {
  const { id } = req.params;
  const { Especie } = req.body;

  try {
    let updateFields = { especie: Especie };

    if (req.file) {
      const fileName = `especies/${Date.now()}_${req.file.originalname}`;

      const { error: uploadError } = await supabase.storage
        .from("img-animalbeats")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: true,
        });

      if (uploadError) throw uploadError;

      const { data: publicUrl } = supabase.storage
        .from("img-animalbeats")
        .getPublicUrl(fileName);

      updateFields.imagen = publicUrl.publicUrl;
    }

    const { data, error } = await supabase
      .from("especie")
      .update(updateFields)
      .eq("id", id)
      .select();

    if (error) throw error;

    if (data.length > 0) res.json({ mensaje: "Especie actualizada", data });
    else res.status(404).json({ mensaje: "Especie no encontrada" });
  } catch (err) {
    console.error("Error actualizando especie:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Eliminar especie
app.delete("/Especies/Eliminar/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("especie")
      .delete()
      .eq("id", id)
      .select();

    if (error) throw error;

    if (data && data.length > 0) {
      res.json({ mensaje: "Especie eliminada", data });
    } else {
      res.status(404).json({ mensaje: "No hay especie con ese ID" });
    }
  } catch (err) {
    console.error("Error al eliminar especie:", err.message);
    res.status(500).json({ error: err.message });
  }
});


/*-------------------------------
* Razas
-------------------------------*/

// Listar razas de una especie
app.get("/Razas/Listado/:id_especie", async (req, res) => {
  const { id_especie } = req.params;
  try {
    const { data, error } = await supabase
      .from("raza")
      .select("*")
      .eq("id_especie", id_especie);

    if (error) throw error;

    if (data.length > 0) res.json(data);
    else res.json({ mensaje: "No hay razas registradas" });
  } catch (err) {
    console.error("Error al obtener razas:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Obtener una raza por ID
app.get("/Razas/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("raza")
      .select("*")
      .eq("id", id)
      .single();

    if (error) throw error;

    if (data) res.json(data);
    else res.status(404).json({ mensaje: "Raza no encontrada" });
  } catch (err) {
    console.error("Error al obtener raza:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Crear raza
app.post("/Razas/Crear/:id_especie", upload.single("imagen"), async (req, res) => {
  const { id_especie } = req.params;
  const { raza, descripcion } = req.body;

  try {
    let imagenUrl = null;

    if (req.file) {
      const fileName = `razas/${Date.now()}_${req.file.originalname}`;

      const { error: uploadError } = await supabase.storage
        .from("img-animalbeats")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: true,
        });

      if (uploadError) throw uploadError;

      const { data: publicUrl } = supabase.storage
        .from("img-animalbeats")
        .getPublicUrl(fileName);

      imagenUrl = publicUrl.publicUrl;
    }

    const { data, error } = await supabase
      .from("raza")
      .insert([{ raza, descripcion, imagen: imagenUrl, id_especie }])
      .select();

    if (error) throw error;

    res.status(201).json({ mensaje: "Raza creada", data });
  } catch (err) {
    console.error("Error registrando raza:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Actualizar raza
app.put("/Razas/Actualizar/:id", upload.single("imagen"), async (req, res) => {
  const { id } = req.params;
  const { raza, descripcion } = req.body;

  try {
    let updateFields = { raza, descripcion };

    if (req.file) {
      const fileName = `razas/${Date.now()}_${req.file.originalname}`;

      const { error: uploadError } = await supabase.storage
        .from("img-animalbeats")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: true,
        });

      if (uploadError) throw uploadError;

      const { data: publicUrl } = supabase.storage
        .from("img-animalbeats")
        .getPublicUrl(fileName);

      updateFields.imagen = publicUrl.publicUrl;
    }

    const { data, error } = await supabase
      .from("raza")
      .update(updateFields)
      .eq("id", id)
      .select();

    if (error) throw error;

    if (data.length > 0) res.json({ mensaje: "Raza actualizada", data });
    else res.status(404).json({ mensaje: "Raza no encontrada" });
  } catch (err) {
    console.error("Error al actualizar raza:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Eliminar raza
app.delete("/Razas/Eliminar/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase.from("raza").delete().eq("id", id).select();

    if (error) throw error;

    if (data.length > 0) res.json({ mensaje: "Raza eliminada", data });
    else res.status(404).json({ mensaje: "No hay raza registrada con ese ID" });
  } catch (err) {
    console.error("Error al eliminar raza:", err.message);
    res.status(500).json({ error: err.message });
  }
});


// =======================
// Rutas de Enfermedades con ID (Supabase)
// =======================

// =======================
// Rutas de Enfermedades (Supabase) - Corregidas
// =======================

// Obtener todas las enfermedades
app.get('/Enfermedades/Listado', async (req, res) => {
  try {
    const { data, error } = await supabase.from("enfermedad").select("*");
    if (error) throw error;

    if (data?.length > 0) {
      return res.json(data);
    }
    return res.json({ mensaje: 'No hay enfermedades registradas' });
  } catch (error) {
    console.error('Error al obtener enfermedades:', error);
    return res.status(500).json({ error: 'Error al obtener enfermedades' });
  }
});

// Registrar nueva enfermedad
app.post('/Enfermedades/Registrar', async (req, res) => {
  const { nombre, descripcion } = req.body;

  if (!nombre?.trim() || !descripcion?.trim()) {
    return res.status(400).json({ error: 'Nombre y descripción son requeridos' });
  }

  try {
    const { data, error } = await supabase
      .from("enfermedad")
      .insert([{ nombre, descripcion }])
      .select(); // Devuelve el ID generado

    if (error) throw error;

    return res.status(201).json({ mensaje: 'Enfermedad registrada correctamente', resultado: data });
  } catch (error) {
    console.error('Error al registrar la enfermedad:', error);
    return res.status(500).json({ error: 'Error al registrar la enfermedad' });
  }
});

// Actualizar enfermedad por ID
app.put('/Enfermedades/Actualizar/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, descripcion } = req.body;

  const idInt = parseInt(id);
  if (isNaN(idInt)) return res.status(400).json({ error: 'ID inválido' });

  if (!nombre?.trim() && !descripcion?.trim()) {
    return res.status(400).json({ error: 'Debe enviar nombre o descripción para actualizar' });
  }

  try {
    const { data, error } = await supabase
      .from("enfermedad")
      .update({ nombre, descripcion })
      .eq("id", idInt);

    if (error) throw error;

    if (data?.length > 0) {
      return res.json({ mensaje: 'Enfermedad actualizada correctamente', resultado: data });
    } else {
      return res.status(404).json({ mensaje: 'No se encontró la enfermedad' });
    }
  } catch (error) {
    console.error('Error al actualizar la enfermedad:', error);
    return res.status(500).json({ error: 'Error al actualizar la enfermedad' });
  }
});

// Eliminar enfermedad por ID
app.delete('/Enfermedades/Eliminar/:id', async (req, res) => {
  const { id } = req.params;
  const idInt = parseInt(id);
  if (isNaN(idInt)) return res.status(400).json({ error: 'ID inválido' });

  try {
    const { data, error } = await supabase
      .from("enfermedad")
      .delete()
      .eq("id", idInt);

    if (error) throw error;

    if (data?.length > 0) {
      return res.json({ mensaje: 'Enfermedad eliminada correctamente', resultado: data });
    } else {
      return res.status(404).json({ mensaje: 'No se encontró la enfermedad' });
    }
  } catch (error) {
    console.error('Error al eliminar la enfermedad:', error);
    return res.status(500).json({ error: 'Error al eliminar la enfermedad' });
  }
});




// =======================
// Rutas de Citas (con Supabase pero mismas rutas)
// =======================

// Obtener todas las citas
app.get('/Citas/Listado', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("citas")
      .select(`
        id,
        id_mascota,
        fecha,
        descripcion,
        estado,
        mascota ( id, nombre ),
        usuarios: id_cliente ( n_documento, nombre ),
        servicios ( id, servicio ),
        veterinarios ( id, nombre_completo )
      `)
      .order("fecha", { ascending: false });

    if (error) throw error;

    if (data.length > 0) {
      res.json(data);
    } else {
      res.json({ mensaje: 'No hay citas registradas' });
    }
  } catch (error) {
    console.error('Error al obtener citas:', error);
    res.status(500).json({ error: 'Error al obtener citas' });
  }
});

// Registrar nueva cita
app.post('/Citas/Registrar', async (req, res) => {
  const { id_mascota, id_cliente, id_servicio, id_veterinario, fecha, descripcion, estado } = req.body;
  try {
    const { data, error } = await supabase
      .from("citas")
      .insert([{ id_mascota, id_cliente, id_servicio, id_veterinario, fecha, descripcion, estado }]);

    if (error) throw error;

    res.status(201).json({ mensaje: 'Cita registrada correctamente', resultado: data });
  } catch (error) {
    console.error('Error al registrar la cita:', error);
    res.status(500).json({ error: 'Error al registrar la cita' });
  }
});

// Obtener una cita por ID
app.get('/Citas/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("citas")
      .select(`
        id,
        id_mascota,
        fecha,
        descripcion,
        estado,
        mascota ( id, nombre ),
        usuarios: id_cliente ( n_documento, nombre ),
        servicios ( id, servicio ),
        veterinarios ( id, nombre_completo )
      `)
      .eq("id", id)
      .single();

    if (error) throw error;

    if (data) {
      res.json(data);
    } else {
      res.status(404).json({ mensaje: 'Cita no encontrada' });
    }
  } catch (error) {
    console.error('Error al buscar la cita:', error);
    res.status(500).json({ error: 'Error al buscar la cita' });
  }
});


// Actualizar una cita por ID
app.put('/Citas/Actualizar/:id', async (req, res) => {
  const { id } = req.params;
  const { descripcion, estado } = req.body;

  try {
    const { data, error } = await supabase
      .from("citas")
      .update({ descripcion, estado })
      .eq("id", id);

    if (error) throw error;

    if (data.length > 0) {
      res.json({ mensaje: 'Cita actualizada correctamente', resultado: data });
    } else {
      res.status(404).json({ mensaje: 'Cita no encontrada para actualizar' });
    }
  } catch (error) {
    console.error('Error al actualizar cita:', error);
    res.status(500).json({ error: 'Error al actualizar la cita' });
  }
});

// Cancelar cita
app.put('/Citas/Cancelar/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("citas")
      .update({ estado: "Cancelado" })
      .eq("id", id);

    if (error) throw error;

    if (data.length > 0) {
      res.json({ mensaje: 'Cita cancelada correctamente', resultado: data });
    } else {
      res.status(404).json({ mensaje: 'Cita no encontrada para cancelar' });
    }
  } catch (error) {
    console.error('Error al cancelar la cita:', error);
    res.status(500).json({ error: 'Error al cancelar la cita' });
  }
});

// Confirmar cita
app.put('/Citas/Confirmar/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("citas")
      .update({ estado: "Confirmado" })
      .eq("id", id);

    if (error) throw error;

    if (data.length > 0) {
      res.json({ mensaje: 'Cita confirmada correctamente', resultado: data });
    } else {
      res.status(404).json({ mensaje: 'Cita no encontrada para confirmar' });
    }
  } catch (error) {
    console.error('Error al confirmar la cita:', error);
    res.status(500).json({ error: 'Error al confirmar la cita' });
  }
});

// Marcar cita como pendiente
app.put('/Citas/Pendiente/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("citas")
      .update({ estado: "Pendiente" })
      .eq("id", id);

    if (error) throw error;

    if (data.length > 0) {
      res.json({ mensaje: 'Cita actualizada a pendiente correctamente', resultado: data });
    } else {
      res.status(404).json({ mensaje: 'Cita no encontrada para actualizar a pendiente' });
    }
  } catch (error) {
    console.error('Error al actualizar la cita a pendiente:', error);
    res.status(500).json({ error: 'Error al actualizar la cita a pendiente' });
  }
});


/* ========================
*  Rutas de Servicios
* ======================== */
app.get('/servicios/Listado', async (req, res) => {
  try {
    const { data, error } = await supabase.from("servicios").select("*");

    if (error) throw error;

    if (data.length > 0) {
      res.json(data);
    } else {
      res.json({ mensaje: 'No hay servicios registrados' });
    }
  } catch (error) {
    console.error('Error al obtener servicios:', error);
    res.status(500).json({ error: 'Error al obtener servicios' });
  }
});

/* ========================
*  Rutas de Gestión de Recordatorios
* ======================== */

// Obtener todas las alarmas de recordatorios
app.get('/recordatorios', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("recordatorios")
      .select(`
        id,
        id_mascota,
        mascota ( nombre ),
        id_cliente,
        fecha,
        descripcion
      `);

    if (error) throw error;

    res.json(data);
  } catch (error) {
    console.error('Error al obtener recordatorios:', error);
    res.status(500).json({ error: 'Error al obtener los recordatorios' });
  }
});

// Conseguir mascotas para mostrar dependiendo el id del dueño
app.get('/Mascota/recordatorio/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const { data, error } = await supabase
      .from("mascota")
      .select("id, nombre")
      .eq("id_cliente", id);

    if (error) throw error;

    if (data.length > 0) {
      res.json(data[0]);
    } else {
      res.status(404).json('No hay mascota registrada para ese ID');
    }
  } catch (err) {
    console.error('Error al obtener mascota:', err);
    res.status(500).json({ error: 'Error al obtener mascota' });
  }
});

// Modificar recordatorio existente
app.put('/recordatorios/modificar/:id', async (req, res) => {
  const { id } = req.params;
  const { cliente, mascota, fecha, descripcion } = req.body;

  try {
    const { error } = await supabase
      .from("recordatorios")
      .update({
        id_cliente: cliente,
        id_mascota: mascota,
        fecha: fecha,
        descripcion: descripcion
      })
      .eq("id", id);

    if (error) throw error;

    res.json({ message: 'Recordatorio actualizado correctamente' });
  } catch (error) {
    console.error('Error al modificar el recordatorio:', error);
    res.status(500).json({ error: 'Error al modificar el recordatorio' });
  }
});

app.post('/recordatorios/guardar', async (req, res) => {
  const { cliente, mascota, fecha, descripcion } = req.body;

  console.log("📩 Datos recibidos en backend:", req.body);

  try {
    if (!fecha || typeof fecha !== 'string') {
      throw new Error('fecha inválida');
    }

    // Validar cliente
    const { data: usuario, error: errorUsuario } = await supabase
      .from("usuarios")
      .select("n_documento")
      .eq("n_documento", cliente);

    console.log("🔎 Validación cliente:", usuario, errorUsuario);

    if (errorUsuario) throw errorUsuario;
    if (!usuario || usuario.length === 0) {
      return res.status(400).json({ error: 'Cliente no existe' });
    }

    // Validar mascota
    const { data: mascotaBD, error: errorMascota } = await supabase
      .from("mascota")
      .select("id")
      .eq("id", mascota)
      .eq("id_cliente", cliente);

    console.log("🔎 Validación mascota:", mascotaBD, errorMascota);

    if (errorMascota) throw errorMascota;
    if (!mascotaBD || mascotaBD.length === 0) {
      return res.status(400).json({ error: 'Mascota no coincide con cliente' });
    }

    // Insertar recordatorio
    const { error } = await supabase
      .from("recordatorios")
      .insert([{ id_cliente: cliente, id_mascota: mascota, fecha: fecha, descripcion, estado: "Activo" }]);

    if (error) throw error;

    res.status(201).json({ message: 'Recordatorio guardado correctamente' });
  } catch (error) {
    console.error('❌ Error al guardar recordatorio:', error);
    res.status(500).json({ error: error.message || 'Error al guardar el recordatorio' });
  }
});


// Eliminar recordatorio
app.delete('/recordatorios/eliminar/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const { error } = await supabase.from("recordatorios").delete().eq("id", id);

    if (error) throw error;

    res.json({ message: 'Recordatorio eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar el recordatorio:', error);
    res.status(500).json({ error: 'Error al eliminar el recordatorio' });
  }
});

/* ========================
*  Rutas de la API
* ======================== */
// Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});


app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

