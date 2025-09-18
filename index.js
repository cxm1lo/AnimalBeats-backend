import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import cors from 'cors';
import upload from './config/multer.js';
import { createClient } from "@supabase/supabase-js";




console.log("Variables de entorno:");
console.log("DB_HOST:", process.env.DB_HOST);
console.log("DB_USER:", process.env.DB_USER);
console.log("DB_PASS:", process.env.DB_PASS ? "****" : null);
console.log("DB_NAME:", process.env.DB_NAME);
console.log("DB_PORT:", process.env.DB_PORT);
console.log("JWT_SECRET:", process.env.JWT_SECRET ? "****" : null);

const router = express.Router();
import jwt from 'jsonwebtoken';
import mysql from 'mysql2/promise';
import bodyParser from 'body-parser';
import bcrypt from 'bcrypt';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(bodyParser.json());
app.use('/uploads', express.static('uploads'));


// Creacion de doc swagger
import swaggerUI from 'swagger-ui-express';
import swaggerDocumentation from './swagger.json' with {type: 'json'};

app.use(express.json());
app.use('/documentacion-api-animalbeats', swaggerUI.serve, swaggerUI.setup(swaggerDocumentation));

// Conexion a storage de supabase
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// Conexión asincrónica a la base de datos AnimalBeats
let conexion;
(async () => {
  try {
    conexion = mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
      enableKeepAlive: true,
      keepAliveInitialDelay: 0,
    });

    app.locals.connection = conexion;
    console.log('Conexión a la base de datos exitosa');
  } catch (error) {
    console.error('Error al conectar a la base de datos:', error);
    process.exit(1);
  }
})();


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

    const sql = `
      INSERT INTO Usuarios (n_documento, correoelectronico, contrasena, id_documento, nombre, id_rol, estado)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    await conexion.execute(sql, [n_documento, correoelectronico, hash, id_documento, nombre, id_rol, 'Activo']);

    res.status(201).json({ mensaje: 'Usuario registrado exitosamente', rol: rolTexto });
  } catch (err) {
    console.error("Error en registro:", err);
    res.status(500).json({ mensaje: 'Error al registrar usuario' });
  }
});

// Obtener tipos de documento
app.get('/tiposDocumento', async (req, res) => {
  try {
    const [results] = await conexion.query('SELECT id, tipo FROM Documento');
    res.status(200).json(results);
  } catch (err) {
    console.error("Error en getTiposDocumento:", err);
    res.status(500).json({ mensaje: 'Error al obtener tipos de documento' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { correoelectronico, contrasena } = req.body;

  try {
    const [resultados] = await conexion.execute(
      'SELECT * FROM Usuarios WHERE correoelectronico = ?',
      [correoelectronico]
    );

    if (resultados.length === 0) {
      return res.status(404).json({ mensaje: 'Usuario no encontrado' });
    }

    const usuario = resultados[0];
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
  const sqlQuery = `
    SELECT u.n_documento, u.nombre, u.correoelectronico, 
           d.tipo AS tipo_documento, u.estado, u.id_rol
    FROM Usuarios u
    LEFT JOIN Documento d ON u.id_documento = d.id
    WHERE u.estado != 'Suspendido'
  `;
  try {
    const [resultado] = await conexion.query(sqlQuery);
    res.json({ Usuarios: resultado });
  } catch (err) {
    console.error('Error al obtener Usuarios:', err);
    res.status(500).json({ error: 'Error al obtener Usuarios' });
  }
});

// Obtener usuario por documento
app.get('/usuario/:n_documento', async (req, res) => {
  const { n_documento } = req.params;
  const sqlQuery = `
    SELECT u.n_documento, u.nombre, u.correoelectronico, d.tipo AS tipo_documento
    FROM Usuarios u
    LEFT JOIN Documento d ON u.id_documento = d.id
    WHERE u.n_documento = ?
  `;
  try {
    const [resultado] = await conexion.execute(sqlQuery, [n_documento]);
    res.json(resultado.length > 0 ? resultado[0] : 'Usuario no encontrado');
  } catch (err) {
    console.error('Error al obtener usuario:', err);
    res.status(500).json({ error: 'Error al obtener usuario' });
  }
});

// Crear usuario
app.post('/usuario/Crear', async (req, res) => {
  const { n_documento, nombre, correoelectronico, contrasena, id_documento, id_rol } = req.body;

  try {
    //Valida si rol es admin pero correo no es el predeterminado
    if (id_rol == 1 && correoelectronico.toLowerCase() !== 'administrador@animalbeats.com') {
      return res.status(400).json({ error: 'Solo se permite el correo predeterminado para rol Administrador' });
    }

    const hashedPassword = await bcrypt.hash(contrasena, 10);

    const sqlInsert = `
      INSERT INTO Usuarios (n_documento, nombre, correoelectronico, contrasena, id_documento, id_rol, estado)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    const estado = 'Activo';

    const [resultado] = await conexion.execute(sqlInsert, [
      n_documento, nombre, correoelectronico, hashedPassword, id_documento, id_rol, estado,
    ]);

    res.status(201).json({ mensaje: 'Usuario registrado correctamente', resultado });
  } catch (err) {
    console.error('Error al registrar usuario:', err);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// Actualizar usuario
app.put('/usuario/Actualizar/:n_documento', async (req, res) => {
  const { nombre, correoelectronico, id_documento, id_rol, n_documento_original } = req.body;


  const estado = 'activo';

  const sqlUpdate = `
    UPDATE Usuarios
    SET nombre = ?, correoelectronico = ?, id_documento = ?, id_rol = ?, estado = ?
    WHERE n_documento = ?
  `;

  try {
    const [resultado] = await conexion.execute(sqlUpdate, [
      nombre, correoelectronico, id_documento, id_rol, estado, n_documento_original,
    ]);


    if (resultado.affectedRows > 0) {
      res.json({ mensaje: 'Usuario actualizado correctamente' });
    } else {
      res.status(404).json({ mensaje: 'Usuario no encontrado' });
    }
  } catch (err) {
    console.error('Error al actualizar usuario:', err);
    res.status(500).json({ error: 'Error al actualizar usuario' });
  }
});


// Suspender usuario
app.put('/usuario/Suspender/:n_documento', async (req, res) => {
  const { n_documento } = req.params;

  const sqlUpdate = `UPDATE Usuarios SET estado = 'Suspendido' WHERE n_documento = ?`;

  try {
    const [resultado] = await conexion.execute(sqlUpdate, [n_documento]);

    if (resultado.affectedRows > 0) {
      res.json({ mensaje: 'Usuario suspendido correctamente' });
    } else {
      res.json('Usuario no encontrado');
    }
  } catch (err) {
    console.error('Error al suspender usuario:', err);
    res.status(500).json({ error: 'Error al suspender usuario' });
  }
});


//Reactivar Usuario

app.put('/usuario/Reactivar/:n_documento', async (req, res) => {
  const { n_documento } = req.params;

  const sqlUpdate = `UPDATE Usuarios SET estado = 'Activo' WHERE n_documento = ?`;

  try {
    const [resultado] = await conexion.execute(sqlUpdate, [n_documento]);

    if (resultado.affectedRows > 0) {
      res.json({ mensaje: 'Usuario reactivado correctamente' });
    } else {
      res.json('Usuario no encontrado');
    }
  } catch (err) {
    console.error('Error al reactivar usuario:', err);
    res.status(500).json({ error: 'Error al reactivar usuario' });
  }
});

//Usuario Pendiente
app.put('/usuario/Pendiente/:n_documento', async (req, res) => {
  const { n_documento } = req.params;

  const sqlUpdate = `UPDATE Usuarios SET estado = 'Pendiente' WHERE n_documento = ?`;

  try {
    const [resultado] = await conexion.execute(sqlUpdate, [n_documento]);

    if (resultado.affectedRows > 0) {
      res.json({ mensaje: 'Usuario puesto en estado pendiente correctamente' });
    } else {
      res.status(404).json({ mensaje: 'Usuario no encontrado' });
    }
  } catch (err) {
    console.error('Error al poner usuario en pendiente:', err);
    res.status(500).json({ error: 'Error al poner usuario en pendiente' });
  }
});


//Ruta Tabla de Roles
app.get('/roles/Listado', async (req, res) => {
  const sqlQuery = `
    SELECT id, rol
    FROM Rol
  `;
  try {
    const [resultado] = await conexion.query(sqlQuery);
    res.json({ roles: resultado });
  } catch (err) {
    console.error('Error al obtener roles:', err);
    res.status(500).json({ error: 'Error al obtener roles' });
  }
});

//Ruta Crear Roles
app.post('/roles/Crear', async (req, res) => {
  const { rol } = req.body;
  if (!rol || rol.trim() === '') {
    return res.status(400).json({ error: 'El rol es obligatorio' });
  }
  try {
    const sqlInsert = 'INSERT INTO Rol (rol) VALUES (?)';
    const [resultado] = await conexion.query(sqlInsert, [rol.trim()]);
    res.json({ message: 'Rol creado correctamente', id: resultado.insertId });
  } catch (err) {
    console.error('Error al crear rol:', err);
    res.status(500).json({ error: 'Error al crear rol' });
  }
});

//Ruta Eliminar Roles

app.delete('/roles/Eliminar/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const sqlDelete = 'DELETE FROM Rol WHERE id = ?';
    const [resultado] = await conexion.query(sqlDelete, [id]);

    if (resultado.affectedRows > 0) {
      res.json({ message: 'Rol eliminado correctamente' });
    } else {
      res.status(404).json({ error: 'Rol no encontrado' });
    }
  } catch (err) {
    console.error('Error al eliminar rol:', err);
    res.status(500).json({ error: 'Error al eliminar rol' });
  }
});

// ==========================
// Perfil Veterinario (Rutas corregidas y robustas)
// ==========================


// Sirve carpeta local (si usas almacenamiento local con multer.diskStorage)
app.use('/uploads/veterinarios', express.static(path.join(__dirname, 'uploads/veterinarios')));

/**
 * Crear /veterinarios
 * - Acepta multipart/form-data con campo 'imagen' y campos textuales.
 * - Maneja tanto storage local (req.file.filename) como cloud (req.file.path con URL).
 */
app.post('/veterinarios', upload.single('imagen'), async (req, res) => {
  try {
    const {
      nombre_completo,
      estudios_especialidad,
      edad: edadRaw,
      altura: alturaRaw,
      anios_experiencia: aniosRaw
    } = req.body;

    // Validación básica
    if (!nombre_completo || !estudios_especialidad || !edadRaw || !alturaRaw || !aniosRaw) {
      return res.status(400).json({ mensaje: 'Faltan campos obligatorios' });
    }

    // Convertir tipos
    const edad = parseInt(edadRaw, 10);
    const altura = parseFloat(alturaRaw);
    const anios_experiencia = parseInt(aniosRaw, 10);

    if (Number.isNaN(edad) || Number.isNaN(altura) || Number.isNaN(anios_experiencia)) {
      return res.status(400).json({ mensaje: 'Edad, altura o años de experiencia tienen formato inválido' });
    }

    // Determinar imagen_url según storage
    // Si req.file.path existe y parece una URL (cloudinary u otro), la usamos.
    // Sino, si se usó storage local y existe filename, construimos URL con SERVER_URL.
    let imagen_url = null;
    if (req.file) {
      if (req.file.path && String(req.file.path).startsWith('http')) {
        imagen_url = req.file.path;
      } else if (req.file.filename) {
        const serverUrl = process.env.SERVER_URL || `http://localhost:${process.env.PORT || 3000}`;
        imagen_url = `${serverUrl}/uploads/veterinarios/${req.file.filename}`;
      } else if (req.file.path) {
        const serverUrl = process.env.SERVER_URL || `http://localhost:${process.env.PORT || 3000}`;
        imagen_url = `${serverUrl}/${req.file.path.replace(/^\/+/, '')}`;
      }
    }

    const sql = `INSERT INTO Veterinarios 
      (nombre_completo, estudios_especialidad, edad, altura, anios_experiencia, imagen_url)
      VALUES (?, ?, ?, ?, ?, ?)`;

    const [resultado] = await conexion.execute(sql, [
      nombre_completo,
      estudios_especialidad,
      edad,
      altura,
      anios_experiencia,
      imagen_url,
    ]);

    return res.status(201).json({
      mensaje: 'Veterinario creado correctamente',
      id: resultado.insertId,
      imagen_url
    });
  } catch (err) {
    console.error('Error al crear veterinario:', err?.message ?? err, err);
    // En producción quizá quieras esconder stack; aquí devolvemos info útil para depuración
    return res.status(500).json({ error: 'Error al crear veterinario', details: err?.message || String(err) });
  }
});

/**
 * Listar veterinarios activos
 */
app.get('/veterinarios', async (req, res) => {
  try {
    const [rows] = await conexion.execute(
      'SELECT * FROM Veterinarios WHERE activo = 1 ORDER BY creado_en DESC'
    );
    res.json(rows);
  } catch (error) {
    console.error('Error al consultar veterinarios:', error?.message ?? error, error);
    res.status(500).json({ mensaje: 'Error al consultar veterinarios', details: error?.message || String(error) });
  }
});


/**
 * Consultar /veterinarios/:id
 */
app.get('/veterinarios/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await conexion.execute('SELECT * FROM Veterinarios WHERE id_veterinario = ?', [id]);

    if (rows.length === 0) {
      return res.status(404).json({ mensaje: 'Veterinario no encontrado' });
    }

    res.json(rows[0]);
  } catch (error) {
    console.error('Error al consultar veterinario:', error?.message ?? error, error);
    res.status(500).json({ mensaje: 'Error al consultar veterinario', details: error?.message || String(error) });
  }
});

/**
 * Eliminar
 */
app.delete('/veterinarios/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const [resultado] = await conexion.execute(
      'UPDATE Veterinarios SET activo = 0 WHERE id_veterinario = ?',
      [id]
    );

    if (resultado.affectedRows === 0) {
      return res.status(404).json({ mensaje: 'Veterinario no encontrado' });
    }

    res.json({ mensaje: 'Veterinario marcado como eliminado' });
  } catch (error) {
    console.error('Error al eliminar veterinario:', error?.message ?? error, error);
    res.status(500).json({ mensaje: 'Error al eliminar veterinario', details: error?.message || String(error) });
  }
});



// Dashboard de admin
app.get('/admin/dashboard', async (req, res) => {
  try {
    // Obtener el primer administrador registrado 
    const [adminRows] = await conexion.execute(
      "SELECT nombre, correoelectronico FROM Usuarios WHERE id_rol = ?", [1]
    );

    if (adminRows.length === 0) {
      return res.status(404).json({ error: "No se encontró ningún admin" });
    }

    // Contar total de Usuarios que sean clientes o veterinarios 
    const [countRows] = await conexion.execute(
      "SELECT COUNT(*) AS total FROM Usuarios WHERE id_rol IN (2, 3)"
    );

    const totalClientes = countRows[0].total;

    // Enviar respuesta con datos del admin y el conteo de clientes
    res.json({
      usuario: {
        nombre: adminRows[0].nombre,
        correo: adminRows[0].correoelectronico,
      },
      total_clientes: totalClientes,
    });
  } catch (error) {
    console.error("Error en /admin/dashboard:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

//Dashboard del cliente
app.get('/cliente/dashboard/:n_documento', async (req, res) => {
  try {
    const { n_documento } = req.params;

    //Obtener datos del cliente
    const [clienteRows] = await conexion.execute(
      "SELECT nombre, correoelectronico FROM Usuarios WHERE n_documento = ? AND id_rol = 2",
      [n_documento]
    );

    if (clienteRows.length === 0) {
      return res.status(404).json({ error: "No se encontró el cliente" });
    }

    //Obtener citas pendientes (fecha despues de hoy)
    const [citasPendientes] = await conexion.execute(
      `SELECT c.id_Mascota, m.nombre AS nombre_mascota, s.servicio, c.fecha, c.Descripcion
       FROM Citas c
       INNER JOIN Mascota m ON c.id_Mascota = m.id
       INNER JOIN Servicios s ON c.id_Servicio = s.id
       WHERE c.id_cliente = ? AND c.fecha >= CURDATE()
       ORDER BY c.fecha ASC`,
      [n_documento]
    );

    // Obtener mascotas registradas
    const [mascotas] = await conexion.execute(
      `SELECT m.id, m.nombre, e.Especie, r.Raza, m.fecha_nacimiento, m.estado
       FROM Mascota m
       INNER JOIN Especie e ON m.id_Especie = e.id
       INNER JOIN Raza r ON m.id_Raza = r.id
       WHERE m.id_cliente = ?`,
      [n_documento]
    );

    // Respuesta
    res.json({
      usuario: {
        nombre: clienteRows[0].nombre,
        correo: clienteRows[0].correoelectronico,
      },
      citas_pendientes: citasPendientes,
      mascotas: mascotas,
    });

  } catch (error) {
    console.error("Error en /cliente/dashboard:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

//Dashboard del veterinario
app.get('/veterinario/dashboard/:n_documento', async (req, res) => {
  try {
    const { n_documento } = req.params;
    console.log("Dashboard veterinario solicitado para:", n_documento);

    // Datos del veterinario
    const [veterinarioRows] = await conexion.execute(
      "SELECT nombre, correoelectronico FROM Usuarios WHERE n_documento = ? AND id_rol = 3",
      [n_documento]
    );

    if (veterinarioRows.length === 0) {
      console.log("No se encontró veterinario con ese documento");
      return res.status(404).json({ error: "No se encontró el veterinario" });
    }

    // Obtener todas las mascotas
    const [mascotas] = await conexion.execute(
      `SELECT m.id, m.nombre, e.Especie, r.Raza, m.fecha_nacimiento, m.estado
       FROM Mascota m
       INNER JOIN Especie e ON m.id_Especie = e.id
       INNER JOIN Raza r ON m.id_Raza = r.id`
    );

    // Obtener todas las citas
    const [citasPendientes] = await conexion.execute(
      `SELECT c.id_Mascota, m.nombre AS nombre_mascota, s.servicio, c.fecha, c.Descripcion
       FROM Citas c
       INNER JOIN Mascota m ON c.id_Mascota = m.id
       INNER JOIN Servicios s ON c.id_Servicio = s.id
       ORDER BY c.fecha ASC`
    );

    // Estadísticas generales
    const stats = {
      mascotas_agregadas: mascotas.length,
      citas_pendientes: citasPendientes.length
    };

    // Respuesta
    res.json({
      usuario: {
        nombre: veterinarioRows[0].nombre,
        correo: veterinarioRows[0].correoelectronico,
        mascotas: mascotas.length
      },
      stats,
      mascotas,
      citas_pendientes: citasPendientes
    });

  } catch (error) {
    console.error("Error en /veterinario/dashboard:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});



/*-------------------------------
* Rutas de Gestion de mascotas
-------------------------------*/


// Mostrar todas las mascotas registradas
app.get('/mascotas', async (req, res) => {
  try {
    const [mascotas] = await conexion.query(`
      SELECT M.id_cliente, M.id, M.nombre, E.Especie AS especie, R.Raza AS raza, M.fecha_nacimiento
      FROM Mascota M
      JOIN Especie E ON M.id_especie = E.id
      JOIN Raza R ON M.id_raza = R.id
      WHERE M.estado != 'Suspendido'
    `);
    if (mascotas.length > 0) {
      res.json(mascotas);
    } else {
      res.json('No hay mascotas registradas');
    }
  } catch (err) {
    console.error('Error al obtener mascotas:', err);
    res.status(500).json({ error: 'Error al obtener mascotas' });
  }
});


// Mostrar una mascota en específico
app.get('/Mascotas/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [resultado] = await conexion.execute("SELECT M.id, M.nombre, M.fecha_nacimiento, U.nombre as cliente, E.especie, R.raza FROM Mascota M join Usuarios U on M.id_cliente = U.n_documento JOIN Especie E ON M.id_especie = E.id JOIN Raza R ON M.id_raza = R.id WHERE M.id = ?", [id]);
    if (resultado.length > 0) {
      res.json(resultado[0]);
    } else {
      res.status(404).json('No hay mascota registrada con ese ID');
    }
  } catch (err) {
    console.error('Error al obtener mascota:', err);
    res.status(500).json({ error: 'Error al obtener mascota' });
  }
});

// Registrar una mascota
app.post('/Mascotas/Registro', async (req, res) => {
  const { nombre, id_especie, id_raza, estado, fecha_nacimiento, id_cliente } = req.body;
  try {
    const sql = "INSERT INTO Mascota (nombre, id_especie, id_raza, estado, fecha_nacimiento, id_cliente) VALUES (?, ?, ?, ?, ?, ?)";
    const [resultado] = await conexion.execute(sql, [nombre, id_especie, id_raza, estado, fecha_nacimiento, id_cliente]);
    res.status(201).json({ mensaje: "Mascota ingresada correctamente", resultado });
  } catch (err) {
    console.error('Error al registrar mascota:', err);
    res.status(500).json({ error: 'Error al registrar mascota' });
  }
});

// Actualizar mascota
app.put('/Mascotas/Actualizar/:id', async (req, res) => {
  const { id } = req.params;
  const { nombre, estado } = req.body;
  try {
    const sql = "UPDATE Mascota SET nombre = ?, estado = ? WHERE id = ?";
    const [resultado] = await conexion.execute(sql, [nombre, estado, id]);
    if (resultado.affectedRows > 0) {
      res.json({ mensaje: "Mascota actualizada correctamente", resultado });
    } else {
      res.status(404).json({ mensaje: "No hay mascota registrada con ese ID" });
    }
  } catch (err) {
    console.error('Error al actualizar mascota:', err);
    res.status(500).json({ error: 'Error al actualizar mascota' });
  }
});

// Eliminar mascota
app.put('/Mascotas/Eliminar/:id', async (req, res) => {
  const { id } = req.params;
  console.log('Solicitud para suspender mascota con id:', id);
  try {
    const [resultado] = await conexion.execute(
      "UPDATE Mascota SET estado = 'Suspendido' WHERE id = ?",
      [id]
    );
    console.log('Resultado de la actualización:', resultado);
    if (resultado.affectedRows > 0) {
      res.json({ mensaje: "Mascota eliminada correctamente", resultado });
    } else {
      res.status(404).json({ mensaje: "No hay mascota registrada con ese ID" });
    }
  } catch (err) {
    console.error('Error al eliminar mascota:', err);
    res.status(500).json({ error: 'Error al eliminar mascota' });
  }
});


// Necesario para el historial
app.get('/Citas/mascota/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const [resultado] = await conexion.execute(
      'SELECT C.*, S.servicio FROM Citas C join Servicios S on S.id = C.id_servicio WHERE C.id_mascota = ?', [id]
    );
    if (resultado.length > 0) {
      res.json(resultado);
    } else {
      res.status(404).json({ mensaje: 'Cita no encontrada' });
    }
  } catch (error) {
    console.error('Error al buscar la cita:', error);
    res.status(500).json({ error: 'Error al buscar la cita' });
  }
});

app.get('/recordatorio/mascota/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const [resultado] = await conexion.execute('select fecha, descripcion, estado from Recordatorios where id_mascota = ?', [id]);
    if (resultado.length > 0) {
      res.json(resultado);
    } else {
      res.status(404).json({ mensaje: 'No hay recordatorios para esta mascota' })
    }
  } catch (error) {
    console.error('Error al buscar recordatorio:', error);
    res.status(500).json({ error: 'Error al buscar recordatorio' });
  }
});


// Listar todas las especies
app.get('/Especies/Listado', async (req, res) => {
  try {
    const [especies] = await conexion.query("SELECT * FROM Especie");
    if (especies.length > 0) res.json(especies);
    else res.json({ mensaje: 'No hay especies registradas' });
  } catch (err) {
    console.error('Error al obtener especies:', err);
    res.status(500).json({ error: err.message });
  }
});

// Obtener una especie por ID
app.get('/Especies/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await conexion.query("SELECT * FROM Especie WHERE id = ?", [id]);
    if (rows.length > 0) res.json(rows[0]);
    else res.status(404).json({ mensaje: 'Especie no encontrada' });
  } catch (err) {
    console.error('Error al obtener especie:', err);
    res.status(500).json({ error: err.message });
  }
});

// Crear especie
app.post("/Especies/Crear", upload.single("imagen"), async (req, res) => {
  try {
    let imagenUrl = null;

    if (req.file) {
      const fileName = `especies/${Date.now()}_${req.file.originalname}`;

      const { error } = await supabase.storage
        .from("img-animalbeats")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: true,
        });

      if (error) throw error;

      const { data: publicUrl } = supabase.storage
        .from("img-animalbeats")
        .getPublicUrl(fileName);

      imagenUrl = publicUrl.publicUrl;
    }

    const [resultado] = await conexion.execute(
      "INSERT INTO Especie (especie, imagen) VALUES (?, ?)",
      [req.body.Especie, imagenUrl]
    );

    res.json({
      mensaje: "Especie creada",
      id: resultado.insertId,
      imagen: imagenUrl,
    });
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
    let imagenUrl = null;

    if (req.file) {
      const fileName = `especies/${Date.now()}_${req.file.originalname}`;

      const { error } = await supabase.storage
        .from("img-animalbeats")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: true,
        });

      if (error) throw error;

      const { data: publicUrl } = supabase.storage
        .from("img-animalbeats")
        .getPublicUrl(fileName);

      imagenUrl = publicUrl.publicUrl;
    }

    let sql, params;
    if (imagenUrl) {
      sql = "UPDATE Especie SET especie = ?, imagen = ? WHERE id = ?";
      params = [Especie, imagenUrl, id];
    } else {
      sql = "UPDATE Especie SET especie = ? WHERE id = ?";
      params = [Especie, id];
    }

    const [resultado] = await conexion.execute(sql, params);

    if (resultado.affectedRows > 0) {
      res.json({ mensaje: "Especie actualizada correctamente" });
    } else {
      res.status(404).json({ mensaje: "Especie no encontrada" });
    }
  } catch (err) {
    console.error("Error actualizando especie:", err.message);
    res.status(500).json({ error: err.message });
  }
});



// Eliminar especie
app.delete('/Especies/Eliminar/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [resultado] = await conexion.execute("DELETE FROM Especie WHERE id = ?", [id]);
    if (resultado.affectedRows > 0) {
      res.json({ mensaje: "Especie eliminada correctamente" });
    } else {
      res.status(404).json({ mensaje: "No hay especie registrada con ese ID" });
    }
  } catch (err) {
    console.error('Error al eliminar especie:', err);
    res.status(500).json({ error: err.message });
  }
});


// ----------------- RAZAS -----------------


// Listar razas de una especie
app.get('/Razas/Listado/:id_especie', async (req, res) => {
  const { id_especie } = req.params;
  try {
    const [resultado] = await conexion.execute(
      "SELECT * FROM Raza WHERE id_especie = ?", [id_especie]
    );
    if (resultado.length > 0) res.json(resultado);
    else res.json({ mensaje: 'No hay razas registradas' });
  } catch (err) {
    console.error('Error al obtener razas:', err);
    res.status(500).json({ error: err.message });
  }
});

// Obtener una raza por ID
app.get('/Razas/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await conexion.query("SELECT * FROM Raza WHERE id = ?", [id]);
    if (rows.length > 0) res.json(rows[0]);
    else res.status(404).json({ mensaje: 'Raza no encontrada' });
  } catch (err) {
    console.error('Error al obtener raza:', err);
    res.status(500).json({ error: err.message });
  }
});

// Crear raza
// Crear raza
app.post('/Razas/Crear/:id_especie', upload.single('imagen'), async (req, res) => {
  const { id_especie } = req.params;
  const { raza, descripcion } = req.body;

  try {
    let imagenUrl = null;

    if (req.file) {
      const fileName = `razas/${Date.now()}_${req.file.originalname}`;

      const { error } = await supabase.storage
        .from("img-animalbeats")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: true,
        });

      if (error) throw error;

      const { data: publicUrl } = supabase.storage
        .from("img-animalbeats")
        .getPublicUrl(fileName);

      imagenUrl = publicUrl.publicUrl;
    }

    const sql =
      "INSERT INTO Raza (raza, descripcion, imagen, id_especie) VALUES (?, ?, ?, ?)";
    const [resultado] = await conexion.execute(sql, [
      raza,
      descripcion,
      imagenUrl,
      id_especie,
    ]);

    res.status(201).json({
      mensaje: "Raza ingresada correctamente",
      id: resultado.insertId,
      raza,
      descripcion,
      imagen: imagenUrl,
      id_especie,
    });
  } catch (err) {
    console.error("Error registrando raza:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// Actualizar raza
app.put('/Razas/Actualizar/:id', upload.single('imagen'), async (req, res) => {
  const { id } = req.params;
  const { raza, descripcion } = req.body;

  try {
    let imagenUrl = null;

    if (req.file) {
      const fileName = `razas/${Date.now()}_${req.file.originalname}`;

      const { error } = await supabase.storage
        .from("img-animalbeats")
        .upload(fileName, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: true,
        });

      if (error) throw error;

      const { data: publicUrl } = supabase.storage
        .from("img-animalbeats")
        .getPublicUrl(fileName);

      imagenUrl = publicUrl.publicUrl;
    }

    let sql, params;
    if (imagenUrl) {
      sql = "UPDATE Raza SET raza = ?, descripcion = ?, imagen = ? WHERE id = ?";
      params = [raza, descripcion, imagenUrl, id];
    } else {
      sql = "UPDATE Raza SET raza = ?, descripcion = ? WHERE id = ?";
      params = [raza, descripcion, id];
    }

    const [resultado] = await conexion.execute(sql, params);

    if (resultado.affectedRows > 0) {
      res.json({
        mensaje: "Raza actualizada correctamente",
        id,
        raza,
        descripcion,
        imagen: imagenUrl,
      });
    } else {
      res.status(404).json({ mensaje: "No hay raza registrada con ese ID" });
    }
  } catch (err) {
    console.error("Error al actualizar raza:", err.message);
    res.status(500).json({ error: err.message });
  }
});


// Eliminar raza
app.delete('/Razas/Eliminar/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [resultado] = await conexion.execute("DELETE FROM Raza WHERE id = ?", [id]);
    if (resultado.affectedRows > 0) {
      res.json({ mensaje: "Raza eliminada correctamente" });
    } else {
      res.status(404).json({ mensaje: "No hay raza registrada con ese ID" });
    }
  } catch (err) {
    console.error('Error al eliminar raza:', err);
    res.status(500).json({ error: err.message });
  }
});



// =======================
// Rutas de Enfermedades
// =======================

// Obtener todas las enfermedades
app.get('/Enfermedades/Listado', async (req, res) => {
  try {
    const [resultado] = await conexion.execute("SELECT * FROM Enfermedad");
    if (resultado.length > 0) {
      return res.json(resultado);
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
  try {
    const [resultado] = await conexion.execute(
      "INSERT INTO Enfermedad (nombre, descripcion) VALUES (?, ?)",
      [nombre, descripcion]
    );
    res.status(201).json({ mensaje: 'Enfermedad registrada correctamente', resultado });
  } catch (error) {
    console.error('Error al registrar la enfermedad:', error);
    res.status(500).json({ error: 'Error al registrar la enfermedad' });
  }
});

// Actualizar enfermedad
app.put('/Enfermedades/Actualizar/:nombre', async (req, res) => {
  const nombre = req.params.nombre;
  const { descripcion } = req.body;
  try {
    const [resultado] = await conexion.execute(
      "UPDATE Enfermedad SET descripcion = ? WHERE nombre = ?",
      [descripcion, nombre]
    );
    if (resultado.affectedRows > 0) {
      return res.json({ mensaje: 'Enfermedad actualizada correctamente', resultado });
    } else {
      return res.status(404).json({ mensaje: 'No se encontró la enfermedad' });
    }
  } catch (error) {
    console.error('Error al actualizar la enfermedad:', error);
    return res.status(500).json({ error: 'Error al actualizar la enfermedad' });
  }
});

// Eliminar enfermedad
app.delete('/Enfermedades/Eliminar/:nombre', async (req, res) => {
  const nombre = req.params.nombre;
  try {
    const [resultado] = await conexion.execute(
      "DELETE FROM Enfermedad WHERE nombre = ?",
      [nombre]
    );
    if (resultado.affectedRows > 0) {
      return res.json({ mensaje: 'Enfermedad eliminada correctamente', resultado });
    } else {
      return res.status(404).json({ mensaje: 'No se encontró la enfermedad' });
    }
  } catch (error) {
    console.error('Error al eliminar la enfermedad:', error);
    return res.status(500).json({ error: 'Error al eliminar la enfermedad' });
  }
});

// =======================
// Rutas de Citas
// =======================

// Obtener todas las citas
// Obtener todas las citas con info del cliente, mascota y veterinario
app.get('/Citas/Listado', async (req, res) => {
  try {
    const [resultado] = await conexion.execute(`
      SELECT 
        C.id,
        C.id_Mascota,
        M.nombre AS nombre_mascota,
        C.id_cliente,
        UC.nombre AS nombre_cliente,
        C.id_Servicio,
        S.nombre AS nombre_servicio,
        C.id_veterinario,
        UV.nombre AS nombre_veterinario,
        C.fecha,
        C.Descripcion
        C.estado
      FROM Citas C
      INNER JOIN Mascota M ON C.id_Mascota = M.id
      INNER JOIN Usuarios UC ON C.id_cliente = UC.n_documento
      INNER JOIN Servicios S ON C.id_Servicio = S.id
      INNER JOIN Usuarios UV ON C.id_veterinario = UV.n_documento
      ORDER BY C.fecha DESC
    `);

    if (resultado.length > 0) {
      res.json(resultado);
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
  const { id_Mascota, id_cliente, id_Servicio, id_veterinario, fecha, Descripcion } = req.body;
  try {
    const [resultado] = await conexion.execute(
      `INSERT INTO Citas (id_Mascota, id_cliente, id_Servicio, id_veterinario, fecha, Descripcion, estado)
       VALUES (?, ?, ?, ?, ?, ?, "Pendiente")`,
      [id_Mascota, id_cliente, id_Servicio, id_veterinario, fecha, Descripcion]
    );
    res.status(201).json({ mensaje: 'Cita registrada correctamente', resultado });
  } catch (error) {
    console.error('Error al registrar la cita:', error);
    res.status(500).json({ error: 'Error al registrar la cita' });
  }
});

// Obtener una cita por ID
// Obtener una cita por ID con info detallada
app.get('/Citas/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const [resultado] = await conexion.execute(`
      SELECT 
        C.id,
        C.id_Mascota,
        M.nombre AS nombre_mascota,
        C.id_cliente,
        UC.nombre AS nombre_cliente,
        C.id_Servicio,
        S.nombre AS nombre_servicio,
        C.id_veterinario,
        UV.nombre AS nombre_veterinario,
        C.fecha,
        C.Descripcion
        C.estado
      FROM Citas C
      INNER JOIN Mascota M ON C.id_Mascota = M.id
      INNER JOIN Usuarios UC ON C.id_cliente = UC.n_documento
      INNER JOIN Servicios S ON C.id_Servicio = S.id
      INNER JOIN Usuarios UV ON C.id_veterinario = UV.n_documento
      WHERE C.id = ?
    `, [id]);

    if (resultado.length > 0) {
      res.json(resultado[0]);
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
  const id = req.params.id;
  const { id_Mascota, id_cliente, id_Servicio, id_veterinario, fecha, Descripcion, estado } = req.body;
  try {
    const [resultado] = await conexion.execute(
      `UPDATE Citas 
       SET id_Mascota = ?, id_cliente = ?, id_Servicio = ?, id_veterinario = ?, fecha = ?, Descripcion = ?, estado = ?
       WHERE id = ?`,
      [id_Mascota, id_cliente, id_Servicio, id_veterinario, fecha, Descripcion, estado, id]
    );
    if (resultado.affectedRows > 0) {
      res.json({ mensaje: 'Cita actualizada correctamente', resultado });
    } else {
      res.status(404).json({ mensaje: 'Cita no encontrada para actualizar' });
    }
  } catch (error) {
    console.error('Error al actualizar cita:', error);
    res.status(500).json({ error: 'Error al actualizar la cita' });
  }
});

// Eliminar una cita por ID
app.delete('/Citas/Eliminar/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const [resultado] = await conexion.execute(
      'DELETE FROM Citas WHERE id = ?', [id]
    );
    if (resultado.affectedRows > 0) {
      res.json({ mensaje: 'Cita eliminada correctamente', resultado });
    } else {
      res.status(404).json({ mensaje: 'Cita no encontrada para eliminar' });
    }
  } catch (error) {
    console.error('Error al eliminar cita:', error);
    res.status(500).json({ error: 'Error al eliminar la cita' });
  }
});

/* ========================
*  Rutas de Servicios
* ======================== */
app.get('/servicios/Listado', async (req, res) => {
  try {
    const [resultado] = await conexion.execute('SELECT * FROM servicios');
    if (resultado.length > 0) {
      res.json(resultado);
    } else {
      res.json({ mensaje: 'No hay citas registradas' });
    }
  } catch (error) {
    console.error('Error al obtener citas:', error);
    res.status(500).json({ error: 'Error al obtener citas' });
  }
});

/* ========================
*  Rutas de Gestión de Recordatorios
* ======================== */

// Obtener todas las alarmas de recordatorios
app.get('/recordatorios', async (req, res) => {
  const connection = req.app.locals.connection;
  try {
    const [alertas] = await connection.execute(`
      SELECT Recordatorios.id, Recordatorios.id_Mascota, Mascota.Nombre AS nombre_mascota,
             Recordatorios.id_cliente, Recordatorios.Fecha, Recordatorios.descripcion
      FROM Recordatorios
      JOIN Mascota ON Recordatorios.id_Mascota = Mascota.id
    `);
    res.json(alertas);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener las alertas' });
  }
});

//conseguir mascotas para mostrar dependiendo el id del dueño al crear un recordatorio
app.get('/Mascota/recordatorio/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const [resultado] = await conexion.execute("SELECT M.id, M.nombre FROM Mascota M WHERE M.id_cliente = ?", [id]);
    if (resultado.length > 0) {
      res.json(resultado[0]);
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
  const connection = req.app.locals.connection;
  const { id } = req.params;
  const { cliente, mascota, fecha, descripcion } = req.body;

  try {
    await connection.execute(`
      UPDATE Recordatorios
      SET id_cliente = ?, id_Mascota = ?, Fecha = ?, descripcion = ?
      WHERE id = ?
    `, [cliente, mascota, fecha, descripcion, id]);

    res.json({ message: 'Recordatorio actualizado correctamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al modificar el recordatorio' });
  }
});

// Guardar un nuevo recordatorio
app.post('/recordatorios/guardar', async (req, res) => {
  const connection = req.app.locals.connection;
  const { cliente, mascota, fecha, descripcion } = req.body;

  try {
    if (!fecha || typeof fecha !== 'string') {
      throw new Error('Fecha inválida');
    }
    const fechaParseada = fecha;

    const [usuario] = await connection.execute(
      'SELECT n_documento FROM Usuarios WHERE n_documento = ?',
      [cliente]
    );
    if (usuario.length === 0) {
      return res.status(400).json({ error: 'Cliente no existe' });
    }

    const [mascotaBD] = await connection.execute(
      'SELECT id FROM Mascota WHERE id = ? AND id_cliente = ?',
      [mascota, cliente]
    );
    if (mascotaBD.length === 0) {
      return res.status(400).json({ error: 'Mascota no coincide con cliente' });
    }

    await connection.execute(
      `
      INSERT INTO Recordatorios (id_cliente, id_Mascota, Fecha, descripcion)
      VALUES (?, ?, ?, ?)
      `,
      [cliente, mascota, fechaParseada, descripcion]
    );

    res.status(201).json({ message: 'Recordatorio guardado correctamente' });
  } catch (error) {
    console.error('Error al guardar recordatorio:', error);
    res.status(500).json({ error: 'Error al guardar el recordatorio' });
  }
});

// Eliminar recordatorio
app.delete('/recordatorios/eliminar/:id', async (req, res) => {
  const connection = req.app.locals.connection;
  const { id } = req.params;

  try {
    await connection.execute("DELETE FROM Recordatorios WHERE id = ?", [id]);
    res.json({ message: 'Recordatorio eliminado correctamente' });
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar el recordatorio' });
  }
});

// Rutas de la API
const PORT = process.env.DB_PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor escuchando en el puerto: ${PORT}`);
});


app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});
