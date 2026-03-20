process.on('uncaughtException', (err) => {
    console.error('ERROR NO CAPTURADO:', err);
});

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Asegura que exista la carpeta en Linux
const uploadDir = process.env.UPLOAD_DIR ||
    (process.platform === 'win32' ?
        path.join(__dirname, 'uploads') :
        '/uploads');

if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, {
    recursive: true
});

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        console.log('Intentando escribir en:', uploadDir);
        console.log('¿Existe?', fs.existsSync(uploadDir));
        try {
            fs.accessSync(uploadDir, fs.constants.W_OK);
            console.log('Tiene permisos de escritura ✓');
        } catch (e) {
            console.log('SIN permisos de escritura ✗', e.message);
            return cb(new Error('No se puede escribir en el directorio de uploads'));
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const basename = path.basename(file.originalname, ext).replace(/\s+/g, '_');
        const unique = Date.now() + '-' + Math.round(Math.random() * 1e6);
        cb(null, `${basename}-${unique}${ext}`);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 2 * 1024 * 1024
    }, // 2MB
    fileFilter: (req, file, cb) => {
        if (file.mimetype !== 'application/pdf') return cb(new Error('Solo PDF'));
        cb(null, true);
    }
});

// middleware para validar token (sin rol)
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null;
    if (!token) return res.status(401).json({
        error: 'Token requerido'
    });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (err) {
        return res.status(401).json({
            error: 'Token inválido'
        });
    }
};
const {
    Pool
} = require('pg');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors({
    origin: process.env.URL_BACKEND,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({
    extended: true
}));

// Configuración de conexión a PostgreSQL desde variables de entorno
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Endpoint de login
app.post('/api/login', async (req, res) => {
    const {
        username,
        password
    } = req.body;
    console.log('Intentando login con:', username, password);

    try {
        // Buscamos al usuario por username
        const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (user.rows.length === 0) return res.status(401).json({
            error: 'Usuario no encontrado'
        });

        // Comparamos la contraseña enviada con la hash de la DB
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) return res.status(401).json({
            error: 'Contraseña incorrecta'
        });

        // Verificamos que tenga al menos un grupo asignado
        const groups = await pool.query(
            'SELECT COUNT(*) FROM user_groups WHERE user_id = $1',
            [user.rows[0].id]
        );
        if (groups.rows[0].count == 0) {
            return res.status(403).json({
                error: 'Usuario registrado. Espere hasta que el administrador asigne un grupo.'
            });
        }

        // Creamos token JWT con id y role
        const token = jwt.sign({
            id: user.rows[0].id,
            role: user.rows[0].role
        }, process.env.JWT_SECRET, {
            expiresIn: '1h'
        });
        res.json({
            token,
            role: user.rows[0].role
        });
    } catch (err) {
        console.error('Error en login:', err);
        res.status(500).json({
            error: 'Error interno'
        });
    }
});

// Endpoint para obtener los grupos del usuario (requiere token válido)
app.get('/api/groups', async (req, res) => {
    const token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null;
    if (!token) return res.status(401).json({
        error: 'Token requerido'
    });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const groups = await pool.query(
            'SELECT g.name FROM groups g JOIN user_groups ug ON g.id = ug.group_id WHERE ug.user_id = $1',
            [decoded.id]
        );
        res.json(groups.rows);
    } catch (err) {
        res.status(401).json({
            error: 'Token inválido'
        });
    }
});

// Middleware para verificar rol admin
const verifyAdmin = (req, res, next) => {
    const token = req.headers.authorization ? req.headers.authorization.split(' ')[1] : null;
    if (!token) return res.status(401).json({
        error: 'Token requerido'
    });


    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({
            error: 'Acceso denegado'
        });
        req.userId = decoded.id;
        next();
    } catch (err) {
        res.status(401).json({
            error: 'Token inválido'
        });
    }
};

// Endpoint admin: listado de usuarios con grupos
app.get('/api/users', verifyAdmin, async (req, res) => {
    try {
        const users = await pool.query('SELECT id, username, email, role FROM users');
        const usersWithGroups = await Promise.all(users.rows.map(async (user) => {
            const groups = await pool.query(
                'SELECT g.id, g.name FROM groups g JOIN user_groups ug ON g.id = ug.group_id WHERE ug.user_id = $1',
                [user.id]
            );
            return {
                ...user,
                groups: groups.rows
            };
        }));
        res.json(usersWithGroups);
    } catch (err) {
        res.status(500).json({
            error: 'Error interno'
        });
    }
});

// Admin asigna grupo a usuario
app.put('/api/users/:id/group', verifyAdmin, async (req, res) => {
    const {
        groupId
    } = req.body;
    const userId = req.params.id;
    try {
        const existing = await pool.query(
            'SELECT * FROM user_groups WHERE user_id = $1 AND group_id = $2',
            [userId, groupId]
        );
        if (existing.rows.length > 0) {
            return res.status(400).json({
                error: 'El usuario ya tiene este grupo asignado'
            });
        }

        await pool.query('INSERT INTO user_groups (user_id, group_id) VALUES ($1, $2)', [userId, groupId]);
        res.json({
            message: 'Grupo asignado'
        });
    } catch (err) {
        res.status(500).json({
            error: 'Error interno'
        });
    }
});

// Admin cambia contraseña de usuario
app.put('/api/users/:id/password', verifyAdmin, async (req, res) => {
    const {
        newPassword
    } = req.body;
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    try {
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, req.params.id]);
        res.json({
            message: 'Contraseña cambiada'
        });
    } catch (err) {
        res.status(500).json({
            error: 'Error interno'
        });
    }
});

// Admin elimina usuario
app.delete('/api/users/:id', verifyAdmin, async (req, res) => {
    const userId = req.params.id;
    try {
        await pool.query('DELETE FROM user_groups WHERE user_id = $1', [userId]);
        await pool.query('DELETE FROM users WHERE id = $1', [userId]);
        res.json({
            message: 'Usuario eliminado'
        });
    } catch (err) {
        console.error('Error al eliminar usuario:', err);
        res.status(500).json({
            error: 'Error interno'
        });
    }
});

// Registro de usuario (hash de contraseña)
app.post('/api/register', async (req, res) => {
    const {
        username,
        password,
        email
    } = req.body;
    console.log('Registrando usuario:', username, email);

    try {
        const existingUser = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({
                error: 'Usuario ya existe'
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password, email) VALUES ($1, $2, $3)', [username, hashedPassword, email]);
        res.status(201).json({
            message: 'Usuario registrado exitosamente'
        });
    } catch (err) {
        console.error('Error en registro:', err);
        res.status(500).json({
            error: 'Error interno'
        });
    }
});

// Admin obtiene todos los grupos
app.get('/api/all-groups', verifyAdmin, async (req, res) => {
    try {
        const groups = await pool.query('SELECT * FROM groups');
        res.json(groups.rows);
    } catch (err) {
        res.status(500).json({
            error: 'Error interno'
        });
    }
});

// Admin obtiene grupos asignados a un usuario específico
app.get('/api/users/:userId/groups', verifyAdmin, async (req, res) => {
    try {
        const groups = await pool.query(
            'SELECT g.id, g.name FROM groups g JOIN user_groups ug ON g.id = ug.group_id WHERE ug.user_id = $1',
            [req.params.userId]
        );
        res.json(groups.rows);
    } catch (err) {
        res.status(500).json({
            error: 'Error interno'
        });
    }
});

// Admin revoca grupo de usuario
app.delete('/api/users/:userId/group/:groupId', verifyAdmin, async (req, res) => {
    const {
        userId,
        groupId
    } = req.params;
    try {
        await pool.query('DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2', [userId, groupId]);
        res.json({
            message: 'Grupo revocado'
        });
    } catch (err) {
        res.status(500).json({
            error: 'Error interno'
        });
    }
});

// subir pdf
app.get('/api/subir-pdf', (req, res) => {
    res.status(405).json({
        error: 'Metodo no permitido. Usa POST con multipart/form-data (campo pdfFile) y token Bearer.'
    });
});

app.post('/api/subir-pdf', verifyToken, upload.single('pdfFile'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({
            error: 'No se recibió archivo'
        });

        const existingFile = await pool.query(
            'SELECT id FROM user_files WHERE user_id = $1 LIMIT 1',
            [req.userId]
        );
        if (existingFile.rows.length > 0) {
            return res.status(400).json({
                error: 'Ya tienes un archivo subido. Retiralo antes de cargar uno nuevo.'
            });
        }

        // Si multer entrega req.file, el archivo ya fue procesado y escrito en destino.
        const filePath = path.resolve(uploadDir, req.file.filename);

        await pool.query(
            'INSERT INTO user_files (user_id, file_name, file_path, file_type) VALUES ($1, $2, $3, $4)',
            [req.userId, req.file.originalname, filePath, req.file.mimetype]
        );
        res.json({
            message: 'PDF subido',
            filePath
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: 'Error interno al subir PDF'
        });
    }
});

// listar archivos del usuario
app.get('/api/user-files', verifyToken, async (req, res) => {
    try {
        const files = await pool.query('SELECT id, file_name, file_path, uploaded_at FROM user_files WHERE user_id = $1 ORDER BY uploaded_at DESC', [req.userId]);
        res.json(files.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: 'Error interno'
        });
    }
});

app.delete('/api/user-files/:id', verifyToken, async (req, res) => {
    try {
        const fileResult = await pool.query(
            'SELECT id, file_path FROM user_files WHERE id = $1 AND user_id = $2',
            [req.params.id, req.userId]
        );

        if (fileResult.rows.length === 0) {
            return res.status(404).json({
                error: 'Archivo no encontrado'
            });
        }

        const storedFilePath = fileResult.rows[0].file_path;

        await pool.query('DELETE FROM user_files WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);

        if (storedFilePath && fs.existsSync(storedFilePath)) {
            fs.unlinkSync(storedFilePath);
        }

        res.json({
            message: 'Archivo retirado'
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: 'Error interno al retirar archivo'
        });
    }
});

app.put('/api/change-password', verifyToken, async (req, res) => {
    const {
        currentPassword,
        newPassword
    } = req.body;

    try {
        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                error: 'Faltan campos requeridos'
            });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({
                error: 'La nueva contraseña debe tener al menos 6 caracteres'
            });
        }

        const user = await pool.query('SELECT id, password FROM users WHERE id = $1', [req.userId]);
        if (user.rows.length === 0) {
            return res.status(404).json({
                error: 'Usuario no encontrado'
            });
        }

        const validCurrent = await bcrypt.compare(currentPassword, user.rows[0].password);
        if (!validCurrent) {
            return res.status(401).json({
                error: 'La contraseña actual es incorrecta'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, req.userId]);

        res.json({
            message: 'Contraseña actualizada correctamente'
        });
    } catch (err) {
        console.error('Error en /api/change-password:', err);
        res.status(500).json({
            error: 'Error interno'
        });
    }
});

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        // Errores específicos de multer
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                error: 'El archivo supera 2MB'
            });
        }
        return res.status(400).json({
            error: `Error al subir archivo: ${err.message}`
        });
    }

    // Errores custom (ej: el fileFilter lanza 'Solo PDF')
    if (err.message === 'Solo PDF') {
        return res.status(400).json({
            error: 'Solo se permiten archivos PDF'
        });
    }

    res.status(500).json({
        error: err.message || 'Error interno'
    });


});

app.listen(3000, () => console.log('Servidor corriendo en puerto 3000'));