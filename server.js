/**
 * Servidor Principal - Sistema de Teleoperación de Robots
 * Stack: Node.js + Express + EJS + MongoDB
 */

import express from 'express';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';
import connectDB from './config/db.js';
import { authRoutes } from './routes/authRoutes.js';
import dashboardRoutes from './routes/dashboardRoutes.js';
import reservationRoutes from './routes/reservationRoutes.js';
import robotRoutes from './routes/robotRoutes.js';
import adminRoutes from './routes/adminRoutes.js';

// Configurar __dirname para ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Cargar variables de entorno
dotenv.config();

// Inicializar Express
const app = express();
const PORT = process.env.PORT || 3000;

// Conectar a MongoDB
connectDB();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configurar sesiones con MongoDB
const isProduction = process.env.NODE_ENV === 'production';

// Crear el store - usar mongoUrl directamente para mejor compatibilidad en Vercel
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGO_URI,
  ttl: 14 * 24 * 60 * 60, // 14 días
  touchAfter: 24 * 3600, // Lazy session update
  autoRemove: 'native', // Usar el método nativo de MongoDB para limpiar sesiones expiradas
  stringify: false, // No stringify, guardar como objeto
  collectionName: 'sessions', // Nombre de la colección
  // Opciones adicionales para Vercel/serverless
  mongoOptions: {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    // Asegurar que la conexión se mantenga activa
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  },
});

// Event listeners para debug del store
sessionStore.on('create', (sessionId) => {
  console.log('✅ Session created in store:', sessionId);
});

sessionStore.on('update', (sessionId) => {
  console.log('✅ Session updated in store:', sessionId);
});

sessionStore.on('set', (sessionId) => {
  console.log('✅ Session set in store:', sessionId);
});

sessionStore.on('destroy', (sessionId) => {
  console.log('🗑️ Session destroyed in store:', sessionId);
});

sessionStore.on('error', (error) => {
  console.error('❌ Session store error:', error);
});

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
    resave: false, // Solo guardar si la sesión fue modificada
    saveUninitialized: false, // No crear sesiones vacías - solo cuando hay datos
    store: sessionStore,
    cookie: {
      secure: isProduction, // true en producción (HTTPS)
      httpOnly: true,
      maxAge: 14 * 24 * 60 * 60 * 1000, // 14 días
      sameSite: 'lax', // 'lax' funciona mejor en Vercel
      path: '/', // Asegurar que la cookie esté disponible en todas las rutas
      // No especificar domain para que use el dominio actual automáticamente
    },
    name: 'sessionId', // Nombre personalizado para la cookie
  })
);

// Middleware para debug de sesiones (solo en desarrollo o para debugging)
app.use((req, res, next) => {
  if (req.path === '/dashboard' || req.path.startsWith('/auth')) {
    console.log('=== Session Debug ===');
    console.log('Path:', req.path);
    console.log('Session ID from cookie:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session user:', req.session?.user ? 'exists' : 'missing');
    console.log('Cookies in request:', req.headers.cookie);
    
    // Verificar si la sesión existe en MongoDB
    if (req.sessionID) {
      sessionStore.get(req.sessionID, (err, session) => {
        if (err) {
          console.log('Error getting session from store:', err);
        } else {
          console.log('Session in MongoDB:', session ? 'found' : 'not found');
          if (session) {
            console.log('Session data in MongoDB:', JSON.stringify(session));
          }
        }
      });
    }
    console.log('===================');
  }
  next();
});

// Configurar EJS como motor de plantillas
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Middleware para pasar datos del usuario a las vistas
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.isAuthenticated = !!req.session.user;
  next();
});

// Rutas
app.use('/auth', authRoutes);
app.use('/dashboard', dashboardRoutes);
app.use('/reservations', reservationRoutes);
app.use('/robots', robotRoutes);
app.use('/admin', adminRoutes);

// Ruta raíz - mostrar landing page si no está autenticado, sino redirigir a dashboard
app.get('/', (req, res) => {
  if (req.session.user) {
    res.redirect('/dashboard');
  } else {
    res.render('landing', {
      title: 'Robot Teleoperation System',
    });
  }
});

// Manejo de errores 404
app.use((req, res) => {
  res.status(404).render('error', {
    title: '404 - Página no encontrada',
    message: 'La página que buscas no existe',
    user: req.session.user || null,
  });
});

// Manejo de errores del servidor
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).render('error', {
    title: '500 - Error del servidor',
    message: 'Ocurrió un error en el servidor',
    user: req.session.user || null,
  });
});

// Iniciar servidor
// En Vercel, no necesitamos app.listen() - Vercel maneja esto automáticamente
if (process.env.NODE_ENV !== 'production' || process.env.VERCEL !== '1') {
  app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
    console.log(`📊 Ambiente: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔐 Session Secret configurado: ${process.env.SESSION_SECRET ? 'Sí' : 'No'}`);
    console.log(`🍪 Cookie secure: ${isProduction ? 'true (HTTPS)' : 'false (HTTP)'}`);
    console.log(`🍪 Cookie sameSite: ${isProduction ? 'none' : 'lax'}`);
  });
}

// Exportar para Vercel
export default app;

