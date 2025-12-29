/**
 * Servidor Principal - Sistema de Teleoperación de Robots
 * Stack: Node.js + Express + EJS + MongoDB
 */

import express from 'express';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import cookieParser from 'cookie-parser';
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
app.use(cookieParser()); // Necesario para leer cookies correctamente
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

// Middleware para restaurar sesión si los datos no están cargados
app.use((req, res, next) => {
  // No restaurar sesión en rutas de logout o login
  if (req.path === '/auth/logout' || req.path === '/auth/login') {
    return next();
  }
  
  // Si ya hay datos de usuario, continuar inmediatamente
  if (req.session && req.session.user) {
    return next();
  }
  
  // Verificar la cookie directamente
  const cookieSessionId = req.cookies?.sessionId;
  let hasCalledNext = false;
  
  const safeNext = () => {
    if (!hasCalledNext) {
      hasCalledNext = true;
      next();
    }
  };
  
  // Si hay una cookie con sessionID pero req.sessionID es diferente, hay un problema
  if (cookieSessionId && req.sessionID && cookieSessionId !== req.sessionID) {
    console.log('⚠️ Session ID mismatch detected!');
    console.log('  - Cookie sessionId:', cookieSessionId);
    console.log('  - req.sessionID:', req.sessionID);
    console.log('  - Attempting to load session from cookie ID...');
    
    // Intentar cargar la sesión usando el ID de la cookie
    sessionStore.get(cookieSessionId, (err, session) => {
      if (hasCalledNext) return;
      
      if (err) {
        console.error('❌ Error getting session from store:', err);
        return safeNext();
      }
      
      if (session && session.user) {
        console.log('✅ Found session with user data, restoring to current session...');
        // Copiar los datos a la sesión actual sin guardar (evita crear nueva sesión)
        req.session.user = session.user;
        // Marcar como modificado pero no guardar explícitamente para evitar crear nueva sesión
        req.session.touch();
        console.log('✅ Session restored successfully');
        return safeNext();
      } else {
        console.log('❌ Session from cookie not found in MongoDB');
        // No continuar con checkSessionData - ya intentamos restaurar
        return safeNext();
      }
    });
  } else {
    // Verificación normal si no hay mismatch
    checkSessionData();
  }
  
  function checkSessionData() {
    if (hasCalledNext) return;
    
    // Solo verificar si hay un sessionID pero no hay datos de usuario
    if (req.sessionID && req.session && !req.session.user) {
      console.log('⚠️ Session exists but user data missing, attempting to restore...');
      console.log('Session ID:', req.sessionID);
      
      // Intentar recuperar la sesión desde MongoDB
      sessionStore.get(req.sessionID, (err, session) => {
        if (hasCalledNext) return;
        
        if (err) {
          console.error('❌ Error getting session from store:', err);
          return safeNext();
        }
        
        if (session && session.user) {
          console.log('✅ Restoring user data from MongoDB');
          // Restaurar los datos del usuario en la sesión
          req.session.user = session.user;
          // Marcar como modificado pero no guardar explícitamente
          req.session.touch();
          console.log('✅ Session restored successfully');
          return safeNext();
        } else {
          console.log('❌ Session not found in MongoDB or has no user data');
          return safeNext();
        }
      });
    } else {
      safeNext();
    }
  }
});

// Middleware para debug de sesiones (solo en desarrollo o para debugging)
app.use((req, res, next) => {
  if (req.path === '/dashboard' || req.path.startsWith('/auth')) {
    console.log('=== Session Debug ===');
    console.log('Path:', req.path);
    console.log('Session ID from req.sessionID:', req.sessionID);
    console.log('Session exists:', !!req.session);
    console.log('Session user:', req.session?.user ? 'exists' : 'missing');
    console.log('Full session object keys:', Object.keys(req.session || {}));
    console.log('Cookies in request:', req.headers.cookie);
    
    // Parsear cookies manualmente para ver qué sessionId está llegando
    if (req.headers.cookie) {
      const cookies = req.headers.cookie.split(';').reduce((acc, cookie) => {
        const [key, value] = cookie.trim().split('=');
        acc[key] = value;
        return acc;
      }, {});
      console.log('Parsed cookies:', cookies);
      console.log('sessionId from parsed cookies:', cookies.sessionId);
    }
    
    // Verificar si la sesión existe en MongoDB
    if (req.sessionID) {
      sessionStore.get(req.sessionID, (err, session) => {
        if (err) {
          console.log('❌ Error getting session from store:', err);
        } else {
          if (session) {
            console.log('✅ Session found in MongoDB');
            console.log('Session data in MongoDB:', JSON.stringify(session, null, 2));
            console.log('Session.user in MongoDB:', session.user ? 'exists' : 'missing');
            
            // Comparar sessionID
            if (session._id !== req.sessionID) {
              console.log('⚠️ WARNING: Session ID mismatch!');
              console.log('  - req.sessionID:', req.sessionID);
              console.log('  - session._id:', session._id);
            }
          } else {
            console.log('❌ Session NOT found in MongoDB for ID:', req.sessionID);
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

