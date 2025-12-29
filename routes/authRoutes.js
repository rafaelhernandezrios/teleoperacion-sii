/**
 * Rutas de Autenticación
 */

import express from 'express';
import bcrypt from 'bcryptjs';
import User from '../models/User.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

/**
 * GET /auth/login
 * Show login page
 */
router.get('/login', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  const registered = req.query.registered === '1';
  res.render('auth/login', {
    title: 'Login',
    error: null,
    registered: registered,
  });
});

/**
 * POST /auth/login
 * Process login
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log('Login attempt for:', email);

    if (!email || !password) {
      console.log('Login failed: Missing email or password');
      return res.render('auth/login', {
        title: 'Login',
        error: 'Email and password are required',
      });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase().trim() });

    if (!user) {
      console.log('Login failed: User not found');
      return res.render('auth/login', {
        title: 'Login',
        error: 'Invalid credentials',
      });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      console.log('Login failed: Invalid password');
      return res.render('auth/login', {
        title: 'Login',
        error: 'Invalid credentials',
      });
    }

    // Verify active account
    if (!user.isActive) {
      console.log('Login failed: Account inactive');
      return res.render('auth/login', {
        title: 'Login',
        error: 'Your account is inactive. Contact the administrator.',
      });
    }

    // Crear sesión directamente
    req.session.user = {
      id: user._id.toString(),
      name: user.name,
      email: user.email,
      role: user.role,
      allowed_robots: user.allowed_robots || [],
    };

    // Guardar sesión explícitamente y esperar a que se persista en MongoDB
    req.session.save((err) => {
      if (err) {
        console.error('❌ Error saving session:', err);
        return res.render('auth/login', {
          title: 'Login',
          error: 'Error signing in. Please try again.',
        });
      }
      
      console.log('✅ Session save callback called for user:', user.email);
      console.log('Session ID:', req.sessionID);
      
      // Establecer la cookie manualmente
      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 14 * 24 * 60 * 60 * 1000,
        path: '/',
      };
      
      res.cookie('sessionId', req.sessionID, cookieOptions);
      console.log('✅ Cookie set with sessionID:', req.sessionID);
      
      // Esperar a que la sesión se persista en MongoDB antes de redirigir
      // Esto es crítico en Vercel/serverless donde la función puede terminar antes
      const checkSessionInStore = (attempts = 0) => {
        const maxAttempts = 10;
        const delay = 100; // 100ms entre intentos
        
        req.sessionStore.get(req.sessionID, (err, session) => {
          if (err) {
            console.error('❌ Error verifying session:', err);
            // Redirigir de todas formas después de algunos intentos
            if (attempts >= maxAttempts) {
              console.log('⚠️ Max attempts reached, redirecting anyway');
              return res.redirect('/dashboard');
            }
            setTimeout(() => checkSessionInStore(attempts + 1), delay);
            return;
          }
          
          if (session && session.user) {
            console.log('✅ Session confirmed in MongoDB store with user data');
            console.log('Session data:', JSON.stringify(session.user));
            res.redirect('/dashboard');
          } else if (attempts < maxAttempts) {
            console.log(`⏳ Session not found yet (attempt ${attempts + 1}/${maxAttempts}), retrying...`);
            setTimeout(() => checkSessionInStore(attempts + 1), delay);
          } else {
            console.log('⚠️ Session not found after max attempts, redirecting anyway');
            // Redirigir de todas formas - el middleware de restauración debería manejarlo
            res.redirect('/dashboard');
          }
        });
      };
      
      // Empezar a verificar después de un pequeño delay
      setTimeout(() => checkSessionInStore(), 50);
    });
  } catch (error) {
    console.error('Error in login:', error);
    res.render('auth/login', {
      title: 'Login',
      error: 'Error signing in. Please try again.',
    });
  }
});

/**
 * GET /auth/register
 * Show registration page
 */
router.get('/register', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  res.render('auth/register', {
    title: 'Sign Up',
    error: null,
  });
});

/**
 * POST /auth/register
 * Process registration
 */
router.post('/register', async (req, res) => {
  try {
    const { name, email, password, occupation, company, country } = req.body;

    // Validaciones
    if (!name || !email || !password) {
      return res.render('auth/register', {
        title: 'Sign Up',
        error: 'Name, email and password are required',
      });
    }

    if (password.length < 6) {
      return res.render('auth/register', {
        title: 'Sign Up',
        error: 'Password must be at least 6 characters',
      });
    }

    // Check if email already exists
    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });

    if (existingUser) {
      return res.render('auth/register', {
        title: 'Sign Up',
        error: 'This email is already registered',
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const user = new User({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      occupation: occupation?.trim() || '',
      company: company?.trim() || '',
      country: country?.trim() || '',
      role: 'user',
      allowed_robots: [],
      isActive: true,
    });

    await user.save();

    // Redirigir a login
    res.redirect('/auth/login?registered=1');
  } catch (error) {
    console.error('Error in registration:', error);
    res.render('auth/register', {
      title: 'Sign Up',
      error: 'Error signing up. Please try again.',
    });
  }
});

/**
 * GET /auth/logout
 * Logout
 */
router.get('/logout', requireAuth, (req, res) => {
  const sessionId = req.sessionID;
  
  console.log('Logout requested for session:', sessionId);
  
  // Limpiar la cookie primero
  res.clearCookie('sessionId', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  });
  
  // Destruir la sesión
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    } else {
      console.log('✅ Session destroyed successfully');
    }
    
    // Redirigir a la landing page (raíz)
    res.redirect('/');
  });
});

export { router as authRoutes };

