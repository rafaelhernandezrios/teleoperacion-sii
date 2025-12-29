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

    // Guardar sesión explícitamente antes de redirigir
    req.session.save((err) => {
      if (err) {
        console.error('❌ Error saving session:', err);
        return res.render('auth/login', {
          title: 'Login',
          error: 'Error signing in. Please try again.',
        });
      }
      
      console.log('✅ Session saved for user:', user.email);
      console.log('Session ID:', req.sessionID);
      
      // Establecer la cookie manualmente con las mismas opciones que express-session
      // Esto es necesario porque express-session puede no establecerla antes del redirect
      const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 14 * 24 * 60 * 60 * 1000,
        path: '/',
      };
      
      res.cookie('sessionId', req.sessionID, cookieOptions);
      console.log('✅ Cookie set with sessionID:', req.sessionID);
      
      // Verificar que la sesión está en el store
      req.sessionStore.get(req.sessionID, (err, session) => {
        if (err) {
          console.error('❌ Error verifying session:', err);
        } else if (session) {
          console.log('✅ Session confirmed in MongoDB store');
        } else {
          console.log('⚠️ Session not found in store (may be async write)');
        }
      });
      
      // Redirigir después de establecer la cookie
      res.redirect('/dashboard');
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
  req.session.destroy((err) => {
    if (err) {
      console.error('Error logging out:', err);
    }
    res.redirect('/auth/login');
  });
});

export { router as authRoutes };

