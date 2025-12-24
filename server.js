import express from 'express';
import cors from 'cors';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import OpenAI from 'openai';
import { verifyUserFromToken } from './authHelpers.js';
import { savePromptHistory, savePrompt } from './historyHelpers.js';
import { getUserProStatus, getUserCredits, deductCredits } from './userHelpers.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Load environment variables
dotenv.config();

// Get current directory for serving static files
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Initialize OpenAI client
if (!process.env.OPENAI_API_KEY) {
  console.warn('Warning: OPENAI_API_KEY not set. OpenAI functionality will not work.');
}
const openai = process.env.OPENAI_API_KEY ? new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
}) : null;

const app = express();
const PORT = process.env.PORT || 3000;

// Enable CORS for frontend requests
app.use(cors());

// Enable JSON body parsing
app.use(express.json());

// Serve static files (HTML, CSS, JS)
app.use(express.static(__dirname));

// Route handlers for HTML files
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, 'auth.html'));
});

app.get('/auth', (req, res) => {
  res.sendFile(join(__dirname, 'auth.html'));
});

app.get('/app', (req, res) => {
  res.sendFile(join(__dirname, 'app.html'));
});

// GET /extension-connect - Connect Chrome extension with Pro token
// Clean flow: website owns auth, extension only consumes token
app.get('/extension-connect', async (req, res) => {
  try {
    // Get token from Authorization header or query param
    const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
    
    // PART 2: If user is NOT logged in → redirect to /auth (login page)
    if (!token) {
      return res.redirect('/auth');
    }

    // Verify token and get authenticated user id
    let user;
    try {
      user = await verifyUserFromToken(token);
    } catch (error) {
      // Invalid token - redirect to login
      return res.redirect('/auth');
    }

    const userId = user.userId;

    // Create authenticated Supabase client
    const authenticatedClient = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY,
      {
        global: {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      }
    );

    // Check if user is Pro
    const isPro = await getUserProStatus({
      authenticatedClient,
      userId
    });

    // PART 2: If user IS logged in but NOT Pro → redirect to /upgrade
    if (!isPro) {
      return res.redirect('/upgrade');
    }

    // PART 2: If user IS logged in AND Pro:
    // Generate extension token (use Supabase token as extension token)
    // Token includes user_id and plan, expiry handled by Supabase token itself
    // For simplicity, we'll use the Supabase access token as the extension token
    // It already contains user_id and has expiry built-in
    
    const extensionToken = token; // Use Supabase token directly (already has user_id, expiry)
    
    // Redirect to extension-connect page with token (extension will detect and extract)
    // This is a special page that the extension monitors via tabs API
    res.redirect(`/extension-connect-success?token=${encodeURIComponent(extensionToken)}`);
  } catch (error) {
    console.error('Error in /extension-connect:', error);
    // On error, redirect to login
    res.redirect('/auth');
  }
});

// Removed: extension-connect.html is no longer needed
// Custom protocol redirect handles everything

// GET /upgrade - Upgrade page (redirects to app for now)
app.get('/upgrade', (req, res) => {
  // For now, redirect to app page
  // In future, this could be a dedicated upgrade page
  res.redirect('/app');
});

// GET /extension-connect-success - Success page that extension monitors
app.get('/extension-connect-success', (req, res) => {
  // This page is monitored by the extension via tabs API
  // Extension will extract token from URL and save it
  res.sendFile(join(__dirname, 'extension-connect-success.html'));
});

// POST /api/history/save
app.post('/api/history/save', async (req, res) => {
  try {
    const { token, type, original_input, final_prompt, action, prompt } = req.body;
    
    // Request logging
    console.log('POST /api/history/save endpoint hit');
    console.log('action:', action);
    console.log('prompt length:', prompt?.length ?? 'N/A');
    console.log('token exists:', !!token);

    // Validate required fields
    if (!token || !type || !original_input || !final_prompt) {
      return res.status(400).json({ 
        error: 'Missing required fields: token, type, original_input, final_prompt' 
      });
    }

    // Verify token and get authenticated user id (never trust client input)
    const user = await verifyUserFromToken(token);
    const userId = user.userId;

    // Create a per-request Supabase client with anon key
    // Pass the user's access token via Authorization header for RLS
    const authenticatedClient = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY,
      {
        global: {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      }
    );

    // Save prompt history using the authenticated client
    await savePromptHistory({
      authenticatedClient,
      userId,
      type,
      originalInput: original_input,
      finalPrompt: final_prompt
    });

    return res.json({ success: true });
  } catch (error) {
    // Invalid token or authentication error
    if (error.message.includes('token') || error.message.includes('Invalid')) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Other errors
    return res.status(500).json({ error: error.message });
  }
});

// GET /api/pro/check
app.get('/api/pro/check', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;

    // Validate token
    if (!token) {
      return res.status(401).json({ error: 'Missing access token' });
    }

    // Verify token and get authenticated user id (never trust client input)
    const user = await verifyUserFromToken(token);
    const userId = user.userId;

    // Create a per-request Supabase client with anon key
    // Pass the user's access token via Authorization header for RLS
    const authenticatedClient = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY,
      {
        global: {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      }
    );

    // Get user's Pro status using the authenticated client
    const isPro = await getUserProStatus({
      authenticatedClient,
      userId
    });

    return res.json({ isPro });
  } catch (error) {
    // Invalid token or authentication error
    if (error.message.includes('token') || error.message.includes('Invalid')) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Other errors
    return res.status(500).json({ error: error.message });
  }
});

// GET /api/me
app.get('/api/me', async (req, res) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or invalid Authorization header' });
    }

    const token = authHeader.replace('Bearer ', '');

    // Verify token and get authenticated user id (never trust client input)
    const user = await verifyUserFromToken(token);
    const userId = user.userId;

    // Create a per-request Supabase client with anon key
    // Pass the user's access token via Authorization header for RLS
    const authenticatedClient = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY,
      {
        global: {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      }
    );

    // Query users table for user data
    const { data: userData, error } = await authenticatedClient
      .from('users')
      .select('email, is_pro, credits')
      .eq('id', userId)
      .single();

    if (error) {
      // If user doesn't exist in users table, use email from auth
      if (error.code === 'PGRST116') {
        return res.json({
          email: user.email,
          plan: 'Free',
          credits: 0
        });
      }
      throw new Error(`Failed to get user data: ${error.message}`);
    }

    // Return formatted response
    return res.json({
      email: userData.email || user.email,
      plan: userData.is_pro === true ? 'Pro' : 'Free',
      credits: userData.credits ?? 0
    });
  } catch (error) {
    // Invalid token or authentication error
    if (error.message.includes('token') || error.message.includes('Invalid')) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Other errors
    console.error('Error getting user data:', error);
    return res.status(500).json({ error: error.message });
  }
});

// POST /api/credits/add - Admin-only endpoint to add credits to a user
app.post('/api/credits/add', async (req, res) => {
  try {
    const { email, credits, secret } = req.body;

    // Validate secret
    if (!secret || secret !== process.env.ADMIN_SECRET) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Validate required fields - reject with 401 for invalid requests
    if (!email || typeof email !== 'string' || !email.trim()) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (typeof credits !== 'number' || credits <= 0 || !Number.isInteger(credits)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Use anon key with RLS enabled
    const supabaseClient = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY
    );

    const normalizedEmail = email.trim().toLowerCase();

    // Validate email exists by finding user
    const { data: userData, error: findError } = await supabaseClient
      .from('users')
      .select('id, credits')
      .eq('email', normalizedEmail)
      .single();

    if (findError || !userData || !userData.id) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Atomically increment credits
    // Attempt RPC function first (if exists), otherwise use direct update
    // Note: For true atomic increment, a database function is recommended
    const currentCredits = userData.credits ?? 0;
    const newCredits = currentCredits + credits;

    const { data: updatedUser, error: updateError } = await supabaseClient
      .from('users')
      .update({ credits: newCredits })
      .eq('id', userData.id)
      .select('credits')
      .single();

    if (updateError || !updatedUser) {
      return res.status(500).json({ error: 'Internal server error' });
    }

    const updatedCredits = updatedUser.credits ?? newCredits;

    // Return success response
    return res.json({
      success: true,
      email: normalizedEmail,
      creditsAdded: credits,
      totalCredits: updatedCredits
    });
  } catch (error) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Anonymous credit tracking (in-memory, keyed by IP)
// This provides a simple credit system for anonymous users
const anonymousCredits = new Map(); // IP -> credits remaining
const ANONYMOUS_FREE_CREDITS = 5; // Free credits for anonymous users

// Helper to get client IP
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
         req.headers['x-real-ip'] || 
         req.connection?.remoteAddress || 
         req.socket?.remoteAddress ||
         'unknown';
}

// Helper to get anonymous credits for an IP
function getAnonymousCredits(ip) {
  if (!anonymousCredits.has(ip)) {
    anonymousCredits.set(ip, ANONYMOUS_FREE_CREDITS);
  }
  return anonymousCredits.get(ip);
}

// Helper to deduct anonymous credits
function deductAnonymousCredits(ip, amount) {
  const current = getAnonymousCredits(ip);
  if (current < amount) {
    throw new Error('Insufficient credits');
  }
  const remaining = current - amount;
  anonymousCredits.set(ip, remaining);
  return remaining;
}

// POST /api/prompts/improve
// POST /api/prompts/refine
// POST /api/prompts/followup
// Unified endpoint handler for all prompt improvement modes
async function handlePromptImprovement(req, res, mode) {
  try {
    // Get token from body or Authorization header
    const token = req.body.token || req.headers.authorization?.replace('Bearer ', '');
    const { original_prompt, previous_prompt } = req.body;

    // Validate required fields
    if (!original_prompt || !original_prompt.trim()) {
      return res.status(400).json({ error: 'original_prompt is required' });
    }

    // Validate mode
    const validModes = ['improve', 'refine', 'followup'];
    if (!validModes.includes(mode)) {
      return res.status(400).json({ error: 'Invalid mode. Must be: improve, refine, or followup' });
    }

    // Follow-up REQUIRES authentication
    if (mode === 'followup') {
      if (!token) {
        return res.status(401).json({ error: 'Authentication required. Please log in.' });
      }
    }

    // For improve and refine, token is optional
    let user = null;
    let userId = null;
    let authenticatedClient = null;
    let isAnonymous = false;

    if (token) {
      // Try to verify token and get authenticated user
      try {
        user = await verifyUserFromToken(token);
        userId = user.userId;

        // Create a per-request Supabase client with anon key
        // Pass the user's access token via Authorization header for RLS
        authenticatedClient = createClient(
          process.env.SUPABASE_URL,
          process.env.SUPABASE_ANON_KEY,
          {
            global: {
              headers: {
                Authorization: `Bearer ${token}`
              }
            }
          }
        );
      } catch (authError) {
        // If token is invalid, treat as anonymous for improve/refine
        if (mode === 'followup') {
          return res.status(401).json({ error: 'Invalid or expired token' });
        }
        // For improve/refine, continue as anonymous
        console.log('Invalid token provided, treating as anonymous user');
        isAnonymous = true;
      }
    } else {
      // No token provided - anonymous user
      isAnonymous = true;
    }

    // Enforce Pro-only access for follow-up mode (requires authentication)
    // Improve and Refine are available to ALL authenticated users (Free or Pro)
    if (mode === 'followup') {
      if (!authenticatedClient || !userId) {
        return res.status(401).json({ error: 'Authentication required. Please log in.' });
      }
      try {
        const isPro = await getUserProStatus({ authenticatedClient, userId });
        if (!isPro) {
          return res.status(403).json({ 
            error: 'Follow-up is a Pro feature. Upgrade to Pro to use this feature.' 
          });
        }
      } catch (proError) {
        console.error('Error checking Pro status:', proError);
        return res.status(500).json({ error: 'Failed to verify Pro status' });
      }
    }
    
    // For Improve and Refine: Allow authenticated users (Free or Pro) - no plan check
    if ((mode === 'improve' || mode === 'refine') && !isAnonymous) {
      console.log(`[CREDITS] ${mode.toUpperCase()} allowed for authenticated user (Free or Pro)`);
    }

    // Determine credit cost based on mode
    const creditCosts = {
      improve: 1,
      refine: 1,
      followup: 2
    };
    const creditCost = creditCosts[mode] || 1;

    // Handle credits: authenticated users vs anonymous users
    let remainingCredits;
    let currentCredits;

    if (isAnonymous) {
      // Anonymous user credit tracking (by IP)
      const clientIP = getClientIP(req);
      currentCredits = getAnonymousCredits(clientIP);
      console.log(`[${mode.toUpperCase()}] Anonymous user (IP: ${clientIP}) current credits: ${currentCredits}`);
      
      // Explicit check: If credits <= 0, return error and do NOT proceed
      if (currentCredits <= 0) {
        console.log(`[${mode.toUpperCase()}] Anonymous user (IP: ${clientIP}) has no credits remaining (${currentCredits}). Blocking request.`);
        return res.status(402).json({ 
          error: 'No credits remaining. Sign up to get more credits.',
          creditsRemaining: currentCredits
        });
      }

      // Check if anonymous user has sufficient credits for this operation
      if (currentCredits < creditCost) {
        console.log(`[${mode.toUpperCase()}] Anonymous user (IP: ${clientIP}) has insufficient credits (${currentCredits} < ${creditCost}). Blocking request.`);
        return res.status(402).json({ 
          error: 'No credits remaining. Sign up to get more credits.',
          creditsRemaining: currentCredits
        });
      }

      // Deduct anonymous credits
      try {
        console.log(`[${mode.toUpperCase()}] Deducting ${creditCost} anonymous credit(s) for IP ${clientIP}`);
        remainingCredits = deductAnonymousCredits(clientIP, creditCost);
        console.log(`[${mode.toUpperCase()}] Anonymous credits deducted successfully. IP ${clientIP} remaining credits: ${remainingCredits}`);
      } catch (deductError) {
        if (deductError.message === 'Insufficient credits') {
          return res.status(402).json({ 
            error: 'No credits remaining. Sign up to get more credits.',
            creditsRemaining: currentCredits
          });
        }
        return res.status(500).json({ 
          error: 'Failed to process credits',
          details: deductError.message
        });
      }
    } else {
      // Authenticated user credit tracking (from database)
      // For Improve/Refine: Allow Free and Pro users - only check credits, not plan
      // Fetch user from Supabase to check credits
      try {
        currentCredits = await getUserCredits({ authenticatedClient, userId });
        console.log(`[${mode.toUpperCase()}] User ${userId} current credits: ${currentCredits}`);
      } catch (creditError) {
        console.error(`[${mode.toUpperCase()}] Error checking credits for user ${userId}:`, creditError);
        return res.status(500).json({ error: 'Failed to check credits' });
      }

      // For Improve/Refine: Only check credits, allow Free users
      // For Follow-up: Already checked Pro status above
      if (mode === 'improve' || mode === 'refine') {
        // Explicit check: If credits <= 0, return error and do NOT proceed
        if (currentCredits <= 0) {
          console.log(`[${mode.toUpperCase()}] User ${userId} has no credits remaining (${currentCredits}). Blocking request.`);
          return res.status(402).json({ 
            error: 'No credits remaining',
            creditsRemaining: currentCredits
          });
        }

        // Check if user has sufficient credits for this operation
        if (currentCredits < creditCost) {
          console.log(`[${mode.toUpperCase()}] User ${userId} has insufficient credits (${currentCredits} < ${creditCost}). Blocking request.`);
          return res.status(402).json({ 
            error: 'No credits remaining',
            creditsRemaining: currentCredits
          });
        }

        // Deduct credits before processing (as per requirements)
        try {
          console.log(`[${mode.toUpperCase()}] Deducting ${creditCost} credit(s) for user ${userId} (mode: ${mode})`);
          remainingCredits = await deductCredits({
            authenticatedClient,
            userId,
            amount: creditCost,
            accessToken: token
          });
          console.log(`[${mode.toUpperCase()}] Credits deducted successfully. User ${userId} remaining credits: ${remainingCredits}`);
        } catch (deductError) {
          console.error(`[${mode.toUpperCase()}] Error deducting credits for user ${userId}:`, deductError);
          console.error(`[${mode.toUpperCase()}] Error stack:`, deductError.stack);
          if (deductError.message === 'Insufficient credits') {
            return res.status(402).json({ 
              error: 'No credits remaining',
              creditsRemaining: currentCredits
            });
          }
          return res.status(500).json({ 
            error: 'Failed to process credits',
            details: deductError.message
          });
        }
      } else if (mode === 'followup') {
        // Follow-up: Already verified Pro status above, now check credits
        if (currentCredits <= 0) {
          console.log(`[${mode.toUpperCase()}] Pro user ${userId} has no credits remaining (${currentCredits}). Blocking request.`);
          return res.status(402).json({ 
            error: 'No credits remaining',
            creditsRemaining: currentCredits
          });
        }

        if (currentCredits < creditCost) {
          console.log(`[${mode.toUpperCase()}] Pro user ${userId} has insufficient credits (${currentCredits} < ${creditCost}). Blocking request.`);
          return res.status(402).json({ 
            error: 'No credits remaining',
            creditsRemaining: currentCredits
          });
        }

        // Deduct credits for Follow-up
        try {
          console.log(`[${mode.toUpperCase()}] Deducting ${creditCost} credit(s) for Pro user ${userId}`);
          remainingCredits = await deductCredits({
            authenticatedClient,
            userId,
            amount: creditCost,
            accessToken: token
          });
          console.log(`[${mode.toUpperCase()}] Credits deducted successfully. Pro user ${userId} remaining credits: ${remainingCredits}`);
        } catch (deductError) {
          console.error(`[${mode.toUpperCase()}] Error deducting credits for Pro user ${userId}:`, deductError);
          if (deductError.message === 'Insufficient credits') {
            return res.status(402).json({ 
              error: 'No credits remaining',
              creditsRemaining: currentCredits
            });
          }
          return res.status(500).json({ 
            error: 'Failed to process credits',
            details: deductError.message
          });
        }
      }
    }

    // Check if OpenAI is configured
    if (!openai) {
      return res.status(500).json({ error: 'OpenAI API not configured' });
    }

    // System prompts matching the extension logic exactly
    const SYSTEM_PROMPT_IMPROVE = `You are a professional prompt editor.

Rewrite the user's input into a clear, high-quality AI prompt using this structure:
- Role or perspective
- Specific task or action
- Relevant context or assumptions
- Desired output format
- Constraints or quality guidelines
- Clear success goal

Example:
Input: "help me with instagram content"
Improved:
"You are a content strategist. Create a 7-day Instagram content plan for beginner freelancers struggling to get clients. Return the output as a table with hooks, post ideas, and CTAs. Keep hooks under 8 words. The goal is to attract inbound DMs."

Rules:
- Preserve the user's original intent.
- If details are missing, make reasonable assumptions instead of asking questions.
- Keep the prompt concise and practical.
- Do NOT answer the prompt.
- Do NOT explain your changes.

Return ONLY the improved prompt text.`;

    const SYSTEM_PROMPT_REFINE = `You are a prompt refinement assistant.

Take the user's prompt and produce a clearer, more specific, and higher-quality version.

Rules:
- Preserve the user's original intent and meaning
- Make the prompt more precise and actionable
- Add clarity where needed without changing the core purpose
- Improve specificity and remove ambiguity
- Keep the prompt concise and practical
- Do NOT answer the prompt
- Do NOT add explanations
- Do NOT change the fundamental task or goal

Return ONLY the refined prompt text.`;

    const SYSTEM_PROMPT_FOLLOWUP = `You are rewriting a follow-up prompt in an ongoing conversation.

Rewrite the user's input so it clearly continues the previous task or discussion.

Rules:
- Preserve the original topic, scope, and criteria.
- Do NOT introduce a new role, task, or format unless explicitly requested.
- Do NOT generalize or reset the task.
- Make the follow-up self-contained and unambiguous.
- Keep it concise.

Return ONLY the rewritten follow-up prompt.`;

    // Build the prompt based on mode (matching extension logic exactly)
    let systemMessage = '';
    let userMessage = '';
    let model = 'gpt-4o-mini';
    let temperature = 0.35;
    let maxTokens = 250;

    if (mode === 'improve') {
      systemMessage = SYSTEM_PROMPT_IMPROVE;
      userMessage = original_prompt.trim();
      temperature = 0.35;
      maxTokens = 250;
    } else if (mode === 'refine') {
      systemMessage = SYSTEM_PROMPT_REFINE;
      userMessage = original_prompt.trim();
      temperature = 0.35;
      maxTokens = 250;
    } else if (mode === 'followup') {
      systemMessage = SYSTEM_PROMPT_FOLLOWUP;
      // Build context from previous messages (matching extension logic)
      if (previous_prompt && previous_prompt.trim()) {
        userMessage = `Previous user message: "${previous_prompt.trim()}"\n\nCurrent user input: "${original_prompt.trim()}"`;
      } else {
        userMessage = `Current user input: "${original_prompt.trim()}"`;
      }
      temperature = 0.35;
      maxTokens = 300;
    }

    // Call OpenAI API with exact parameters from extension
    let improvedPrompt = '';
    try {
      const completion = await openai.chat.completions.create({
        model: model,
        messages: [
          {
            role: 'system',
            content: systemMessage
          },
          {
            role: 'user',
            content: userMessage
          }
        ],
        max_tokens: maxTokens,
        temperature: temperature
      });

      improvedPrompt = completion.choices[0]?.message?.content || '';
      
      // Clean up the response - matching extension logic exactly
      improvedPrompt = improvedPrompt.trim();
      // Strip surrounding quotes if present (matching extension behavior)
      if ((improvedPrompt.startsWith('"') && improvedPrompt.endsWith('"')) ||
          (improvedPrompt.startsWith("'") && improvedPrompt.endsWith("'"))) {
        improvedPrompt = improvedPrompt.slice(1, -1);
      }
      // Remove markdown code blocks if present
      improvedPrompt = improvedPrompt.replace(/^```[\w]*\n?/g, '').replace(/\n?```$/g, '');
      improvedPrompt = improvedPrompt.trim();
      
      if (!improvedPrompt) {
        throw new Error('No improved prompt received from OpenAI');
      }
    } catch (openaiError) {
      console.error('OpenAI API error:', openaiError);
      return res.status(500).json({ error: `OpenAI API error: ${openaiError.message}` });
    }

    // Save prompt to database (only for authenticated users)
    if (!isAnonymous && authenticatedClient && userId) {
      try {
        await savePrompt({
          authenticatedClient,
          userId,
          inputText: original_prompt.trim(),
          outputText: improvedPrompt
        });
      } catch (saveError) {
        console.error('Error saving prompt:', saveError);
        // Continue even if save fails - credits are already deducted
      }
    }

    // Return improved prompt and remaining credits
    return res.json({
      success: true,
      output: improvedPrompt,
      creditsRemaining: remainingCredits
    });
  } catch (error) {
    // Invalid token or authentication error
    if (error.message.includes('token') || error.message.includes('Invalid')) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }

    // Other errors
    console.error(`Error ${mode} prompt:`, error);
    return res.status(500).json({ error: error.message });
  }
}

// Route handlers for each mode
app.post('/api/prompts/improve', (req, res) => handlePromptImprovement(req, res, 'improve'));
app.post('/api/prompts/refine', (req, res) => handlePromptImprovement(req, res, 'refine'));
app.post('/api/prompts/followup', (req, res) => handlePromptImprovement(req, res, 'followup'));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

