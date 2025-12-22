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

// POST /api/prompts/improve
// POST /api/prompts/refine
// POST /api/prompts/followup
// Unified endpoint handler for all prompt improvement modes
async function handlePromptImprovement(req, res, mode) {
  try {
    const { token, original_prompt, previous_prompt } = req.body;

    // Validate required fields
    if (!token) {
      return res.status(401).json({ error: 'Missing access token' });
    }

    if (!original_prompt || !original_prompt.trim()) {
      return res.status(400).json({ error: 'original_prompt is required' });
    }

    // Validate mode
    const validModes = ['improve', 'refine', 'followup'];
    if (!validModes.includes(mode)) {
      return res.status(400).json({ error: 'Invalid mode. Must be: improve, refine, or followup' });
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

    // Enforce Pro-only access for follow-up mode
    if (mode === 'followup') {
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

    // Determine credit cost based on mode
    const creditCosts = {
      improve: 1,
      refine: 1,
      followup: 2
    };
    const creditCost = creditCosts[mode] || 1;

    // Check user's credits before processing
    let currentCredits;
    try {
      currentCredits = await getUserCredits({ authenticatedClient, userId });
    } catch (creditError) {
      console.error('Error checking credits:', creditError);
      return res.status(500).json({ error: 'Failed to check credits' });
    }

    // Check if user has sufficient credits
    if (currentCredits <= 0 || currentCredits < creditCost) {
      return res.status(402).json({ 
        error: 'No credits remaining',
        creditsRemaining: currentCredits
      });
    }

    // Deduct credits before processing (as per V1 requirements)
    let remainingCredits;
    try {
      console.log(`Attempting to deduct ${creditCost} credits for user ${userId} (mode: ${mode})`);
      remainingCredits = await deductCredits({
        authenticatedClient,
        userId,
        amount: creditCost,
        accessToken: token
      });
      console.log(`Credits deducted successfully. Remaining: ${remainingCredits}`);
    } catch (deductError) {
      console.error('Error deducting credits:', deductError);
      console.error('Error stack:', deductError.stack);
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

    const SYSTEM_PROMPT_REFINE_BUILD = `You are a professional prompt editor.

Using the original user input and the selected answers, assemble a single, high-quality AI prompt.

The final prompt must:
- Clearly define the role or perspective
- Specify the exact task to perform
- Integrate ALL selected answers explicitly
- Define the desired output format
- Include key constraints or quality guidelines
- State a clear success goal

Critical rules:
- Every selected answer must be reflected clearly in the final prompt.
- Do NOT omit, summarize away, or ignore any selected input.
- Do NOT repeat the questions themselves.
- Focus on framing the task, not executing it.
- Keep the prompt concise but complete.
- Do NOT add explanations or commentary.

Return ONLY the final prompt text.`;

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
      systemMessage = SYSTEM_PROMPT_REFINE_BUILD;
      // For refine, we need to handle the context similar to extension
      // The extension sends: original input + user answers
      // Since we're receiving original_prompt and potentially previous_prompt,
      // we'll treat previous_prompt as the answers/refinement context
      if (previous_prompt && previous_prompt.trim()) {
        userMessage = `Original input: "${original_prompt.trim()}"\n\nUser answers:\n${previous_prompt.trim()}`;
      } else {
        userMessage = `Original input: "${original_prompt.trim()}"\n\nUser answers:\nNo specific answers provided`;
      }
      temperature = 0.7;
      maxTokens = 500;
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

    // Save prompt to database
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

