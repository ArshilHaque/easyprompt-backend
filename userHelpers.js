import { supabase } from './supabaseClient.js';

/**
 * Gets the user's plan from the users table
 * @param {string} userId - The user's ID (from auth.uid)
 * @returns {Promise<string>} The user's plan, defaults to "free" if missing
 */
export async function getUserPlan(userId) {
  if (!userId) {
    throw new Error('User ID is required');
  }

  const { data, error } = await supabase
    .from('users')
    .select('plan')
    .eq('id', userId)
    .single();

  if (error) {
    // If user doesn't exist, return default plan
    if (error.code === 'PGRST116') {
      return 'free';
    }
    throw new Error(`Failed to get user plan: ${error.message}`);
  }

  return data?.plan || 'free';
}

/**
 * Ensures a user exists in the users table
 * Creates the user if they don't exist
 * @param {Object} user - User object with id and email
 * @param {string} user.id - The user's ID (from auth.uid)
 * @param {string} user.email - The user's email
 * @returns {Promise<void>}
 */
export async function ensureUserExists(user) {
  if (!user || !user.id) {
    throw new Error('User object with id is required');
  }

  // Check if user exists
  const { data: existingUser, error: selectError } = await supabase
    .from('users')
    .select('id')
    .eq('id', user.id)
    .single();

  // If user exists, return early
  if (existingUser) {
    return;
  }

  // If user doesn't exist, create them
  // Note: This will fail if RLS prevents inserts, which is expected
  const { error: insertError } = await supabase
    .from('users')
    .insert({
      id: user.id,
      email: user.email,
      plan: 'free'
    });

  if (insertError) {
    // If it's a duplicate key error, user was created between check and insert
    if (insertError.code === '23505') {
      return;
    }
    throw new Error(`Failed to create user: ${insertError.message}`);
  }
}

/**
 * Checks if a user has Pro access using an authenticated Supabase client
 * @param {Object} params - Parameters object
 * @param {Object} params.authenticatedClient - Authenticated Supabase client with user's access token
 * @param {string} params.userId - The user's ID (from auth.uid, not from client input)
 * @returns {Promise<boolean>} True if user has Pro access, false otherwise
 */
export async function getUserProStatus({ authenticatedClient, userId }) {
  if (!authenticatedClient) {
    throw new Error('Authenticated Supabase client is required');
  }

  if (!userId) {
    throw new Error('User ID is required');
  }

  const { data, error } = await authenticatedClient
    .from('users')
    .select('is_pro')
    .eq('id', userId)
    .single();

  if (error) {
    // If user doesn't exist, return false (not Pro)
    if (error.code === 'PGRST116') {
      return false;
    }
    throw new Error(`Failed to get user Pro status: ${error.message}`);
  }

  return data?.is_pro === true;
}

/**
 * Gets the user's current credits using an authenticated Supabase client
 * @param {Object} params - Parameters object
 * @param {Object} params.authenticatedClient - Authenticated Supabase client with user's access token
 * @param {string} params.userId - The user's ID (from auth.uid, not from client input)
 * @returns {Promise<number>} Current credits count
 */
export async function getUserCredits({ authenticatedClient, userId }) {
  if (!authenticatedClient) {
    throw new Error('Authenticated Supabase client is required');
  }

  if (!userId) {
    throw new Error('User ID is required');
  }

  const { data, error } = await authenticatedClient
    .from('users')
    .select('credits')
    .eq('id', userId)
    .single();

  if (error) {
    // If user doesn't exist, return 0 credits
    if (error.code === 'PGRST116') {
      return 0;
    }
    throw new Error(`Failed to get user credits: ${error.message}`);
  }

  // Return credits, defaulting to 0 if null or undefined
  return data?.credits ?? 0;
}

/**
 * Deducts credits from a user's account using an authenticated Supabase client
 * @param {Object} params - Parameters object
 * @param {Object} params.authenticatedClient - Authenticated Supabase client with user's access token
 * @param {string} params.userId - The user's ID (from auth.uid, not from client input)
 * @param {number} params.amount - Amount of credits to deduct (must be positive)
 * @returns {Promise<number>} Remaining credits after deduction
 */
export async function deductCredits({ authenticatedClient, userId, amount, accessToken }) {
  if (!authenticatedClient) {
    throw new Error('Authenticated Supabase client is required');
  }

  if (!userId) {
    throw new Error('User ID is required');
  }

  if (!amount || amount <= 0) {
    throw new Error('Deduction amount must be positive');
  }

  // Get current credits first
  const currentCredits = await getUserCredits({ authenticatedClient, userId });

  if (currentCredits < amount) {
    throw new Error('Insufficient credits');
  }

  // Set session explicitly to ensure RLS recognizes the user for UPDATE operations
  if (accessToken) {
    try {
      await authenticatedClient.auth.setSession({
        access_token: accessToken,
        refresh_token: ''
      });
    } catch (sessionError) {
      console.warn('Could not set session (may already be set):', sessionError.message);
      // Continue - session might already be set via headers
    }
  }

  // Deduct credits using atomic update
  const newCredits = currentCredits - amount;
  console.log(`Deducting ${amount} credits from user ${userId}. Current: ${currentCredits}, New: ${newCredits}`);
  
  // Use RPC call or direct update - try update first
  const { data, error } = await authenticatedClient
    .from('users')
    .update({ credits: newCredits })
    .eq('id', userId)
    .select('credits')
    .single();

  if (error) {
    console.error('Credit deduction error details:', {
      error: error.message,
      code: error.code,
      details: error.details,
      hint: error.hint,
      userId: userId
    });
    
    // If RLS is blocking, try using a different approach
    if (error.code === '42501' || error.message.includes('permission') || error.message.includes('policy')) {
      throw new Error(`RLS policy blocked credit update: ${error.message}. Please ensure users can update their own credits.`);
    }
    
    throw new Error(`Failed to deduct credits: ${error.message}`);
  }

  if (!data) {
    console.error('Credit deduction returned no data');
    throw new Error('Failed to deduct credits: No data returned');
  }

  console.log(`Credits successfully deducted. Remaining: ${data.credits}`);
  return data.credits ?? 0;
}

