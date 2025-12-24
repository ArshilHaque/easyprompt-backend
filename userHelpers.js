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

  // If user doesn't exist, create them with initial values
  // Note: This will fail if RLS prevents inserts, which is expected
  const now = new Date();
  const nextReset = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours from now
  
  const { error: insertError } = await supabase
    .from('users')
    .insert({
      id: user.id,
      email: user.email,
      plan: 'free',
      credits: 0, // Signup bonus will be granted on first login via /api/me
      daily_credits_used: 0,
      daily_reset_at: nextReset.toISOString(),
      signup_bonus_given: false
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

/**
 * Gets user's credit information including daily credits and signup bonus
 * @param {Object} params - Parameters object
 * @param {Object} params.authenticatedClient - Authenticated Supabase client
 * @param {string} params.userId - The user's ID
 * @returns {Promise<Object>} Credit information object
 */
export async function getUserCreditInfo({ authenticatedClient, userId }) {
  if (!authenticatedClient) {
    throw new Error('Authenticated Supabase client is required');
  }

  if (!userId) {
    throw new Error('User ID is required');
  }

  const { data, error } = await authenticatedClient
    .from('users')
    .select('credits, daily_credits_used, daily_reset_at, signup_bonus_given')
    .eq('id', userId)
    .single();

  if (error) {
    if (error.code === 'PGRST116') {
      // User doesn't exist, return defaults
      return {
        credits: 0,
        dailyCreditsUsed: 0,
        dailyResetAt: null,
        signupBonusGiven: false
      };
    }
    throw new Error(`Failed to get user credit info: ${error.message}`);
  }

  return {
    credits: data?.credits ?? 0,
    dailyCreditsUsed: data?.daily_credits_used ?? 0,
    dailyResetAt: data?.daily_reset_at ? new Date(data.daily_reset_at) : null,
    signupBonusGiven: data?.signup_bonus_given ?? false
  };
}

/**
 * Resets daily credits if 24 hours have passed
 * @param {Object} params - Parameters object
 * @param {Object} params.authenticatedClient - Authenticated Supabase client
 * @param {string} params.userId - The user's ID
 * @returns {Promise<boolean>} True if reset occurred, false otherwise
 */
export async function resetDailyCreditsIfNeeded({ authenticatedClient, userId }) {
  if (!authenticatedClient) {
    throw new Error('Authenticated Supabase client is required');
  }

  if (!userId) {
    throw new Error('User ID is required');
  }

  const creditInfo = await getUserCreditInfo({ authenticatedClient, userId });
  const now = new Date();
  const resetAt = creditInfo.dailyResetAt ? new Date(creditInfo.dailyResetAt) : null;

  // If daily_reset_at is missing OR 24 hours have passed, reset daily credits
  if (!resetAt || now >= resetAt) {
    const nextReset = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours from now
    
    const { error } = await authenticatedClient
      .from('users')
      .update({
        daily_credits_used: 0,
        daily_reset_at: nextReset.toISOString()
      })
      .eq('id', userId);

    if (error) {
      throw new Error(`Failed to reset daily credits: ${error.message}`);
    }

    console.log(`[CREDITS] Daily credits reset for user ${userId}. Next reset: ${nextReset.toISOString()}`);
    return true;
  }

  return false;
}

/**
 * Deducts credits for Free users (daily credits first, then bonus credits)
 * @param {Object} params - Parameters object
 * @param {Object} params.authenticatedClient - Authenticated Supabase client
 * @param {string} params.userId - The user's ID
 * @param {number} params.amount - Amount to deduct
 * @param {string} params.accessToken - Access token for session
 * @returns {Promise<Object>} Result with remaining credits and source used
 */
export async function deductFreeUserCredits({ authenticatedClient, userId, amount, accessToken }) {
  if (!authenticatedClient) {
    throw new Error('Authenticated Supabase client is required');
  }

  if (!userId) {
    throw new Error('User ID is required');
  }

  if (!amount || amount <= 0) {
    throw new Error('Deduction amount must be positive');
  }

  // Set session explicitly
  if (accessToken) {
    try {
      await authenticatedClient.auth.setSession({
        access_token: accessToken,
        refresh_token: ''
      });
    } catch (sessionError) {
      console.warn('Could not set session (may already be set):', sessionError.message);
    }
  }

  // Reset daily credits if needed
  await resetDailyCreditsIfNeeded({ authenticatedClient, userId });

  // Get current credit info
  const creditInfo = await getUserCreditInfo({ authenticatedClient, userId });
  const DAILY_CREDITS = 3;
  const dailyCreditsAvailable = DAILY_CREDITS - creditInfo.dailyCreditsUsed;
  const bonusCredits = creditInfo.credits; // Bonus credits stored in credits field

  // Check if user has enough credits
  const totalAvailable = dailyCreditsAvailable + bonusCredits;
  if (totalAvailable < amount) {
    throw new Error('Insufficient credits');
  }

  // Deduct from daily credits first, then from bonus credits
  let newDailyCreditsUsed = creditInfo.dailyCreditsUsed;
  let newBonusCredits = bonusCredits;
  let creditSource = '';

  if (dailyCreditsAvailable >= amount) {
    // Use daily credits only
    newDailyCreditsUsed = creditInfo.dailyCreditsUsed + amount;
    creditSource = 'daily';
    console.log(`[CREDITS] Deducted ${amount} from daily credits for user ${userId}. Source: daily`);
  } else {
    // Use all available daily credits + some bonus credits
    const bonusNeeded = amount - dailyCreditsAvailable;
    newDailyCreditsUsed = DAILY_CREDITS; // All daily credits used
    newBonusCredits = bonusCredits - bonusNeeded;
    creditSource = 'mixed';
    console.log(`[CREDITS] Deducted ${dailyCreditsAvailable} from daily + ${bonusNeeded} from bonus for user ${userId}. Source: mixed`);
  }

  // Update database
  const { data, error } = await authenticatedClient
    .from('users')
    .update({
      daily_credits_used: newDailyCreditsUsed,
      credits: newBonusCredits
    })
    .eq('id', userId)
    .select('credits, daily_credits_used')
    .single();

  if (error) {
    throw new Error(`Failed to deduct credits: ${error.message}`);
  }

  const remainingCredits = newBonusCredits;
  console.log(`[CREDITS] Credits deducted successfully. User ${userId} remaining: ${remainingCredits} bonus credits, ${DAILY_CREDITS - newDailyCreditsUsed} daily credits. Source: ${creditSource}`);

  return {
    remainingCredits,
    dailyCreditsRemaining: DAILY_CREDITS - newDailyCreditsUsed,
    creditSource
  };
}

/**
 * Grants signup bonus to a user (10 credits, one-time only)
 * @param {Object} params - Parameters object
 * @param {Object} params.authenticatedClient - Authenticated Supabase client
 * @param {string} params.userId - The user's ID
 * @returns {Promise<void>}
 */
export async function grantSignupBonus({ authenticatedClient, userId }) {
  if (!authenticatedClient) {
    throw new Error('Authenticated Supabase client is required');
  }

  if (!userId) {
    throw new Error('User ID is required');
  }

  const creditInfo = await getUserCreditInfo({ authenticatedClient, userId });

  // Only grant if not already given
  if (creditInfo.signupBonusGiven) {
    console.log(`[CREDITS] Signup bonus already granted to user ${userId}`);
    return;
  }

  const SIGNUP_BONUS = 10;
  const newCredits = creditInfo.credits + SIGNUP_BONUS;

  const { error } = await authenticatedClient
    .from('users')
    .update({
      credits: newCredits,
      signup_bonus_given: true
    })
    .eq('id', userId);

  if (error) {
    throw new Error(`Failed to grant signup bonus: ${error.message}`);
  }

  console.log(`[CREDITS] Signup bonus granted: +${SIGNUP_BONUS} credits to user ${userId}. Total: ${newCredits}`);
}

