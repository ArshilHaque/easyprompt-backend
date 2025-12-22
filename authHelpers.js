import { supabase } from './supabaseClient.js';

/**
 * Validates a Supabase JWT and returns user information
 * @param {string} accessToken - The Supabase JWT access token
 * @returns {Promise<{id: string, email: string}>} User id and email
 * @throws {Error} If token is invalid or user cannot be retrieved
 */
export async function getUserFromToken(accessToken) {
  if (!accessToken) {
    throw new Error('Access token is required');
  }

  // Verify the JWT and get the user
  const { data: { user }, error } = await supabase.auth.getUser(accessToken);

  if (error) {
    throw new Error(`Invalid token: ${error.message}`);
  }

  if (!user) {
    throw new Error('User not found');
  }

  return {
    id: user.id,
    email: user.email
  };
}

/**
 * Verifies a Supabase JWT and returns user information
 * @param {string} token - The Supabase JWT access token
 * @returns {Promise<{userId: string, email: string}>} User id and email
 * @throws {Error} If token is invalid or expired
 */
export async function verifyUserFromToken(token) {
  if (!token) {
    throw new Error('Invalid or expired token');
  }

  const { data: { user }, error } = await supabase.auth.getUser(token);

  if (error || !user) {
    throw new Error('Invalid or expired token');
  }

  return {
    userId: user.id,
    email: user.email
  };
}

