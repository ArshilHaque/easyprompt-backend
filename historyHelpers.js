/**
 * Saves prompt history to the database using an authenticated Supabase client
 * @param {Object} params - Parameters object
 * @param {Object} params.authenticatedClient - Authenticated Supabase client with user's access token
 * @param {string} params.userId - The user's ID (from auth.uid, not from client input)
 * @param {string} params.type - The type of prompt (e.g., 'enhance', 'shorten', etc.)
 * @param {string} params.originalInput - The original user input
 * @param {string} params.finalPrompt - The final processed prompt
 * @returns {Promise<void>}
 */
export async function savePromptHistory({ authenticatedClient, userId, type, originalInput, finalPrompt }) {
  if (!authenticatedClient) {
    throw new Error('Authenticated Supabase client is required');
  }

  if (!userId) {
    throw new Error('User ID is required');
  }

  if (!type || !originalInput || !finalPrompt) {
    throw new Error('Type, originalInput, and finalPrompt are required');
  }

  const { error } = await authenticatedClient
    .from('prompt_history')
    .insert({
      user_id: userId,
      type,
      original_input: originalInput,
      final_prompt: finalPrompt,
      created_at: new Date().toISOString()
    });

  if (error) {
    throw new Error(`Failed to save prompt history: ${error.message}`);
  }
}

/**
 * Gets prompt history for a user
 * @param {string} userId - The user's ID (from auth.uid, not from client input)
 * @param {number} limit - Maximum number of records to return (default: 20)
 * @returns {Promise<Array>} Array of prompt history records
 */
export async function getPromptHistory(userId, limit = 20) {
  if (!userId) {
    throw new Error('User ID is required');
  }

  const { data, error } = await supabase
    .from('prompt_history')
    .select('*')
    .eq('user_id', userId)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) {
    throw new Error(`Failed to get prompt history: ${error.message}`);
  }

  return data || [];
}

/**
 * Saves a prompt to the prompts table using an authenticated Supabase client
 * @param {Object} params - Parameters object
 * @param {Object} params.authenticatedClient - Authenticated Supabase client with user's access token
 * @param {string} params.userId - The user's ID (from auth.uid, not from client input)
 * @param {string} params.inputText - The input prompt text
 * @param {string} params.outputText - The generated output text
 * @returns {Promise<void>}
 */
export async function savePrompt({ authenticatedClient, userId, inputText, outputText }) {
  if (!authenticatedClient) {
    throw new Error('Authenticated Supabase client is required');
  }

  if (!userId) {
    throw new Error('User ID is required');
  }

  if (!inputText) {
    throw new Error('Input text is required');
  }

  const { error } = await authenticatedClient
    .from('prompts')
    .insert({
      user_id: userId,
      input_text: inputText,
      output_text: outputText || null,
      created_at: new Date().toISOString()
    });

  if (error) {
    throw new Error(`Failed to save prompt: ${error.message}`);
  }
}

