# EasyPrompt Backend

## Setup Instructions

### 1. Install Dependencies

Run the following command in the project directory:

```bash
npm install
```

This will install:
- express
- @supabase/supabase-js
- cors
- openai
- dotenv

### 2. Environment Variables

Create a `.env` file in the project root with:

```
SUPABASE_URL=your_supabase_url
SUPABASE_ANON_KEY=your_supabase_anon_key
OPENAI_API_KEY=your_openai_api_key
PORT=3000
```

### 3. Start the Server

```bash
node server.js
```

The server will run on `http://localhost:3000` by default.

## Troubleshooting

### Server won't start

- Make sure all dependencies are installed: `npm install`
- Check that `.env` file exists with required variables
- Verify Node.js version is compatible (v14+)

### Login issues

- Open browser console (F12) to see error messages
- Check that Supabase credentials are correct
- Verify the backend server is running
- Check network tab for failed API requests

