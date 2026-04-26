# onepost-backend

## Setup (local)

1. Create a `.env` file:

   - Copy `.env.example` to `.env`
   - Set `DEEPGRAM_KEY` to your Deepgram API key

2. Install dependencies:

   - `pip install -r requirements.txt`

3. Run:

   - `python app.py`

Server runs on port `5000`.

## API

### `POST /transcribe`

Upload `multipart/form-data` with field name `file` (audio/video).

Response:

- `transcript`: extracted transcript string (or `null` if not found)
- `deepgram`: full Deepgram JSON response

