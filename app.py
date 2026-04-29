# ====================================================================
# OnePost — /regenerate endpoint
# Add this to your existing main.py (or whichever file has /generate)
# on your Render backend (onepost-backend).
# ====================================================================

# This endpoint regenerates a single platform's caption with a
# variation hint, so each click produces meaningfully different output.

@app.post("/regenerate")
async def regenerate(
    platform: str = Form(...),
    platform_name: str = Form(...),
    previous_caption: str = Form(...),
    attempt: str = Form("1"),
    variation_hint: str = Form("different angle and hook"),
    content_type: str = Form(...),
    tone: str = Form(...),
    language: str = Form("english"),
    user_context: str = Form("")
):
    try:
        # Build a strong "give me something different" prompt
        lang_instruction = {
            "english": "in English",
            "hindi": "in Hindi (Devanagari script)",
            "both": "in both Hindi and English mixed naturally"
        }.get(language, "in English")

        ctx_part = f"\nAdditional context from user: {user_context}\n" if user_context else ""

        prompt = f"""You are generating a fresh caption for {platform_name} ONLY.

The user already received this caption and wants a DIFFERENT variation:
---
{previous_caption}
---

CRITICAL INSTRUCTIONS:
1. Generate a COMPLETELY NEW caption with a {variation_hint}.
2. Do NOT repeat phrases, hooks, or structure from the previous caption.
3. Match the platform's native tone and length conventions for {platform_name}.
4. Content type: {content_type}
5. Tone: {tone}
6. Language: {lang_instruction}
7. This is regeneration attempt #{attempt} — the user wants noticeably different output.{ctx_part}

Return ONLY the new caption text. No preamble, no explanation, no quotation marks."""

        # Call your existing AI client (Gemini / Claude / OpenAI — whichever you use)
        # Example using the same Gemini client your /generate endpoint uses:
        import google.generativeai as genai
        model = genai.GenerativeModel('gemini-2.0-flash-exp')  # or whichever model you're already using
        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 1.1,  # Higher temperature = more variation
                "top_p": 0.95,
                "max_output_tokens": 800
            }
        )

        new_caption = response.text.strip()

        # Strip any accidental quotation marks the model might add
        if new_caption.startswith('"') and new_caption.endswith('"'):
            new_caption = new_caption[1:-1].strip()
        if new_caption.startswith("'") and new_caption.endswith("'"):
            new_caption = new_caption[1:-1].strip()

        return {
            "success": True,
            "caption": new_caption,
            "platform": platform,
            "attempt": int(attempt)
        }

    except Exception as e:
        return {
            "success": False,
            "error": f"Regeneration failed: {str(e)}",
            "caption": ""
        }


# ====================================================================
# IMPORTANT: At the top of main.py, make sure you have this import:
#   from fastapi import Form
# ====================================================================
