import asyncio
import html
import os
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

import aiohttp
from dotenv import load_dotenv

from src.common.model_utils import analyze_full, analyze_text
from src.common.voice_utils import transcribe_audio

load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
SCAM_THRESHOLD = float(os.getenv("SCAM_THRESHOLD", "0.6"))
ALERT_CHAT_ID = os.getenv("ALERT_CHAT_ID")

if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN not found")

API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"
FILE_BASE = f"https://api.telegram.org/file/bot{BOT_TOKEN}"
BASE_DIR = Path(__file__).resolve().parent.parent.parent
SCAM_TEMPLATES_PATH = BASE_DIR / "data" / "scam_calls" / "scam.txt"
SAFE_TEMPLATES_PATH = BASE_DIR / "data" / "scam_calls" / "not_scam.txt"


def load_templates(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


SCAM_TEMPLATES = load_templates(SCAM_TEMPLATES_PATH)
SAFE_TEMPLATES = load_templates(SAFE_TEMPLATES_PATH)
BUSINESS_ALERT_CHAT_CACHE: dict[str, int] = {}


def boost_risk_with_rules(text: str, base_prob: float) -> float:
    text_lower = text.lower().strip()
    boosted = base_prob
    scam_similarity = max((SequenceMatcher(None, text_lower, t).ratio() for t in SCAM_TEMPLATES), default=0.0)
    safe_similarity = max((SequenceMatcher(None, text_lower, t).ratio() for t in SAFE_TEMPLATES), default=0.0)
    boosted += 0.35 * scam_similarity
    boosted -= 0.20 * safe_similarity
    return max(0.0, min(boosted, 1.0))


def is_dangerous(prob: float) -> bool:
    return prob >= SCAM_THRESHOLD


def format_alert_message(source_label: str, original_text: str, risk: float) -> str:
    quoted = html.escape((original_text or "").strip()) or "[пустое сообщение]"
    return (
        "⚠️ <b>Обнаружен риск мошенничества</b>\n"
        f"Источник: <b>{html.escape(source_label)}</b>\n"
        f"Риск: <b>{risk * 100:.1f}%</b>\n\n"
        "🧾 <b>Цитата сообщения:</b>\n"
        f"<i>{quoted}</i>"
    )




async def tg_api(session: aiohttp.ClientSession, method: str, payload: dict[str, Any]) -> dict[str, Any]:
    async with session.post(f"{API_BASE}/{method}", json=payload) as response:
        data = await response.json(content_type=None)
    if not data.get("ok"):
        raise RuntimeError(f"Telegram API {method} failed: {data}")
    return data["result"]


async def send_message(
    session: aiohttp.ClientSession,
    chat_id: int,
    text: str,
    business_connection_id: str | None = None,
    parse_mode: str | None = "HTML",
) -> None:
    payload: dict[str, Any] = {"chat_id": chat_id, "text": text}
    if parse_mode:
        payload["parse_mode"] = parse_mode
    if business_connection_id:
        payload["business_connection_id"] = business_connection_id
    await tg_api(session, "sendMessage", payload)


async def download_voice(session: aiohttp.ClientSession, file_id: str, prefix: str) -> str:
    file_info = await tg_api(session, "getFile", {"file_id": file_id})
    file_path = file_info["file_path"]
    extension = Path(file_path).suffix or ".ogg"
    output_path = f"{prefix}{extension}"
    async with session.get(f"{FILE_BASE}/{file_path}") as response:
        response.raise_for_status()
        content = await response.read()
    with open(output_path, "wb") as file:
        file.write(content)
    return output_path


async def resolve_alert_chat_id(session: aiohttp.ClientSession, business_connection_id: str) -> int | None:
    if ALERT_CHAT_ID:
        return int(ALERT_CHAT_ID)
    cached = BUSINESS_ALERT_CHAT_CACHE.get(business_connection_id)
    if cached:
        return cached
    result = await tg_api(session, "getBusinessConnection", {"business_connection_id": business_connection_id})
    owner_user_id = result.get("user", {}).get("id")
    if owner_user_id:
        BUSINESS_ALERT_CHAT_CACHE[business_connection_id] = owner_user_id
        return owner_user_id
    return None


async def process_text(text: str) -> float:
    prob = analyze_text(text)
    return boost_risk_with_rules(text, prob)


async def process_voice(
    session: aiohttp.ClientSession,
    file_id: str,
    local_prefix: str,
) -> tuple[str, float, float, float]:
    local_path = await download_voice(session, file_id, local_prefix)
    try:
        text = transcribe_audio(local_path)
        try:
            final_prob, text_prob, audio_prob = analyze_full(text, local_path)
        except Exception as exc:
            print(f"Audio model failed, fallback to text-only: {exc}")
            text_prob = analyze_text(text)
            audio_prob = text_prob
            final_prob = text_prob
        text_prob = boost_risk_with_rules(text, text_prob)
        final_prob = (text_prob + audio_prob) / 2
        return text, final_prob, text_prob, audio_prob
    finally:
        if os.path.exists(local_path):
            os.remove(local_path)


async def handle_private_bot_chat(session: aiohttp.ClientSession, message: dict[str, Any]) -> None:
    chat_id = message["chat"]["id"]
    text = (message.get("text") or "").strip()
    if text == "/start":
        await send_message(
            session,
            chat_id,
            "🛡 VoiceShield подключен.\nБот отслеживает сообщения в Telegram Business и присылает сюда только опасные кейсы.",
        )


async def handle_business_update(session: aiohttp.ClientSession, business_message: dict[str, Any]) -> None:
    source_chat_id = business_message.get("chat", {}).get("id")
    source_title = business_message.get("chat", {}).get("title")
    business_connection_id = business_message.get("business_connection_id")
    if not source_chat_id or not business_connection_id:
        return
    alert_chat_id = await resolve_alert_chat_id(session, business_connection_id)
    if not alert_chat_id:
        print("Cannot resolve alert chat id for business connection")
        return
    source_label = source_title or f"chat_id={source_chat_id}"
    text = business_message.get("text")
    if text:
        risk = await process_text(text)
        if is_dangerous(risk):
            alert = format_alert_message(source_label, text, risk)
            await send_message(session, alert_chat_id, alert)
        return
    voice = business_message.get("voice") or business_message.get("audio")
    if voice and voice.get("file_id"):
        try:
            transcript, final_prob, text_prob, audio_prob = await process_voice(
                session,
                voice["file_id"],
                "temp_business_voice",
            )
        except Exception as exc:
            print(f"Voice processing failed: {exc}")
            await send_message(
                session,
                alert_chat_id,
                "❌ Не удалось обработать голосовое сообщение. Проверьте установку ffmpeg и доступность аудиокодеков.",
            )
            return
        if is_dangerous(final_prob):
            alert = (
                format_alert_message(source_label, transcript, final_prob)
                + "\n\n"
                + f"📊 Текст: {text_prob * 100:.1f}%\n"
                + f"🎙 Аудио: {audio_prob * 100:.1f}%"
            )
            await send_message(session, alert_chat_id, alert)


async def handle_update(session: aiohttp.ClientSession, update: dict[str, Any]) -> None:
    message = update.get("message")
    if message and message.get("chat", {}).get("type") == "private":
        await handle_private_bot_chat(session, message)
    business_message = update.get("business_message") or update.get("edited_business_message")
    if business_message:
        await handle_business_update(session, business_message)


async def polling_loop() -> None:
    offset = 0
    allowed_updates = ["message", "business_message", "edited_business_message"]
    print("Bot started...")
    print(f"Scam threshold: {SCAM_THRESHOLD}")
    print(f"Scam templates loaded: {len(SCAM_TEMPLATES)}")
    print(f"Safe templates loaded: {len(SAFE_TEMPLATES)}")
    timeout = aiohttp.ClientTimeout(total=90)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while True:
            try:
                updates = await tg_api(
                    session,
                    "getUpdates",
                    {
                        "offset": offset,
                        "timeout": 60,
                        "allowed_updates": allowed_updates,
                    },
                )
                for item in updates:
                    offset = item["update_id"] + 1
                    await handle_update(session, item)
            except Exception as exc:
                print(f"Polling error: {exc}")
                await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(polling_loop())
