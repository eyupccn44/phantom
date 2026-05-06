import json
import urllib.request
import urllib.error
from pathlib import Path

OLLAMA_BASE = "http://localhost:11434"
SYSTEM_PROMPT_PATH = Path(__file__).parent.parent / "prompts" / "system.txt"


def get_default_model() -> str:
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            models = data.get("models", [])
            if models:
                return models[0]["name"]
    except Exception:
        pass
    return "llama3"


def check_ollama() -> tuple[bool, str]:
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            models = data.get("models", [])
            if not models:
                return False, "Ollama çalışıyor ama kurulu model yok. 'ollama pull llama3' çalıştır."
            return True, models[0]["name"]
    except urllib.error.URLError:
        return False, "Ollama bağlantısı başarısız. 'ollama serve' ile Ollama'yı başlat."
    except Exception as e:
        return False, str(e)


def load_system_prompt() -> str:
    try:
        return SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "You are PHANTOM, a red team AI assistant."


class OllamaClient:
    def __init__(self, model: str | None = None):
        self.model = model or get_default_model()
        self.system_prompt = load_system_prompt()

    def chat(
        self,
        messages: list[dict],
        on_token=None,
        stream: bool = True,
    ) -> str:
        full_messages = [{"role": "system", "content": self.system_prompt}] + messages

        payload = json.dumps({
            "model": self.model,
            "messages": full_messages,
            "stream": stream,
            "options": {
                "temperature": 0.7,
                "num_ctx": 16384,
                "num_predict": 1500,
            }
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{OLLAMA_BASE}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        full_response = ""
        MAX_CHARS = 10000
        _repeated_chunk = 0

        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                if stream:
                    for line in resp:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line.decode("utf-8"))
                        except json.JSONDecodeError:
                            continue
                        token = chunk.get("message", {}).get("content", "")
                        full_response += token
                        if on_token and token:
                            on_token(token)

                        # Tekrar tespiti: aynı token 30+ kez üst üste
                        if len(token.strip()) > 0 and full_response.endswith(token * 5):
                            _repeated_chunk += 1
                        else:
                            _repeated_chunk = 0
                        if _repeated_chunk >= 6:
                            break

                        # Karakter limiti
                        if len(full_response) >= MAX_CHARS:
                            break

                        if chunk.get("done"):
                            break
                else:
                    data = json.loads(resp.read())
                    full_response = data.get("message", {}).get("content", "")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise ConnectionError(f"Ollama bağlantı/zaman aşımı: {e}")

        return full_response

    def analyze(self, context: str, on_token=None) -> str:
        messages = [{"role": "user", "content": context}]
        return self.chat(messages, on_token=on_token)
