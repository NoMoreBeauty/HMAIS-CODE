import os


try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

MAX_QUERY_RESULT = 50    # count-first 安全上限 (θ_max)
MAX_RETRIES = 3          # 查询失败最大重试次数
CONFIDENCE_THRESHOLD = 0.75

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "dashscope")
FORMATTER_KEYS = os.environ.get("FORMATTER_KEYS", "")
DASHSCOPE_API_KEY = os.environ.get("DASHSCOPE_API_KEY", "")

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

LLM_API_KEY = DASHSCOPE_API_KEY if LLM_PROVIDER == "dashscope" else OPENROUTER_API_KEY

LLM_MODEL = os.environ.get("LLM_MODEL", "qwen-plus")

LLM_CODER_MODEL = os.environ.get("LLM_CODER_MODEL", "deepseek-r1")

LLM_TEMPERATURE = 0.7
LLM_CODER_TEMPERATURE = 0.1
LLM_MAX_TOKENS = 2000

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")
NEO4J_DATABASE = "neo4j"
