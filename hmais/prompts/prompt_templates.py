
import os
from pathlib import Path

PROMPTS_DIR = Path(__file__).parent

def _load_prompt(filename: str) -> str:
    filepath = PROMPTS_DIR / filename
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()

class PlannerPrompts:
    
    @property
    def SYSTEM_PROMPT(self) -> str:
        return _load_prompt("planner_system.txt")
    
    @property
    def USER_TEMPLATE(self) -> str:
        return _load_prompt("planner_user.txt")
    
    FEEDBACK_TEMPLATE = """反馈信息：
{feedback}

请根据此反馈调整调查策略。"""

class QueryPrompts:
    
    @property
    def SYSTEM_PROMPT(self) -> str:
        return _load_prompt("query_system.txt")
    
    @property
    def USER_TEMPLATE_COUNT(self) -> str:
        return _load_prompt("query_user_count.txt")
    
    @property
    def USER_TEMPLATE_FETCH(self) -> str:
        return _load_prompt("query_user_fetch.txt")

class AdversarialPrompts:
    
    @property
    def PROSECUTOR_SYSTEM(self) -> str:
        return _load_prompt("adversarial_prosecutor.txt")
    
    @property
    def DEFENDER_SYSTEM(self) -> str:
        return _load_prompt("adversarial_defender.txt")
    
    @property
    def JUDGE_SYSTEM(self) -> str:
        return _load_prompt("adversarial_judge.txt")
    
    @property
    def USER_TEMPLATE(self) -> str:
        return _load_prompt("adversarial_user.txt")

class MemoryPrompts:
    @property
    def MITRE_SYSTEM_PROMPT(self) -> str:
        return _load_prompt("mitre_system.txt")
        
    @property
    def MITRE_USER_TEMPLATE(self) -> str:
        return _load_prompt("mitre_user.txt")

PlannerPrompts = PlannerPrompts()
QueryPrompts = QueryPrompts()
AdversarialPrompts = AdversarialPrompts()
MemoryPrompts = MemoryPrompts()
