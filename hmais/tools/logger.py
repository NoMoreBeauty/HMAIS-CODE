
import os
import json
from datetime import datetime
from typing import Optional, Any, Dict

class HMAISLogger:
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if HMAISLogger._initialized:
            return
            
        self.log_dir = None
        self.log_files = {}
        self.iteration = 0
        HMAISLogger._initialized = True
    
    def init_session(self, base_dir: str = "."):

        self.log_dir = base_dir
        log_path = os.path.join(base_dir, "main.log")

        log_types = ["main", "planner", "query", "filter", "adversarial", "memory"]
        for log_type in log_types:
            self.log_files[log_type] = log_path

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"\n{'=' * 80}\n")
            f.write(f"HMAIS SESSION STARTED: {datetime.now().isoformat()}\n")
            f.write(f"{'=' * 80}\n\n")

        self._log("main", f"日志会话初始化完成，日志文件: {log_path}")
        return base_dir
    
    def set_iteration(self, iteration: int):
        self.iteration = iteration
        self._log("main", f"\n{'='*60}\n迭代 {iteration}\n{'='*60}")
    
    def _log(self, log_type: str, message: str):
        if not self.log_dir:
            return

        log_path = self.log_files.get(log_type)
        if not log_path:
            return

        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        prefix = f"[{timestamp}][{log_type.upper()}]"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{prefix} {message}\n")
    
    def log_main(self, message: str):
        self._log("main", message)
    
    def log_planner_input(self, context: str, feedback: Optional[str] = None):
        self._log("planner", f"\n{'='*60}")
        self._log("planner", f"[迭代 {self.iteration}] PLANNER INPUT")
        self._log("planner", f"{'='*60}")
        self._log("planner", f"\n--- Context (来自 Memory Agent) ---\n{context}")
        if feedback:
            self._log("planner", f"\n--- Feedback ---\n{feedback}")
    
    def log_planner_prompt(self, system_prompt: str, user_message: str):
        self._log("planner", f"\n--- System Prompt ---\n{system_prompt}")
        self._log("planner", f"\n--- User Message ---\n{user_message}")
    
    def log_planner_output(self, raw_response: str, parsed_plan: Dict[str, Any]):
        self._log("planner", f"\n--- LLM Raw Response ---\n{raw_response}")
        self._log("planner", f"\n--- Parsed Plan ---")
        self._log("planner", f"Phase: {parsed_plan.get('phase', 'N/A')}")
        self._log("planner", f"Thought: {parsed_plan.get('thought_process', 'N/A')}")
        self._log("planner", f"Action: {parsed_plan.get('next_action', 'N/A')}")
        self._log("planner", f"Stop: {parsed_plan.get('stop_investigation', False)}")
    
    def log_query_input(self, action: str):
        self._log("query", f"\n{'='*60}")
        self._log("query", f"[迭代 {self.iteration}] QUERY INPUT")
        self._log("query", f"{'='*60}")
        self._log("query", f"\n--- Action (来自 Planner) ---\n{action}")
    
    def log_query_prompt(self, query_type: str, system_prompt: str, user_message: str):
        self._log("query", f"\n--- {query_type} Query Generation ---")
        self._log("query", f"\n[System Prompt]\n{system_prompt}")
        self._log("query", f"\n[User Message]\n{user_message}")
    
    def log_query_llm_response(self, query_type: str, raw_response: str, cleaned_query: str):
        self._log("query", f"\n--- {query_type} LLM Response ---")
        self._log("query", f"\n[Raw Response]\n{raw_response}")
        self._log("query", f"\n[Cleaned Query]\n{cleaned_query}")
    
    def log_query_execution(self, query: str, result_count: int, success: bool, error: str = None):
        self._log("query", f"\n--- Query Execution ---")
        self._log("query", f"Query: {query}")
        self._log("query", f"Success: {success}")
        self._log("query", f"Result Count: {result_count}")
        if error:
            self._log("query", f"Error: {error}")
    
    def log_filter_input(self, event_count: int):
        self._log("filter", f"\n{'='*60}")
        self._log("filter", f"[迭代 {self.iteration}] FILTER INPUT")
        self._log("filter", f"{'='*60}")
        self._log("filter", f"收到 {event_count} 条事件")
    
    def log_filter_event(self, event_id: str, event_details: Dict[str, Any], suspicion_level: str):
        self._log("filter", f"\n--- Event: {event_id} ---")
        self._log("filter", f"Details: {json.dumps(event_details, ensure_ascii=False, indent=2)}")
        self._log("filter", f"Suspicion Level: {suspicion_level}")
    
    def log_filter_output(self, suspicious_count: int, total_count: int):
        self._log("filter", f"\n--- Filter Result ---")
        self._log("filter", f"可疑事件: {suspicious_count}/{total_count}")
    
    def log_adversarial_start(self, event_id: str, event_details: str):
        self._log("adversarial", f"\n{'='*60}")
        self._log("adversarial", f"[迭代 {self.iteration}] ADVERSARIAL DEBATE: {event_id}")
        self._log("adversarial", f"{'='*60}")
        self._log("adversarial", f"\n--- Event Details ---\n{event_details}")
    
    def log_adversarial_context(self, memory_context: str):
        self._log("adversarial", f"\n--- Memory Context ---\n{memory_context}")
    
    def log_prosecutor_prompt(self, system_prompt: str, user_message: str):
        self._log("adversarial", f"\n--- PROSECUTOR PROMPT ---")
        self._log("adversarial", f"\n[System Prompt]\n{system_prompt}")
        self._log("adversarial", f"\n[User Message]\n{user_message}")
    
    def log_prosecutor_response(self, response: str):
        self._log("adversarial", f"\n--- PROSECUTOR RESPONSE ---\n{response}")
    
    def log_defender_prompt(self, system_prompt: str, user_message: str):
        self._log("adversarial", f"\n--- DEFENDER PROMPT ---")
        self._log("adversarial", f"\n[System Prompt]\n{system_prompt}")
        self._log("adversarial", f"\n[User Message]\n{user_message}")
    
    def log_defender_response(self, response: str):
        self._log("adversarial", f"\n--- DEFENDER RESPONSE ---\n{response}")
    
    def log_judge_prompt(self, system_prompt: str, user_message: str):
        self._log("adversarial", f"\n--- JUDGE PROMPT ---")
        self._log("adversarial", f"\n[System Prompt]\n{system_prompt}")
        self._log("adversarial", f"\n[User Message]\n{user_message}")
    
    def log_judge_response(self, raw_response: str, judgement: Dict[str, Any]):
        self._log("adversarial", f"\n--- JUDGE RAW RESPONSE ---\n{raw_response}")
        self._log("adversarial", f"\n--- JUDGE VERDICT ---")
        self._log("adversarial", f"Is Malicious: {judgement.get('is_malicious', 'N/A')}")
        self._log("adversarial", f"Confidence: {judgement.get('confidence_score', 'N/A')}")
        self._log("adversarial", f"Reasoning: {judgement.get('reasoning', 'N/A')}")
        self._log("adversarial", f"MITRE: {judgement.get('mitre_technique', 'N/A')}")
    
    def log_memory_poi(self, poi_details: Dict[str, Any]):
        self._log("memory", f"\n{'='*60}")
        self._log("memory", f"POI REGISTERED")
        self._log("memory", f"{'='*60}")
        self._log("memory", f"\n{json.dumps(poi_details, ensure_ascii=False, indent=2)}")
    
    def log_memory_action(self, action: str, result: str):
        self._log("memory", f"\n--- Action Recorded ---")
        self._log("memory", f"Action: {action}")
        self._log("memory", f"Result: {result}")
    
    def log_memory_update(self, event_id: str, event_type: str, mitre: str, nodes: int, edges: int):
        self._log("memory", f"\n--- Malicious Event Added ---")
        self._log("memory", f"Event ID: {event_id}")
        self._log("memory", f"Event Type: {event_type}")
        self._log("memory", f"MITRE: {mitre}")
        self._log("memory", f"Graph: {nodes} nodes, {edges} edges")
    
    def log_memory_context(self, context: str):
        self._log("memory", f"\n--- Generated Context ---\n{context}")

    def log_memory_summary(self, attack_summary: str, ttp_chain: list):
        self._log("memory", f"\n{'='*60}")
        self._log("memory", f"[迭代 {self.iteration}] MEMORY STATE UPDATE")
        self._log("memory", f"{'='*60}")
        
        self._log("memory", f"\n--- 叙述性攻击摘要 ---")
        self._log("memory", attack_summary if attack_summary else "(空)")
        
        self._log("memory", f"\n--- MITRE TTP 链 ---")
        if ttp_chain:
            for i, ttp in enumerate(ttp_chain, 1):
                tactic = ttp.get("tactic", "Unknown")
                technique = ttp.get("technique", "?")
                name = ttp.get("name", "Unknown")
                event_desc = ttp.get("event_desc", "")
                self._log("memory", f"  {i}. [{tactic}] {technique} ({name}) - {event_desc}")
        else:
            self._log("memory", "  (空)")

    def log_citation_validation(self, agent_name: str, report: str):
        self._log("adversarial", f"\n--- {agent_name} Citation Validation ---")
        self._log("adversarial", report)
    
    def close(self):
        if self.log_dir:
            self._log("main", f"\n{'='*60}")
            self._log("main", f"调查结束: {datetime.now().isoformat()}")
            self._log("main", f"{'='*60}")

logger = HMAISLogger()
