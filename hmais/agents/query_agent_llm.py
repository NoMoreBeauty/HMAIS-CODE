
from typing import Optional, List
from rich.console import Console
from hmais.models.data_models import QueryResult
from hmais.tools.llm_client import LLMClient
from hmais.prompts.prompt_templates import QueryPrompts
from hmais.tools.logger import logger
import config

console = Console()

class QueryAgentLLM:

    def __init__(self, db):
        self.db = db
        self.llm = LLMClient(model=config.LLM_CODER_MODEL, temperature=config.LLM_CODER_TEMPERATURE)

    def execute(self, action: str) -> QueryResult:
        print(f"\n🔍 Query Agent: {action}")
        
        logger.log_query_input(action)

        count_query = self._generate_count_query_with_repair(action)
        if count_query is None:
            return QueryResult(success=False, error="COUNT 查询在重试后仍然失败")

        print(f"  → {count_query}")

        try:
            count = self.db.execute_count_query(count_query)
            if not isinstance(count, int):
                error = f"查询应返回 count 但返回了 {type(count).__name__}"
                logger.log_query_execution(count_query, 0, False, error)
                return QueryResult(success=False, error=error)
            print(f"  ✓ Count: {count}")
            logger.log_query_execution(count_query, count, True)
        except Exception as e:
            logger.log_query_execution(count_query, 0, False, str(e))
            return QueryResult(success=False, error=f"COUNT 查询执行失败: {str(e)}")

        if count > config.MAX_QUERY_RESULT:
            return QueryResult(success=False, count=count, error=f"结果过多: {count}")
        elif count == 0:
            return QueryResult(success=True, count=0, data=[])

        fetch_query = self._generate_fetch_query_with_repair(action)
        if fetch_query is None:
            return QueryResult(success=False, error="FETCH 查询在重试后仍然失败")

        try:
            data = self.db.execute_fetch_query(fetch_query)
            print(f"  ✓ 获取 {len(data)} 条事件")
            logger.log_query_execution(fetch_query, len(data), True)
            return QueryResult(success=True, count=count, data=data)
        except Exception as e:
            logger.log_query_execution(fetch_query, 0, False, str(e))
            return QueryResult(success=False, error=f"FETCH 查询执行失败: {str(e)}")

    def _generate_count_query_with_repair(self, action: str) -> Optional[str]:
        error_history: List[dict] = []
        
        for attempt in range(config.MAX_RETRIES + 1):
            query, raw_response = self._generate_query_llm(action, "COUNT", error_history)
            if query.startswith("Error:"):
                return None

            is_valid_local, error_msg_local = self._validate_cypher_syntax(query)
            if not is_valid_local:
                print(f"❌ 本地验证失败 (尝试 {attempt+1}): {error_msg_local}")
                logger.log_query_execution(query, 0, False, error_msg_local)
                error_history.append({"query": query, "error": error_msg_local})
                if attempt < config.MAX_RETRIES:
                    print(f"⚠️ 反馈错误给 LLM 进行修复 ({attempt+1}/{config.MAX_RETRIES})...")
                continue

            is_valid, error_msg = self.db.validate_cypher(query)
            if not is_valid:
                print(f"❌ 数据库验证失败 (尝试 {attempt+1}): {error_msg}")
                logger.log_query_execution(query, 0, False, error_msg)
                error_history.append({"query": query, "error": error_msg})
                if attempt < config.MAX_RETRIES:
                    print(f"⚠️ 反馈错误给 LLM 进行修复 ({attempt+1}/{config.MAX_RETRIES})...")
                continue
            
            return query
        
        return None

    def _generate_fetch_query_with_repair(self, action: str) -> Optional[str]:
        error_history: List[dict] = []
        
        for attempt in range(config.MAX_RETRIES + 1):
            query, raw_response = self._generate_query_llm(action, "FETCH", error_history)
            if query.startswith("Error:"):
                return None

            is_valid, error_msg = self._validate_cypher_syntax(query)
            if not is_valid:
                print(f"❌ Fetch 语法验证失败 (尝试 {attempt+1}): {error_msg}")
                logger.log_query_execution(query, 0, False, error_msg)
                error_history.append({"query": query, "error": error_msg})
                if attempt < config.MAX_RETRIES:
                    print(f"⚠️ 反馈错误给 LLM 进行修复 ({attempt+1}/{config.MAX_RETRIES})...")
                continue
            
            return query
        
        return None

    def _generate_query_llm(self, action: str, query_type: str, 
                            error_history: List[dict] = None) -> tuple[str, str]:
        if query_type == "COUNT":
            user_message = QueryPrompts.USER_TEMPLATE_COUNT.format(action=action)
        else:
            user_message = QueryPrompts.USER_TEMPLATE_FETCH.format(action=action)
        
        if error_history:
            correction_context = "\n\n⚠️ 之前的查询出错，请修复：\n"
            for i, entry in enumerate(error_history, 1):
                correction_context += f"  尝试 {i}:\n"
                correction_context += f"    查询: {entry['query']}\n"
                correction_context += f"    错误: {entry['error']}\n"
            correction_context += "\n请根据以上错误信息生成修正后的查询。"
            user_message += correction_context
        
        logger.log_query_prompt(query_type, QueryPrompts.SYSTEM_PROMPT, user_message)

        try:
            raw_query = self.llm.call(
                system_prompt=QueryPrompts.SYSTEM_PROMPT,
                user_message=user_message
            )
            query = self._clean_cypher(raw_query)
            
            logger.log_query_llm_response(query_type, raw_query, query)
            
            return query, raw_query

        except Exception as e:
            return f"Error: 生成 {query_type} 查询失败: {str(e)}", ""

    def _clean_cypher(self, query: str) -> str:
        if "```cypher" in query:
            start = query.find("```cypher") + 9
            end = query.find("```", start)
            if end != -1:
                query = query[start:end]
        elif "```" in query:
            start = query.find("```") + 3
            end = query.find("```", start)
            if end != -1:
                query = query[start:end]
        query = " ".join(query.split())
        return query.strip()

    def _validate_cypher_syntax(self, query: str) -> tuple[bool, str]:
        import re
        query_lower = query.lower()

        if "-->" in query or "<--" in query:
            return False, f"禁止使用 --> 或 <--，必须使用 -[r]-> 或 -[r:TYPE]->"

        used_vars = set(re.findall(r'\b(r\d*)\s*[.,\s]', query_lower))

        return_match = re.search(r'return\s+(.+?)(?:\s+limit|\s*$)', query_lower, re.IGNORECASE)
        if return_match:
            return_vars = re.findall(r'\b(r\d*)\b', return_match.group(1))
            used_vars.update(return_vars)
        
        defined_vars = set(re.findall(r'\-\[(r\d*)(?::[A-Z_]+)?\]\-\>', query, re.IGNORECASE))
        
        undefined = used_vars - defined_vars
        if undefined:
            return False, f"使用了未定义的关系变量: {undefined}"

        invalid_types = ["SPAWN", "CREATE", "CONNECT", "OPEN", "CLOSE", "START", "STOP"]
        for inv_type in invalid_types:
            if f"[r:{inv_type}]" in query.upper() or f"[:{inv_type}]" in query.upper():
                return False, f"使用了不存在的关系类型 {inv_type}"

            if re.search(rf'\[r\d*:{inv_type}\]', query, re.IGNORECASE):
                return False, f"使用了不存在的关系类型 {inv_type}"

        if "->>" in query:
            return False, f"禁止使用 PostgreSQL JSON 语法 ->>"

        return True, ""
