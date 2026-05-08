
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from hmais.models.data_models import Event, Judgement
from hmais.tools.llm_client import LLMClient
from hmais.prompts.prompt_templates import AdversarialPrompts
from hmais.tools.logger import logger
from hmais.tools.rag_retriever import RAGRetriever
from hmais.tools.citation_validator import CitationValidator
import config

console = Console()

class AdversarialGroupLLM:

    def __init__(self):
        self.prosecutor = ProsecutorAgentLLM()
        self.defender = DefenderAgentLLM()
        self.judge = JudgeAgentLLM()

        self.rag_retriever = RAGRetriever()
        self._rag_loaded = self.rag_retriever.load_index()

        self.citation_validator = CitationValidator()

        self._current_cti_sources: list = []
        
        self.log_schema_context = ""
        try:
            from pathlib import Path
            schema_file = Path(__file__).parent.parent.parent / "knowledge_base" / "log_schemas.md"
            if schema_file.exists():
                with open(schema_file, "r", encoding="utf-8") as f:
                    self.log_schema_context = f.read()
        except Exception:
            pass

    def debate(self, event: Event, memory_context: str = "") -> Judgement:
        """执行对抗辩论过程"""
        print(f"\n⚖️  Adversarial Group: {event.event_id}")
        
        event_details = f"Event Type: {event.event_type}\n"
        for k, v in event.properties.items():
            event_details += f"{k}: {v}\n"
            
        print(f"  🔍  Retrieving Knowledge Base...")
        knowledge_context, cti_sources, mitre_sources = self._retrieve_knowledge_context(event, memory_context)
        self._current_cti_sources = cti_sources
        
        if cti_sources:
            self.citation_validator.set_cti_sources(cti_sources)
            
        if knowledge_context:
            logger.log_adversarial_context(f"[Knowledge Base]\n{knowledge_context}")

        with ThreadPoolExecutor(max_workers=2) as executor:
            prosecutor_future = executor.submit(
                self.prosecutor.argue, event_details, memory_context, knowledge_context
            )
            defender_future = executor.submit(
                self.defender.argue, event_details, memory_context, knowledge_context
            )
            
            malicious_evidence = prosecutor_future.result()
            benign_evidence = defender_future.result()
        
        prosecutor_validation = self._validate_and_log_citations("Prosecutor", malicious_evidence)
        print(f"  🔴 Prosecutor: {malicious_evidence[:120]}...")
        
        defender_validation = self._validate_and_log_citations("Defender", benign_evidence)
        print(f"  🔵 Defender: {benign_evidence[:120]}...")
        
        credibility_summary = self._build_credibility_summary(prosecutor_validation, defender_validation)

        judgement = self.judge.decide(
            event_details, malicious_evidence, benign_evidence, 
            memory_context, knowledge_context, credibility_summary
        )
        self._validate_and_log_citations("Judge", judgement.reasoning)

        verdict_text = "MALICIOUS" if judgement.is_malicious else "BENIGN"
        print(f"  ⚖️  Judge: {verdict_text} ({judgement.confidence_score:.2f})")
        print(f"  {judgement.reasoning[:150]}...")

        return judgement
    
    def _validate_and_log_citations(self, agent_name: str, text: str):
        result = self.citation_validator.validate(text)
        report = self.citation_validator.format_validation_report(result)
        logger.log_citation_validation(agent_name, report)
        
        if result.unverified_count > 0:
            console.print(f"  [yellow]⚠️ {agent_name}: {result.unverified_count} 个引用未验证[/yellow]")
        
        return result
    
    def _build_credibility_summary(self, prosecutor_result, defender_result) -> str:
        def format_result(name, result):
            total = len(result.citations)
            if total == 0:
                return f"{name}: 无引用"
            return f"{name}: {result.verified_count}✅已验证 {result.unverified_count}⚠️未验证 {result.inferred_count}ℹ️推断 / 共{total}引用"
        
        prosecutor_summary = format_result("检察官", prosecutor_result)
        defender_summary = format_result("辩护人", defender_result)
        
        tips = []
        if prosecutor_result.verified_count > defender_result.verified_count:
            tips.append("检察官的引用更多来自可验证来源")
        elif defender_result.verified_count > prosecutor_result.verified_count:
            tips.append("辩护人的引用更多来自可验证来源")
        
        if defender_result.unverified_count > 0:
            tips.append(f"辩护人有{defender_result.unverified_count}个引用无法验证（可能存在幻觉）")
        if prosecutor_result.unverified_count > 0:
            tips.append(f"检察官有{prosecutor_result.unverified_count}个引用无法验证（可能存在幻觉）")
        
        summary = f"""📊 引用可信度摘要：
- {prosecutor_summary}
- {defender_summary}"""
        
        if tips:
            summary += "\n⚠️ 注意：" + "；".join(tips)
        
        return summary
    
    def _retrieve_knowledge_context(self, event: Event, memory_context: str) -> tuple:
        if not self._rag_loaded:
            return "", [], []
            
        # 提取细粒度上下文和当前事件的内容
        recent_context = memory_context[-500:] if memory_context else ""
        event_str = f"{event.event_type} " + " ".join([str(v) for v in event.properties.values()])
        narrative = f"Context: {recent_context}\nCurrent Event: {event_str}"
        
        keywords = []
        if "command_line" in event.properties:
            keywords.extend(event.properties["command_line"].split())
        if "process_name" in event.properties:
            keywords.append(event.properties["process_name"])
            
        try:
            results = self.rag_retriever.search(
                narrative_context=narrative,
                keywords=keywords,
                top_k=3
            )
            
            if not results:
                return "", [], []
                
            if isinstance(results, dict):
                results = [results]
                
            knowledge_parts = []
            cti_sources = []
            mitre_sources = []
            
            for i, r in enumerate(results, 1):
                source = r.get("source", "Unknown")
                source_type = r.get("source_type", "CTI")
                text = r.get("text", "")
                
                if source_type == "CTI":
                    knowledge_parts.append(f"[CTI Source: {source}]\n{text}")
                    cti_sources.append(source)
                    print(f"  📚 CTI Reference: {source} (score: {r.get('score', 0):.3f})")
                elif source_type == "MITRE":
                    knowledge_parts.append(f"[MITRE TTP: {source}]\n{text}")
                    mitre_sources.append(source)
                    print(f"  📚 MITRE Reference: {source} (score: {r.get('score', 0):.3f})")
                    
            if self.log_schema_context:
                knowledge_parts.append(f"[System Log Schema]\n{self.log_schema_context}")
                
            return "\n\n".join(knowledge_parts), cti_sources, mitre_sources
            
        except Exception as e:
            console.print(f"[yellow]⚠️ RAG 检索失败: {e}[/yellow]")
            return "", [], []

    def _format_event_details(self, event: Event) -> str:
        props = event.properties
        details = f"Event ID: {event.event_id}\n"
        details += f"Event Type: {event.event_type}\n"
        
        key_props = ["source_name", "target_name", "source_type", "target_type", 
                     "source_uuid", "target_uuid", "event_name", "command_line", 
                     "path", "pid", "user", "parent", "ip_context"]
        for key, value in props.items():
            if key in key_props:
                details += f"  - {key}: {value}\n"

        return details

class ProsecutorAgentLLM:

    def __init__(self):
        self.llm = LLMClient()

    def argue(self, event_details: str, memory_context: str = "", cti_context: str = "") -> str:
        cti_section = ""
        if cti_context:
            cti_section = f"""📚 参考威胁情报 (CTI):
以下是与当前事件相关的威胁情报摘录，请结合参考：
{cti_context}"""
        
        user_message = AdversarialPrompts.USER_TEMPLATE.format(
            event_details=event_details,
            context=memory_context or "暂无已确认的恶意事件",
            cti_section=cti_section
        )
        
        logger.log_prosecutor_prompt(AdversarialPrompts.PROSECUTOR_SYSTEM, user_message)

        try:
            evidence = self.llm.call(
                system_prompt=AdversarialPrompts.PROSECUTOR_SYSTEM,
                user_message=user_message,
                temperature=0.7
            )
            logger.log_prosecutor_response(evidence)
            return evidence.strip()
        except Exception as e:
            return f"Error: {str(e)}"

class DefenderAgentLLM:

    def __init__(self):
        self.llm = LLMClient()

    def argue(self, event_details: str, memory_context: str = "", cti_context: str = "") -> str:
        cti_section = ""
        if cti_context:
            cti_section = f"""📚 参考威胁情报 (CTI):
以下是与当前事件相关的威胁情报摘录，请结合参考：
{cti_context}"""
        
        user_message = AdversarialPrompts.USER_TEMPLATE.format(
            event_details=event_details,
            context=memory_context or "暂无已确认的恶意事件",
            cti_section=cti_section
        )
        
        logger.log_defender_prompt(AdversarialPrompts.DEFENDER_SYSTEM, user_message)

        try:
            evidence = self.llm.call(
                system_prompt=AdversarialPrompts.DEFENDER_SYSTEM,
                user_message=user_message,
                temperature=0.7
            )
            logger.log_defender_response(evidence)
            return evidence.strip()
        except Exception as e:
            return f"Error: {str(e)}"

class JudgeAgentLLM:

    def __init__(self):
        self.llm = LLMClient()

    def decide(self, event_details: str, malicious_arg: str, benign_arg: str, 
               memory_context: str = "", cti_context: str = "", 
               credibility_summary: str = "") -> Judgement:
        cti_section = ""
        if cti_context:
            cti_section = f"""\n📚 参考威胁情报 (CTI):
{cti_context}
"""
        
        credibility_section = ""
        if credibility_summary:
            credibility_section = f"""
{credibility_summary}
"""
        
        user_message = f"""当前事件详情：
{event_details}

调查上下文（重要！已确认的恶意事件列表）：
{memory_context or "暂无已确认的恶意事件"}
{cti_section}
检察官论据（恶意证据）：
{malicious_arg}

辩护律师论据（良性解释）：
{benign_arg}
{credibility_section}
请综合双方论据，特别关注当前事件与已确认恶意事件的关联，以及双方引用的可信度，做出最终判决。"""

        logger.log_judge_prompt(AdversarialPrompts.JUDGE_SYSTEM, user_message)

        try:
            result, raw_response = self.llm.call_json_with_raw(
                system_prompt=AdversarialPrompts.JUDGE_SYSTEM,
                user_message=user_message,
                temperature=0.5
            )
            
            logger.log_judge_response(raw_response, result)

            if "error" in result:
                return self._fallback_judgement(malicious_arg, benign_arg)

            return Judgement(
                is_malicious=result.get("is_malicious", False),
                confidence_score=min(max(result.get("confidence_score", 0.5), 0.0), 1.0),
                reasoning=result.get("reasoning", "LLM判决")
            )

        except Exception as e:
            print(f"Judge LLM 错误: {e}")
            return self._fallback_judgement(malicious_arg, benign_arg)

    def _fallback_judgement(self, malicious_arg: str, benign_arg: str) -> Judgement:
        malicious_keywords = ["encoded", "obfuscated", "suspicious", "malicious", "attack", "exploit"]
        malicious_score = sum(1 for keyword in malicious_keywords if keyword.lower() in malicious_arg.lower())

        is_malicious = malicious_score >= 2
        confidence = 0.6 if is_malicious else 0.4

        return Judgement(
            is_malicious=is_malicious,
            confidence_score=confidence,
            reasoning=f"备用判决: 基于关键词分析 (malicious_score={malicious_score})"
        )
