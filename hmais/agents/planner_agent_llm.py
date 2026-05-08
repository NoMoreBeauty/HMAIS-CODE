
from rich.console import Console
from hmais.models.data_models import Plan, InvestigationPhase
from hmais.tools.llm_client import LLMClient
from hmais.prompts.prompt_templates import PlannerPrompts
from hmais.tools.logger import logger

console = Console()

class PlannerAgentLLM:

    def __init__(self):
        self.current_phase = InvestigationPhase.INVESTIGATION
        self.iteration = 0
        self.last_error = None
        self.llm = LLMClient()
        
        self.human_direction = None

        self.human_direction_executed = False

        self.evaluated_events = set()
        
        self.consecutive_failures = 0
        self.syntax_errors = 0
        self.last_action = None
    
    def record_result(self, action: str, success: bool, has_new_findings: bool, is_syntax_error: bool = False):
        if is_syntax_error:
            self.syntax_errors += 1
        
        if not has_new_findings:
            self.consecutive_failures += 1
        else:
            self.consecutive_failures = 0
        
        self.last_action = action
    
    def set_human_direction(self, direction: str):
        self.human_direction = direction
        self.human_direction_executed = False
        console.print(f"[bold cyan]📋 人类指导: {direction}[/bold cyan]")
    
    def set_evaluated_events(self, event_ids: set):
        self.evaluated_events = event_ids
        if event_ids:
            console.print(f"[cyan]📝 已加载 {len(event_ids)} 个已评估事件[/cyan]")

    def plan(self, context: str, feedback: str = None) -> Plan:
        self.iteration += 1
        console.print(f"\n[bold blue]🧠 Planner Agent:[/bold blue]")
        
        logger.set_iteration(self.iteration)
        
        logger.log_planner_input(context, feedback)

        if feedback:
            console.print(f"[yellow]收到反馈: {feedback}[/yellow]")

        history = f"迭代 {self.iteration}"
        feedback_section = ""
        if feedback:

            feedback_section = PlannerPrompts.FEEDBACK_TEMPLATE.format(feedback=feedback)
        
        human_direction_section = ""
        if self.human_direction and not self.human_direction_executed:
            human_direction_section = f"""
🎯 **人类安全员指导（优先执行）**:
{self.human_direction}

请优先按照上述指导方向进行调查。完成后再恢复自主调查。
"""

            self.human_direction_executed = True
        
        evaluated_section = ""
        if self.evaluated_events:
            evaluated_section = f"""
⚠️ **已调查过的事件（请勿重复调查）**:
共 {len(self.evaluated_events)} 个事件已被评估。请探索新的方向，不要重复调查这些已知事件。
"""

        user_message = PlannerPrompts.USER_TEMPLATE.format(
            context=context,
            history=history,
            feedback_section=feedback_section,
            action_count=self.iteration,
            consecutive_failures=self.consecutive_failures,
            syntax_errors=self.syntax_errors
        )
        
        if human_direction_section or evaluated_section:
            user_message = human_direction_section + evaluated_section + "\n" + user_message
        
        logger.log_planner_prompt(PlannerPrompts.SYSTEM_PROMPT, user_message)

        try:
            result, raw_response = self.llm.call_json_with_raw(
                system_prompt=PlannerPrompts.SYSTEM_PROMPT,
                user_message=user_message,
                temperature=0.7
            )
            
            logger.log_planner_output(raw_response, result)

            if "error" in result:
                console.print(f"[red]LLM 错误: {result['error']}[/red]")
                return self._fallback_plan(feedback)

            plan = Plan(
                phase=InvestigationPhase(result.get("phase", "Investigation")),
                thought_process=result.get("thought_process", ""),
                next_action=result.get("next_action", ""),
                stop_investigation=result.get("stop_investigation", False)
            )

            console.print(f"[blue]Thought:[/blue] {plan.thought_process[:200]}...")
            console.print(f"[blue]Action:[/blue] {plan.next_action}")

            return plan

        except Exception as e:
            console.print(f"[red]Planner 错误: {e}[/red]")
            return self._fallback_plan(feedback)

    def _fallback_plan(self, feedback: str = None) -> Plan:
        if feedback and "no events found" in feedback.lower():
            return Plan(
                phase=InvestigationPhase.CONCLUSION,
                thought_process="LLM 不可用且未找到结果，停止调查。",
                next_action="结束调查",
                stop_investigation=True
            )

        return Plan(
            phase=InvestigationPhase.INVESTIGATION,
            thought_process="LLM 不可用，使用备用策略。",
            next_action="查找初始 POI 的相关事件",
            stop_investigation=False
        )
