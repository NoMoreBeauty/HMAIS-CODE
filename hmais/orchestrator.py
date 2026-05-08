
from typing import Optional, Dict, Any
import re
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

from hmais.agents.planner_agent_llm import PlannerAgentLLM
from hmais.agents.query_agent_llm import QueryAgentLLM
from hmais.agents.filter_agent import FilterAgent
from hmais.agents.adversarial_group_llm import AdversarialGroupLLM
from hmais.agents.memory_agent import MemoryAgent

from hmais.tools.real_neo4j import RealNeo4jDB
import config

console = Console()

class HMAISOrchestrator:

    def __init__(self):

        from hmais.tools.logger import logger
        self.logger = logger
        log_dir = logger.init_session()
        self.log_dir = log_dir
        console.print(f"[dim]日志文件: main.log[/dim]")
        
        self.db = RealNeo4jDB()

        self.planner = PlannerAgentLLM()
        self.query_agent = QueryAgentLLM(self.db)
        self.adversarial_group = AdversarialGroupLLM()
        self.filter_agent = FilterAgent()
        self.memory = MemoryAgent()
        
        self.human_direction = None

        console.print(f"[bold cyan]HMAIS 初始化完成[/bold cyan]\n")
        self.logger.log_main(f"HMAIS 初始化完成")
    
    def restore_state(self, state: dict):

        self.memory.import_state(state)
        
        evaluated_events = state.get("evaluated_events", set())
        if hasattr(self.planner, 'set_evaluated_events'):
            self.planner.set_evaluated_events(evaluated_events)
    
    def set_human_direction(self, direction: str):
        self.human_direction = direction
        if hasattr(self.planner, 'set_human_direction'):
            self.planner.set_human_direction(direction)

    def _fetch_poi_details(self, poi_id: str) -> Optional[Dict[str, Any]]:

        if len(poi_id) < 30 or " " in poi_id or "：" in poi_id:

            return None

        try:
            console.print(f"[dim]从数据库获取 POI 详情...[/dim]")

            event_query = f"""
            MATCH (src:node)-[r]->(dst:node)
            WHERE r.event_uuid = '{poi_id}'
            RETURN
                type(r) AS rel_type,
                r.event_uuid AS event_uuid,
                r.event_category AS category,
                r.event_type_raw AS event_type_raw,
                r.event_name AS event_name,
                r.start_node_uuid AS start_id,
                src.type AS start_type,
                r.start_node_name AS start_name,
                r.end_node_uuid AS end_id,
                dst.type AS end_type,
                r.end_node_name AS end_name
            LIMIT 1
            """
            event_result = self.db.execute_fetch_query(event_query)

            if event_result and len(event_result) > 0:
                event_data = event_result[0]
                console.print(f"[green]✓ 找到 POI: {event_data.get('rel_type', 'Unknown')} 事件[/green]")
                return {
                    "POI类型": "事件 (Event)",
                    "Event UUID": event_data.get("event_uuid", poi_id),
                    "关系类型": event_data.get("rel_type", "Unknown"),
                    "事件类别": event_data.get("category", "Unknown"),
                    "事件类型": event_data.get("event_type_raw", "Unknown"),
                    "事件名称": event_data.get("event_name", "Unknown"),
                    "源节点": f"{event_data.get('start_name', 'Unknown')} ({event_data.get('start_type', 'Unknown')})",
                    "目标节点": f"{event_data.get('end_name', 'Unknown')} ({event_data.get('end_type', 'Unknown')})",
                    "源节点ID": event_data.get("start_id", ""),
                    "目标节点ID": event_data.get("end_id", "")
                }

            console.print(f"[yellow]⚠️  数据库中未找到 POI 事件[/yellow]")
            return None

        except Exception as e:
            console.print(f"[yellow]⚠️  无法获取 POI 详情: {e}[/yellow]")
            return None

    def run_investigation(self, initial_poi: str = "可疑的 PowerShell 进程执行事件", 
                          is_continuation: bool = False):
        if is_continuation:
            console.print(f"[bold]继续调查:[/bold] {initial_poi}\n")
        else:
            console.print(f"[bold]开始调查:[/bold] {initial_poi}\n")

        if not is_continuation:
            self.memory.initial_poi = initial_poi

            poi_details = self._fetch_poi_details(initial_poi)
            if poi_details:
                self.memory.poi_details = poi_details

                self.memory.register_poi_as_malicious(poi_details)
        else:

            poi_details = self._fetch_poi_details(initial_poi)
            if poi_details:
                self.memory.poi_details = poi_details

        iteration = 0
        max_iterations = 75
        
        stagnation_threshold = 20
        stagnation_count = 0
        last_edge_count = len(self.memory.graph.edges)

        count_first_max_refine = 3

        while iteration < max_iterations:
            iteration += 1
            console.print(f"\n[bold cyan]─── 迭代 {iteration} ───[/bold cyan]")

            context = self.memory.get_context(iteration=iteration)
            plan = self.planner.plan(context)

            if plan.stop_investigation:
                console.print("\n[bold green]✓ Planner 决定结束调查[/bold green]")
                break

            uuid_match = re.search(r'([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})', plan.next_action)
            if uuid_match:
                self.memory.set_focus_entity(uuid_match.group(1))
            
            current_action = plan.next_action
            result = None
            for refine_attempt in range(count_first_max_refine + 1):
                result = self.query_agent.execute(current_action)
                
                if not result.success and result.count and result.count > config.MAX_QUERY_RESULT:
                    if refine_attempt < count_first_max_refine:
                        console.print(f"[yellow]⚡ Count-First 回压: {result.count} 条结果超过阈值 {config.MAX_QUERY_RESULT}，请求 Planner 细化查询...[/yellow]")
                        refine_feedback = (
                            f"上一步查询 '{current_action}' 返回了 {result.count} 条结果，"
                            f"超过了安全阈值 {config.MAX_QUERY_RESULT}。"
                            f"请生成更严格的查询指令（如添加时间窗口、事件类型过滤或更具体的节点属性约束）。"
                        )
                        refined_plan = self.planner.plan(context, feedback=refine_feedback)
                        if refined_plan.stop_investigation:
                            plan = refined_plan
                            break
                        current_action = refined_plan.next_action
                        console.print(f"[cyan]  → 细化指令: {current_action[:80]}...[/cyan]")
                    else:

                        console.print(f"[yellow]⚠️ 回压重试已达上限，跳过本次查询[/yellow]")
                        self.memory.record_action(plan.next_action, f"Skipped: too many results ({result.count})")
                        self.planner.record_result(plan.next_action, success=False, has_new_findings=False)
                        stagnation_count += 1
                        if stagnation_count >= stagnation_threshold:
                            console.print(f"\n[yellow]⚠️ 连续 {stagnation_threshold} 轮无新发现（N_stag），停止调查[/yellow]")
                            break
                        result = None
                else:
                    break
            
            if plan.stop_investigation:
                console.print("\n[bold green]✓ Planner 决定结束调查[/bold green]")
                break
            if result is None:
                continue

            if not result.success:
                console.print(f"[red]查询失败: {result.error}[/red]")
                self.memory.record_action(plan.next_action, f"Failed: {result.error}")

                is_syntax_error = "语法" in str(result.error) or "syntax" in str(result.error).lower()
                self.planner.record_result(plan.next_action, success=False, has_new_findings=False, is_syntax_error=is_syntax_error)

                stagnation_count += 1
                if stagnation_count >= stagnation_threshold:
                    console.print(f"\n[yellow]⚠️ 攻击子图已连续 {stagnation_threshold} 次迭代无变化，停止调查[/yellow]")
                    break
                continue

            if not result.data or result.count == 0:
                console.print("[yellow]未找到相关事件[/yellow]")
                self.memory.record_action(plan.next_action, "No results")

                self.planner.record_result(plan.next_action, success=True, has_new_findings=False)

                stagnation_count += 1
                if stagnation_count >= stagnation_threshold:
                    console.print(f"\n[yellow]⚠️ 攻击子图已连续 {stagnation_threshold} 次迭代无变化，停止调查[/yellow]")
                    break
                continue

            self.memory.record_action(plan.next_action, "Success")

            known_event_ids = self.memory.get_known_event_ids()
            suspicious_events = self.filter_agent.scan(result.data, known_event_ids)

            if not suspicious_events:
                console.print("[green]所有事件已被过滤（良性或已知），继续...[/green]")

                stagnation_count += 1
                if stagnation_count >= stagnation_threshold:
                    console.print(f"\n[yellow]⚠️ 攻击子图已连续 {stagnation_threshold} 次迭代无变化，停止调查[/yellow]")
                    break
                continue

            memory_context = self.memory.get_context(iteration=iteration)
            
            for event in suspicious_events:

                judgement = self.adversarial_group.debate(event, memory_context)

                if judgement.is_malicious and judgement.confidence_score >= config.CONFIDENCE_THRESHOLD:
                    self.memory.update(event, judgement)
                else:
                    console.print(f"[dim]事件 {event.event_id} 被标记为良性 (置信度: {judgement.confidence_score:.2f})[/dim]")

            current_edge_count = len(self.memory.graph.edges)
            if current_edge_count == last_edge_count:
                stagnation_count += 1
                self.planner.record_result(plan.next_action, success=True, has_new_findings=False)
                if stagnation_count >= stagnation_threshold:
                    console.print(f"\n[yellow]⚠️ 攻击子图已连续 {stagnation_threshold} 轮无新发现（N_stag），停止调查[/yellow]")
                    break
            else:
                stagnation_count = 0
                last_edge_count = current_edge_count
                self.planner.record_result(plan.next_action, success=True, has_new_findings=True)

        console.print("\n[bold green]✓ 调查完成[/bold green]\n")
        self._display_final_report()

    def _display_final_report(self):
        report = self.memory.generate_report()

        console.print(Markdown(report))

        console.print("\n[bold]统计信息:[/bold]")
        console.print(f"  迭代次数: {self.planner.iteration}")
        console.print(f"  执行动作数: {len(self.memory.get_investigation_history())}")
        console.print(f"  恶意事件数: {len(self.memory.graph.edges)}")
        console.print(f"  攻击涉及实体数: {len(self.memory.graph.nodes)}")
        
        import os
        log_dir = self.logger.log_dir if hasattr(self, 'logger') and self.logger.log_dir else "."
        dot_path = os.path.join(log_dir, "attack_graph.dot")
        self.memory.export_to_dot(dot_path)
        
        from hmais.tools.investigation_state import save_state
        state_data = self.memory.export_state()
        save_state(log_dir, state_data)
