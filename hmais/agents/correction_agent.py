
import json
from typing import Optional, Tuple, Set, List, Dict, Any
from rich.console import Console

from hmais.tools.llm_client import LLMClient
from hmais.tools.logger import logger

console = Console()

class CorrectionAgent:
    
    def __init__(self):
        self.llm = LLMClient()
    
    def _normalize_state(self, state: dict) -> dict:
        import copy
        
        attack_graph = state.get("attack_graph", {})
        nodes = attack_graph.get("nodes", [])
        
        if not nodes or "id" in nodes[0]:
            return state
        
        if "uuid" not in nodes[0]:
            return state
        
        console.print("[cyan]检测到 shadow_tracking 格式，自动转换中...[/cyan]")
        
        normalized = copy.deepcopy(state)
        ag = normalized["attack_graph"]
        
        for node in ag["nodes"]:
            if "uuid" in node and "id" not in node:
                node["id"] = node.pop("uuid")
        
        for edge in ag["edges"]:
            if "event_uuid" in edge and "event_id" not in edge:
                edge["event_id"] = edge.pop("event_uuid")
            if "source_uuid" in edge and "source" not in edge:
                edge["source"] = edge.pop("source_uuid")
            if "target_uuid" in edge and "target" not in edge:
                edge["target"] = edge.pop("target_uuid")
        
        if "action_history" in normalized and "investigation_history" not in normalized:
            normalized["investigation_history"] = normalized.pop("action_history")
        
        if "narrative_summary" in normalized:
            if "memory_context" not in normalized:
                normalized["memory_context"] = {}
            mc = normalized["memory_context"]
            if "attack_summary" not in mc:
                mc["attack_summary"] = normalized["narrative_summary"]

            if "state" not in mc:
                mc["state"] = {
                    "narrative_log": [],
                    "confirmed_malicious": [e.get("event_id", e.get("event_uuid", "")) for e in ag["edges"]],
                    "pending_investigation": []
                }
        
        if "evaluated_events" not in normalized:
            normalized["evaluated_events"] = []
        
        console.print("[green]✓ 格式转换完成[/green]")
        return normalized
    
    def correct(self, state: dict, feedback: str, 
                human_direction: Optional[str] = None) -> Tuple[dict, str]:
        console.print(f"\n[bold cyan]🔧 纠错智能体[/bold cyan]")
        console.print(f"[cyan]反馈: {feedback}[/cyan]")
        
        state = self._normalize_state(state)
        
        events_to_remove = self._parse_feedback(state, feedback)
        
        if not events_to_remove:
            console.print("[yellow]⚠️ 未能识别需要移除的事件[/yellow]")
            return state, human_direction or ""
        
        console.print(f"[cyan]识别到需要移除的事件: {events_to_remove}[/cyan]")
        
        corrected_state = self._remove_events_cascade(state, events_to_remove)
        
        if human_direction:
            new_direction = human_direction
            console.print(f"[cyan]使用人类提供的调查方向: {new_direction}[/cyan]")
        else:
            new_direction = self._infer_new_direction(corrected_state, feedback)
            console.print(f"[cyan]推理出的新调查方向: {new_direction}[/cyan]")
        
        return corrected_state, new_direction
    
    def _parse_feedback(self, state: dict, feedback: str) -> Set[str]:

        graph_summary = self._build_graph_summary(state)
        
        system_prompt = """你是一个安全调查纠错助手。你的任务是解析人类安全员的反馈，识别需要从攻击图中移除的事件。

人类可能会说:
- "事件 X 不是恶意的"
- "bash 进程是正常的"
- "这个网络连接是误报"
- "EXECUTE 事件判断错了"

你需要根据反馈和攻击图信息，输出需要移除的事件 ID 列表。

输出格式 (JSON):
{
    "events_to_remove": ["event_id_1", "event_id_2"],
    "reasoning": "解释为什么选择这些事件"
}

如果无法识别，返回:
{
    "events_to_remove": [],
    "reasoning": "无法识别需要移除的事件"
}"""

        user_message = f"""当前攻击图:
{graph_summary}

人类反馈:
{feedback}

请识别需要从攻击图中移除的事件 ID。"""

        try:
            result, _ = self.llm.call_json_with_raw(
                system_prompt=system_prompt,
                user_message=user_message,
                temperature=0.3
            )
            
            events = result.get("events_to_remove", [])
            reasoning = result.get("reasoning", "")
            
            if reasoning:
                console.print(f"[dim]推理: {reasoning}[/dim]")
            
            return set(events)
            
        except Exception as e:
            console.print(f"[red]解析反馈失败: {e}[/red]")
            return set()
    
    def _remove_events_cascade(self, state: dict, events_to_remove: Set[str]) -> dict:
        import copy
        corrected = copy.deepcopy(state)
        
        attack_graph = corrected.get("attack_graph", {})
        edges = attack_graph.get("edges", [])
        nodes = attack_graph.get("nodes", [])
        evaluated_events = set(corrected.get("evaluated_events", []))
        
        poi = corrected.get("poi", {})
        poi_event_id = poi.get("event_id", "")
        
        initial_nodes = set()
        for edge in edges:
            if edge.get("event_id") == poi_event_id:
                initial_nodes.add(edge.get("source"))
                initial_nodes.add(edge.get("target"))
                break
        
        all_events_to_remove = set()
        all_nodes_to_remove = set()
        
        def collect_downstream(event_ids: Set[str]):
            for event_id in event_ids:
                if event_id in all_events_to_remove:
                    continue
                    
                all_events_to_remove.add(event_id)
                
                for edge in edges:
                    if edge.get("event_id") == event_id:
                        target_node = edge.get("target")
                        
                        if target_node and target_node not in initial_nodes:
                            all_nodes_to_remove.add(target_node)
                            
                            downstream_events = set()
                            for e in edges:
                                if e.get("source") == target_node:
                                    downstream_events.add(e.get("event_id"))
                            
                            if downstream_events:
                                collect_downstream(downstream_events)
                        break
        
        collect_downstream(events_to_remove)
        
        console.print(f"[cyan]级联删除: {len(all_events_to_remove)} 个事件, {len(all_nodes_to_remove)} 个节点[/cyan]")
        
        new_edges = [e for e in edges if e.get("event_id") not in all_events_to_remove]
        new_nodes = [n for n in nodes if n.get("id") not in all_nodes_to_remove]
        new_evaluated = evaluated_events - all_events_to_remove
        
        corrected["attack_graph"]["edges"] = new_edges
        corrected["attack_graph"]["nodes"] = new_nodes
        corrected["evaluated_events"] = list(new_evaluated)
        
        memory_context = corrected.get("memory_context", {})
        state_data = memory_context.get("state", {})
        confirmed = set(state_data.get("confirmed_malicious", []))
        state_data["confirmed_malicious"] = list(confirmed - all_events_to_remove)
        corrected["memory_context"]["state"] = state_data
        
        console.print(f"[green]✓ 纠错完成: {len(new_nodes)} 节点, {len(new_edges)} 边[/green]")
        
        return corrected
    
    def _infer_new_direction(self, corrected_state: dict, feedback: str) -> str:
        graph_summary = self._build_graph_summary(corrected_state)
        evaluated_count = len(corrected_state.get("evaluated_events", []))
        
        system_prompt = """你是一个安全调查规划专家。在纠错后，你需要基于剩余的攻击图推理出一个新的调查方向。

规则:
1. 分析剩余攻击图中的节点和边
2. 识别尚未充分调查的方向
3. 避免重复调查已评估的事件
4. 给出具体、可执行的调查方向

输出格式 (JSON):
{
    "direction": "具体的调查方向描述",
    "reasoning": "为什么选择这个方向"
}"""

        user_message = f"""纠错后的攻击图:
{graph_summary}

已评估事件数: {evaluated_count}

之前的纠错反馈:
{feedback}

请推理出一个新的调查方向。"""

        try:
            result, _ = self.llm.call_json_with_raw(
                system_prompt=system_prompt,
                user_message=user_message,
                temperature=0.7
            )
            
            direction = result.get("direction", "")
            reasoning = result.get("reasoning", "")
            
            if reasoning:
                console.print(f"[dim]推理依据: {reasoning}[/dim]")
            
            return direction
            
        except Exception as e:
            console.print(f"[red]推理新方向失败: {e}[/red]")
            return "继续调查攻击图中未探索的节点"
    
    def _build_graph_summary(self, state: dict) -> str:
        attack_graph = state.get("attack_graph", {})
        nodes = attack_graph.get("nodes", [])
        edges = attack_graph.get("edges", [])
        
        lines = ["节点:"]
        for node in nodes:
            lines.append(f"  - {node.get('id')}: {node.get('name')} ({node.get('type')})")
        
        lines.append("\n事件 (边):")
        for edge in edges:
            lines.append(f"  - {edge.get('event_id')}: {edge.get('source')} --[{edge.get('event_type')}]--> {edge.get('target')}")
        
        return "\n".join(lines)

def save_corrected_state(session_dir: str, corrected_state: dict) -> str:
    import os
    from datetime import datetime
    
    corrected_state["corrected_at"] = datetime.now().isoformat()
    
    filepath = os.path.join(session_dir, "corrected_state.json")
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(corrected_state, f, ensure_ascii=False, indent=2)
    
    console.print(f"[green]✓ 纠错状态已保存: {filepath}[/green]")
    return filepath
