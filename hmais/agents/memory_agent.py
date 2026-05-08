
from typing import Dict, Any
import networkx as nx
from pathlib import Path
from rich.console import Console
from hmais.models.data_models import Event, Judgement, MemoryState
from hmais.tools.llm_client import LLMClient
from hmais.tools.logger import logger

console = Console()

class MemoryAgent:

    def __init__(self, initial_poi: str = ""):

        self.graph = nx.DiGraph()
        
        self.state = MemoryState()
        
        self.investigation_steps = []
        
        self.initial_poi = initial_poi
        self.poi_details = None
        
        self.attack_summary = ""

        self.current_focus_entity = None

        self.llm = LLMClient()

        self._summary_prompt = self._load_summary_prompt()
        
        self.ttp_chain = []
        


    def update(self, event: Event, judgement: Judgement, parent_id: str = None):
        print(f"\n📝 Memory Agent: 记录恶意事件 {event.event_id}")

        props = event.properties
        source_uuid = props.get("source_uuid", "")
        target_uuid = props.get("target_uuid", "")
        source_name = props.get("source_name", "Unknown")
        target_name = props.get("target_name", "Unknown")
        source_type = props.get("source_type", "unknown")
        target_type = props.get("target_type", "unknown")

        ttp_dict = self._infer_mitre_ttp(event)
        mitre_technique = ttp_dict.get("technique", "N/A")

        if source_uuid and source_uuid not in self.graph.nodes:
            self.graph.add_node(
                source_uuid,
                name=source_name,
                node_type=source_type,
                is_entity=True
            )

        if target_uuid and target_uuid not in self.graph.nodes:
            self.graph.add_node(
                target_uuid,
                name=target_name,
                node_type=target_type,
                is_entity=True
            )

        if source_uuid and target_uuid:
            self.graph.add_edge(
                source_uuid,
                target_uuid,
                event_id=event.event_id,
                event_type=event.event_type,
                mitre_technique=mitre_technique,
                properties=event.properties
            )

        self.state.add_malicious_event(event, judgement, mitre_technique)

        print(f"  ✓ 攻击子图: {len(self.graph.nodes)} 实体, {len(self.graph.edges)} 事件")
        print(f"  🎯 MITRE: {ttp_dict.get('tactic', 'Unknown')} - {mitre_technique} ({ttp_dict.get('name', 'Unknown')})")
        
        self._update_ttp_chain(event, ttp_dict)
        
        self._generate_summary(event, mitre_technique)
        
        logger.log_memory_summary(self.attack_summary, self.ttp_chain)

    def _load_summary_prompt(self) -> str:
        prompt_path = Path(__file__).parent.parent / "prompts" / "summary_system.txt"
        try:
            with open(prompt_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            console.print("[yellow]⚠️ 未找到摘要 Prompt 文件，使用默认配置[/yellow]")
            return "请将新事件融入现有摘要，生成连贯的中文叙述，不超过500字。"

    def set_focus_entity(self, entity_uuid: str):
        self.current_focus_entity = entity_uuid

    def _infer_mitre_ttp(self, event: Event) -> dict:
        props = event.properties
        
        event_details = f"Event ID: {event.event_id}\n"
        event_details += f"Event Type: {event.event_type}\n"
        key_props = ["source_name", "target_name", "source_type", "target_type", 
                     "event_name", "command_line", "path", "pid", "user", "parent", "ip_context"]
        for key, value in props.items():
            if key in key_props:
                event_details += f"  - {key}: {value}\n"
                
        context = ""
        for ttp in self.ttp_chain:
            context += f"- [{ttp.get('tactic')}] {ttp.get('technique')} ({ttp.get('name')})\n"
                
        if not context:
            context = "暂无已确认的上下文"
            
        from hmais.prompts.prompt_templates import MemoryPrompts
        
        user_message = MemoryPrompts.MITRE_USER_TEMPLATE.format(
            event_details=event_details,
            context=context
        )
        
        try:
            result, _ = self.llm.call_json_with_raw(
                system_prompt=MemoryPrompts.MITRE_SYSTEM_PROMPT,
                user_message=user_message,
                temperature=0.3
            )
            return {
                "tactic": result.get("tactic", "Unknown"),
                "technique": result.get("technique_id", "N/A"),
                "name": result.get("technique_name", "Unknown")
            }
        except Exception as e:
            console.print(f"[yellow]⚠️ MITRE 推断失败: {e}[/yellow]")
            return {
                "tactic": "Unknown",
                "technique": "N/A",
                "name": "Unknown"
            }

    def _update_ttp_chain(self, event: Event, ttp_dict: dict):
        technique_id = ttp_dict.get("technique")
        if not technique_id or technique_id == "N/A" or technique_id == "Unknown":
            return
        
        tactic = ttp_dict.get("tactic", "Unknown")
        technique_name = ttp_dict.get("name", "Unknown")
        
        props = event.properties
        source_name = props.get("source_name", "Unknown")
        target_name = props.get("target_name", "Unknown")
        event_desc = f"{source_name} → {target_name}"
        
        timestamp = props.get("timestamp", None)
        
        ttp_entry = {
            "technique": technique_id,
            "tactic": tactic,
            "name": technique_name,
            "timestamp": timestamp,
            "event_desc": event_desc
        }
        
        if timestamp is None:
            self.ttp_chain.insert(0, ttp_entry)
        else:

            inserted = False
            for i, entry in enumerate(self.ttp_chain):
                entry_ts = entry.get("timestamp")
                if entry_ts is None:

                    continue
                if timestamp < entry_ts:
                    self.ttp_chain.insert(i, ttp_entry)
                    inserted = True
                    break
            if not inserted:
                self.ttp_chain.append(ttp_entry)

    def _generate_summary(self, new_event: Event, mitre_technique: str):

        props = new_event.properties
        source_name = props.get("source_name", "Unknown")
        target_name = props.get("target_name", "Unknown")
        event_type = new_event.event_type
        mitre = mitre_technique if mitre_technique else "N/A"
        timestamp = props.get("timestamp", "")
        
        new_event_desc = f"事件: {source_name} -[{event_type}]-> {target_name}"
        if mitre != "N/A":
            new_event_desc += f" (MITRE: {mitre})"
        if timestamp:
            new_event_desc += f" [时间: {timestamp}]"
        
        focus_name = "未知"
        if self.current_focus_entity and self.current_focus_entity in self.graph.nodes:
            focus_name = self.graph.nodes[self.current_focus_entity].get("name", "未知")
        
        user_message = f"""当前摘要：
{self.attack_summary if self.attack_summary else "（首次生成，无现有摘要）"}

新确认的恶意事件：
{new_event_desc}

当前调查焦点实体：{focus_name}

请将新事件融入摘要，生成更新后的叙述性摘要。"""

        try:

            response = self.llm.call(
                system_prompt=self._summary_prompt,
                user_message=user_message
            )
            
            if response:
                self.attack_summary = response.strip()

                if len(self.attack_summary) > 500:
                    self.attack_summary = self.attack_summary[:497] + "..."
                    
        except Exception as e:
            console.print(f"[yellow]⚠️ 摘要生成失败: {e}[/yellow]")

            if self.attack_summary:
                self.attack_summary += f" {new_event_desc}"
            else:
                self.attack_summary = new_event_desc

    def register_poi_as_malicious(self, poi_details: Dict[str, Any]):
        if not poi_details:
            return
            
        poi_id = poi_details.get("Event UUID") or poi_details.get("ID") or "POI"
        event_type = poi_details.get("关系类型") or poi_details.get("Type") or "Unknown"
        
        source_full = poi_details.get("源节点", "Unknown")
        target_full = poi_details.get("目标节点", "Unknown")
        
        if " (" in source_full:
            source_name = source_full.split(" (")[0]
            source_type = source_full.split(" (")[1].rstrip(")")
        else:
            source_name = source_full
            source_type = "unknown"
            
        if " (" in target_full:
            target_name = target_full.split(" (")[0]
            target_type = target_full.split(" (")[1].rstrip(")")
        else:
            target_name = target_full
            target_type = "unknown"
        
        source_uuid = poi_details.get("源节点ID", "")
        target_uuid = poi_details.get("目标节点ID", "")
        
        if source_uuid:
            self.graph.add_node(
                source_uuid,
                name=source_name,
                node_type=source_type,
                is_entity=True
            )
        
        if target_uuid:
            self.graph.add_node(
                target_uuid,
                name=target_name,
                node_type=target_type,
                is_entity=True
            )
        
        if source_uuid and target_uuid:
            self.graph.add_edge(
                source_uuid,
                target_uuid,
                event_id=poi_id,
                event_type=event_type,
                is_poi=True,
                mitre_technique="N/A (Initial POI)",
                properties=poi_details
            )
        
        self.state.narrative_log.append(f"POI (初始恶意事件): {source_name} → {target_name} [{event_type}]")
        
        print(f"  ✓ POI 已注册: {source_name} -[{event_type}]-> {target_name}")
        print(f"    攻击子图: {len(self.graph.nodes)} 节点, {len(self.graph.edges)} 边")

    def record_action(self, action: str, result: str):
        self.investigation_steps.append({
            "action": action,
            "result": result
        })

    def _classify_action_type(self, action: str) -> str:
        action_lower = action.lower()
        if "父进程" in action or "parent" in action_lower:
            return "向上溯源（父进程）"
        elif "子进程" in action or "child" in action_lower or "衍生" in action:
            return "向下追踪（子进程）"
        elif "网络" in action or "ip" in action_lower or "连接" in action or "通信" in action:
            return "网络行为分析"
        elif "文件" in action and ("读" in action or "写" in action or "访问" in action):
            return "文件操作追踪"
        elif "时间" in action or "前后" in action:
            return "时间线分析"
        else:
            return "其他方向"

    def get_context(self, iteration: int = 1) -> str:

        compress_mode = iteration > 8
        
        context = f"""=== 调查上下文 ===
初始调查点 (POI): {self.initial_poi}
"""

        if self.poi_details:
            context += "\nPOI 详细信息:\n"
            for key, value in self.poi_details.items():
                context += f"  - {key}: {value}\n"

        if self.investigation_steps:
            if compress_mode:

                recent_steps = self.investigation_steps[-5:]
                context += f"\n⚠️ 最近 5 次动作（共执行 {len(self.investigation_steps)} 次，禁止重复！）:\n"
            else:
                recent_steps = self.investigation_steps
                context += "\n⚠️ 已执行的动作列表（禁止重复执行相同动作！）:\n"
            
            start_idx = len(self.investigation_steps) - len(recent_steps) + 1
            for i, step in enumerate(recent_steps, start_idx):
                action = step["action"]
                result = step["result"]
                if result == "Success":
                    context += f"  {i}. ✅ {action} → 有结果\n"
                elif result == "No results":
                    context += f"  {i}. ❌ {action} → 无结果\n"
                else:
                    context += f"  {i}. ⚠️ {action} → {result}\n"
            
            action_stats = {}
            for step in self.investigation_steps:
                action_type = self._classify_action_type(step["action"])
                if action_type not in action_stats:
                    action_stats[action_type] = {"success": 0, "failed": 0}
                if step["result"] == "Success":
                    action_stats[action_type]["success"] += 1
                else:
                    action_stats[action_type]["failed"] += 1

            failed_directions = [at for at, stats in action_stats.items() if stats["failed"] >= 2]
            if failed_directions:
                context += "\n🚫 以下方向已多次失败，请切换调查方向:\n"
                for d in failed_directions:
                    context += f"  - {d}\n"

        context += f"\n=== 攻击子图 ({len(self.graph.nodes)} 个实体, {len(self.graph.edges)} 条恶意事件) ===\n"

        if compress_mode:

            edge_nodes = self._get_edge_nodes()
            if edge_nodes:
                context += "\n🔍 边缘实体（尚未充分调查，优先探索）:\n"
                for node_id in edge_nodes:
                    node_data = self.graph.nodes[node_id]
                    name = node_data.get('name', 'Unknown')
                    node_type = node_data.get('node_type', 'unknown')
                    context += f"  • {name} ({node_type}) | UUID: {node_id}\n"
            else:
                context += "\n⚠️ 所有实体均已充分调查，建议停止调查。\n"
        else:

            if self.graph.nodes:
                context += "\n可用于查询的实体:\n"
                for node_id in self.graph.nodes:
                    node_data = self.graph.nodes[node_id]
                    name = node_data.get('name', 'Unknown')
                    node_type = node_data.get('node_type', 'unknown')
                    context += f"  • {name} ({node_type}) | UUID: {node_id}\n"

        if self.attack_summary:
            context += "\n📖 攻击摘要:\n"
            if compress_mode and len(self.attack_summary) > 300:

                context += f"{self.attack_summary[:300]}...\n"
            else:
                context += f"{self.attack_summary}\n"
        elif self.graph.edges:

            context += "\n已确认的恶意事件:\n"
            for edge in self.graph.edges:
                edge_data = self.graph.edges[edge]
                source_id, target_id = edge
                source_name = self.graph.nodes[source_id].get('name', 'Unknown') if source_id in self.graph.nodes else 'Unknown'
                target_name = self.graph.nodes[target_id].get('name', 'Unknown') if target_id in self.graph.nodes else 'Unknown'
                event_type = edge_data.get('event_type', 'Unknown')
                mitre = edge_data.get('mitre_technique', 'N/A')
                context += f"  • {source_name} -[{event_type}]-> {target_name} | MITRE: {mitre}\n"

        if self.ttp_chain:
            context += "\n🎯 MITRE ATT&CK TTP 链:\n"
            for i, ttp in enumerate(self.ttp_chain, 1):
                tactic = ttp.get("tactic", "Unknown")
                technique = ttp.get("technique", "?")
                name = ttp.get("name", "Unknown")
                event_desc = ttp.get("event_desc", "")
                context += f"  {i}. [{tactic}] {technique} ({name}) - {event_desc}\n"

        context += "\n💡 使用上面实体的 UUID 来查询其他行为（如父进程、子进程、网络活动等）\n"

        return context
    
    def _get_edge_nodes(self) -> list:
        edge_nodes = []
        for node_id in self.graph.nodes:
            in_degree = self.graph.in_degree(node_id)
            out_degree = self.graph.out_degree(node_id)
            if in_degree + out_degree <= 2:
                edge_nodes.append(node_id)
        return edge_nodes

    def get_investigation_history(self) -> list:
        return self.investigation_steps

    def get_known_event_ids(self) -> set:
        known_ids = set()
        for edge in self.graph.edges:
            edge_data = self.graph.edges[edge]
            event_id = edge_data.get('event_id')
            if event_id:
                known_ids.add(event_id)
        return known_ids

    def generate_report(self) -> str:
        report = "# HMAIS 调查报告\n\n"
        report += f"## 摘要\n"
        report += f"- 识别的恶意事件总数: {len(self.graph.edges)}\n"
        report += f"- 攻击涉及实体数: {len(self.graph.nodes)}\n"
        report += f"- 执行的调查步骤数: {len(self.investigation_steps)}\n\n"

        report += "## 攻击时间线\n"
        for entry in self.state.narrative_log:
            report += f"- {entry}\n"

        report += "\n## 攻击图拓扑\n"
        report += f"```\n"
        for edge in self.graph.edges:
            report += f"{edge[0]} --> {edge[1]}\n"
        report += "```\n"

        report += "\n## 观察到的 MITRE ATT&CK 技术\n"
        techniques = set()

        for src, dst, edge_data in self.graph.edges(data=True):
            technique = edge_data.get('mitre_technique')
            if technique:
                techniques.add(technique)

        for ttp in self.ttp_chain:
            tech = ttp.get('technique')
            if tech:
                techniques.add(tech)

        if techniques:
            for technique in sorted(techniques):
                report += f"- {technique}\n"
        else:
            report += "- （未识别到 MITRE 技术）\n"

        return report

    def export_to_dot(self, output_path: str = "attack_graph.dot") -> str:
        lines = [
            'digraph AttackGraph {',
            '    rankdir=TB;',
            '    node [fontname="Arial"];',
            ''
        ]
        
        shape_map = {
            'process': 'ellipse',
            'file': 'box',
            'network': 'diamond',
            'unknown': 'ellipse'
        }
        
        nodes_by_type = {'process': [], 'file': [], 'network': [], 'unknown': []}
        
        for node_id in self.graph.nodes:
            node_data = self.graph.nodes[node_id]
            name = node_data.get('name', 'Unknown')
            node_type = node_data.get('node_type', 'unknown').lower()
            
            if node_type in ['process', 'proc']:
                node_type = 'process'
            elif node_type in ['file', 'path']:
                node_type = 'file'
            elif node_type in ['network', 'socket', 'ip', 'addr']:
                node_type = 'network'
            else:
                node_type = 'unknown'
            
            nodes_by_type[node_type].append((name, node_id))
        
        for node_type, nodes in nodes_by_type.items():
            if nodes:
                lines.append(f'    // {node_type.upper()} 节点')
                shape = shape_map[node_type]
                for name, node_id in nodes:

                    safe_name = name.replace('"', '\\"')
                    lines.append(f'    "{safe_name}" [shape={shape}];')
                lines.append('')
        
        lines.append('    // 恶意事件边')
        for edge in self.graph.edges:
            source_id, target_id = edge
            edge_data = self.graph.edges[edge]
            
            source_name = self.graph.nodes[source_id].get('name', 'Unknown') if source_id in self.graph.nodes else 'Unknown'
            target_name = self.graph.nodes[target_id].get('name', 'Unknown') if target_id in self.graph.nodes else 'Unknown'
            
            event_type = edge_data.get('event_type', 'related')

            label = event_type.lower().replace('event_', '')
            
            safe_source = source_name.replace('"', '\\"')
            safe_target = target_name.replace('"', '\\"')
            
            lines.append(f'    "{safe_source}" -> "{safe_target}" [label="{label}"];')
        
        lines.append('}')
        
        dot_content = '\n'.join(lines)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(dot_content)
        
        print(f"  ✓ 攻击图已导出: {output_path}")
        return output_path

    def export_state(self) -> dict:

        attack_graph = {
            "nodes": [],
            "edges": []
        }
        
        for node_id, data in self.graph.nodes(data=True):
            attack_graph["nodes"].append({
                "id": node_id,
                "name": data.get("name", "Unknown"),
                "type": data.get("type", "Unknown"),
                "properties": data.get("properties", {})
            })
        
        for source, target, data in self.graph.edges(data=True):
            attack_graph["edges"].append({
                "source": source,
                "target": target,
                "event_id": data.get("event_id", ""),
                "event_type": data.get("event_type", "")
            })
        
        memory_context = {
            "attack_summary": self.attack_summary,
            "ttp_chain": self.ttp_chain.copy(),
            "state": {
                "narrative_log": self.state.narrative_log,
                "confirmed_malicious": list(self.state.attack_nodes),
                "pending_investigation": []
            }
        }
        
        poi = {
            "event_id": self.initial_poi,
            "details": self.poi_details
        }
        
        investigation_history = self.investigation_steps.copy()
        
        evaluated_events = set()
        for step in self.investigation_steps:
            if "evaluated_event_ids" in step:
                evaluated_events.update(step["evaluated_event_ids"])
            if "event_id" in step:
                evaluated_events.add(step["event_id"])
        
        return {
            "poi": poi,
            "attack_graph": attack_graph,
            "memory_context": memory_context,
            "evaluated_events": evaluated_events,
            "investigation_history": investigation_history
        }
    
    def import_state(self, state: dict) -> bool:
        try:

            poi = state.get("poi", {})
            self.initial_poi = poi.get("event_id", "")
            self.poi_details = poi.get("details")
            
            attack_graph = state.get("attack_graph", {})
            self.graph = nx.DiGraph()
            
            for node in attack_graph.get("nodes", []):
                self.graph.add_node(
                    node["id"],
                    name=node.get("name", "Unknown"),
                    type=node.get("type", "Unknown"),
                    properties=node.get("properties", {})
                )
            
            for edge in attack_graph.get("edges", []):
                self.graph.add_edge(
                    edge["source"],
                    edge["target"],
                    event_id=edge.get("event_id", ""),
                    event_type=edge.get("event_type", "")
                )
            
            memory_context = state.get("memory_context", {})
            self.attack_summary = memory_context.get("attack_summary", "")
            self.ttp_chain = memory_context.get("ttp_chain", [])
            
            state_data = memory_context.get("state", {})

            narrative_log = state_data.get("narrative_log", [])
            if isinstance(narrative_log, str):
                narrative_log = [narrative_log] if narrative_log else []
            self.state.narrative_log = narrative_log
            
            confirmed = state_data.get("confirmed_malicious", [])
            self.state.attack_nodes = list(confirmed) if confirmed else []
            
            self.investigation_steps = state.get("investigation_history", [])
            
            console.print(f"[green]✓ 调查状态已恢复[/green]")
            console.print(f"  • 攻击子图: {len(self.graph.nodes())} 节点, {len(self.graph.edges())} 边")
            console.print(f"  • 调查步骤: {len(self.investigation_steps)} 步")
            
            return True
            
        except Exception as e:
            console.print(f"[red]❌ 恢复状态失败: {e}[/red]")
            return False
    
    def get_evaluated_event_ids(self) -> set:
        evaluated = set()
        for step in self.investigation_steps:
            if "evaluated_event_ids" in step:
                evaluated.update(step["evaluated_event_ids"])
            if "event_id" in step:
                evaluated.add(step["event_id"])

        evaluated.update(self.state.attack_nodes)
        return evaluated
    
    def add_investigation_step(self, iteration: int, action: str, result: str, 
                                evaluated_event_ids: list = None):
        step = {
            "iteration": iteration,
            "action": action,
            "result": result,
            "evaluated_event_ids": evaluated_event_ids or []
        }
        self.investigation_steps.append(step)
