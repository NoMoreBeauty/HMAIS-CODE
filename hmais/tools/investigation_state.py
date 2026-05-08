
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
from rich.console import Console

console = Console()

STATE_FILE = "investigation_state.json"
STATE_VERSION = "1.0"

def save_state(session_dir: str, state_data: Dict[str, Any]) -> bool:
    try:
        session_path = Path(session_dir)
        if not session_path.exists():
            console.print(f"[red]❌ 会话目录不存在: {session_dir}[/red]")
            return False
        
        state_file = session_path / STATE_FILE
        
        full_state = {
            "version": STATE_VERSION,
            "saved_at": datetime.now().isoformat(),
            "session_dir": str(session_path.absolute()),
            **state_data
        }
        
        if "evaluated_events" in full_state and isinstance(full_state["evaluated_events"], set):
            full_state["evaluated_events"] = list(full_state["evaluated_events"])
        
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(full_state, f, ensure_ascii=False, indent=2)
        
        console.print(f"[green]✓ 调查状态已保存: {state_file}[/green]")
        return True
        
    except Exception as e:
        console.print(f"[red]❌ 保存状态失败: {e}[/red]")
        return False

def load_state(session_dir: str) -> Optional[Dict[str, Any]]:
    try:
        session_path = Path(session_dir)
        state_file = session_path / STATE_FILE
        
        if not state_file.exists():
            console.print(f"[red]❌ 状态文件不存在: {state_file}[/red]")
            console.print("[yellow]提示: 请确认该目录是一个有效的调查会话[/yellow]")
            return None
        
        with open(state_file, "r", encoding="utf-8") as f:
            state = json.load(f)
        
        version = state.get("version")
        if version is not None and version != STATE_VERSION:
            console.print(f"[yellow]⚠️ 状态文件版本不匹配: {version} (当前: {STATE_VERSION})[/yellow]")
        
        if "evaluated_events" in state and isinstance(state["evaluated_events"], list):
            state["evaluated_events"] = set(state["evaluated_events"])
        
        console.print(f"[green]✓ 调查状态已加载: {state_file}[/green]")
        console.print(f"  • 保存时间: {state.get('saved_at', 'Unknown')}")
        console.print(f"  • 已评估事件数: {len(state.get('evaluated_events', []))}")
        
        return state
        
    except json.JSONDecodeError as e:
        console.print(f"[red]❌ 状态文件格式错误: {e}[/red]")
        return None
    except Exception as e:
        console.print(f"[red]❌ 加载状态失败: {e}[/red]")
        return None

def format_investigation_summary(state: Dict[str, Any]) -> str:
    lines = ["=== 上次调查摘要 ==="]
    
    poi = state.get("poi", {})
    if poi:
        lines.append(f"\nPOI: {poi.get('event_type', 'Unknown')} ({poi.get('event_id', 'Unknown')})")
    
    attack_graph = state.get("attack_graph", {})
    nodes = attack_graph.get("nodes", [])
    edges = attack_graph.get("edges", [])
    if nodes:
        lines.append(f"\n攻击子图: {len(nodes)} 节点, {len(edges)} 边")
        for node in nodes[:5]:
            lines.append(f"  • {node.get('name', 'Unknown')} ({node.get('type', 'Unknown')})")
        if len(nodes) > 5:
            lines.append(f"  ... 及其他 {len(nodes) - 5} 个节点")
    
    memory = state.get("memory_context", {})
    attack_summary = memory.get("attack_summary", "") or state.get("narrative_summary", "")
    if attack_summary:
        lines.append(f"\n攻击摘要: {attack_summary[:200]}...")
    
    evaluated = state.get("evaluated_events", set())
    if evaluated:
        lines.append(f"\n已评估事件数: {len(evaluated)}")
    
    history = state.get("investigation_history", []) or state.get("action_history", [])
    if history:
        lines.append(f"\n调查历史 ({len(history)} 步):")
        for item in history[-3:]:
            lines.append(f"  • 迭代 {item.get('iteration', '?')}: {item.get('action', 'Unknown')[:50]}...")
    
    return "\n".join(lines)
