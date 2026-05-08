
from typing import List, Dict, Any
from rich.console import Console
from hmais.models.data_models import Event, SuspicionLevel

console = Console()

class FilterAgent:

    def __init__(self):

        self.whitelist_hashes = {
            "abc123def456",
            "789ghi012jkl"
        }

        self.system_binaries = {
            "svchost.exe",
            "conhost.exe",
            "csrss.exe",
            "lsass.exe"
        }
        
        self.internal_networks = [
            "10.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "192.168.",
            "127.",
        ]
    
    def _is_internal_ip(self, ip_str: str) -> bool:
        if not ip_str:
            return False
            
        ip_part = ip_str.split(":")[0] if ":" in ip_str else ip_str
        
        for prefix in self.internal_networks:
            if ip_part.startswith(prefix):
                return True
        return False

    def scan(self, raw_events: List[Dict[str, Any]], known_event_ids: set = None) -> List[Event]:
        if known_event_ids is None:
            known_event_ids = set()
            
        print(f"\n🔬 Filter Agent: 扫描 {len(raw_events)} 条事件")

        suspicious_events = []
        skipped_known = 0

        for idx, raw_event in enumerate(raw_events):

            parsed_event = self._parse_neo4j_result(raw_event, idx)
            event_id = parsed_event.get("event_id", f"event_{idx}")

            if event_id in known_event_ids:
                skipped_known += 1
                continue

            event = Event(
                event_id=event_id,
                event_type=parsed_event.get("event_type", "Unknown"),
                timestamp=parsed_event.get("timestamp", "unknown"),
                properties=parsed_event
            )
            
            event_type = parsed_event.get("event_type", "").upper()
            if "SENDTO" in event_type or "RECVFROM" in event_type:
                target_name = parsed_event.get("target_name", "")
                source_name = parsed_event.get("source_name", "")
                
                if "SENDTO" in event_type:
                    is_internal = self._is_internal_ip(target_name)
                    ip_for_check = target_name
                else:
                    is_internal = self._is_internal_ip(source_name)
                    ip_for_check = source_name
                
                event.properties["is_internal_ip"] = is_internal
                event.properties["ip_context"] = "内网通信" if is_internal else "外网通信"

            suspicion = self._apply_heuristics(event)
            event.suspicion_level = suspicion

            if suspicion != SuspicionLevel.BENIGN:
                source_name = parsed_event.get('source_name', 'Unknown')
                target_name = parsed_event.get('target_name', 'Unknown')
                event_type = parsed_event.get('event_type', '')
                print(f"  → {source_name} -[{event_type}]-> {target_name}: {suspicion.value}")
                suspicious_events.append(event)

        if skipped_known > 0:
            print(f"  ⏭️  跳过 {skipped_known} 条已知恶意事件")
        print(f"  ✓ {len(suspicious_events)}/{len(raw_events)} 可疑")
        return suspicious_events

    def _parse_neo4j_result(self, raw_event: Dict[str, Any], idx: int) -> Dict[str, Any]:
        import json
        
        if 's' in raw_event and 'r' in raw_event:
            s_node = raw_event.get('s', {})
            r_rel = raw_event.get('r', {})
            t_node = raw_event.get('t', {})
            
            rel_props = r_rel if isinstance(r_rel, dict) else {}
            
            return {
                "event_id": rel_props.get("event_uuid", f"event_{idx}"),
                "event_type": rel_props.get("event_type_raw", "Unknown"),
                "event_name": rel_props.get("event_name", "Unknown"),
                "timestamp": rel_props.get("event_timestampNanos", "unknown"),

                "source_name": s_node.get("name", "Unknown") if isinstance(s_node, dict) else "Unknown",
                "source_type": s_node.get("type", "Unknown") if isinstance(s_node, dict) else "Unknown",
                "source_uuid": rel_props.get("start_node_uuid", ""),

                "target_name": t_node.get("name", "Unknown") if isinstance(t_node, dict) else "Unknown",
                "target_type": t_node.get("type", "Unknown") if isinstance(t_node, dict) else "Unknown",
                "target_uuid": rel_props.get("end_node_uuid", ""),

                "properties_json": rel_props.get("properties_json", "{}"),
                "parameters_json": rel_props.get("parameters_json", "{}"),
                "hostId": rel_props.get("hostId", ""),
            }
        else:

            return raw_event

    def _apply_heuristics(self, event: Event) -> SuspicionLevel:
        props = event.properties

        if props.get("hash") in self.whitelist_hashes:
            return SuspicionLevel.BENIGN

        name = props.get("name", "").lower()
        path = props.get("path", "").lower()
        cmdline = props.get("command_line", "").lower()

        if name in self.system_binaries and "c:\\windows\\system32" in path:
            if not any(keyword in cmdline for keyword in ["encoded", "http://", "bitsadmin", "download"]):
                return SuspicionLevel.BENIGN

        if any(keyword in cmdline for keyword in ["encoded", "bitsadmin", "http://", "powershell", "-w hidden"]):
            return SuspicionLevel.SUSPICIOUS

        return SuspicionLevel.UNKNOWN
