
import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
import json
from pathlib import Path
from enum import Enum

class CitationType(Enum):
    CTI = "CTI"
    MITRE = "MITRE"
    KNOWN = "KNOWN"
    SUSPECT = "SUSPECT"

class VerificationStatus(Enum):
    VERIFIED = "✅"
    UNVERIFIED = "⚠️"
    INFERRED = "ℹ️"
    INVALID = "❌"

@dataclass
class Citation:
    index: int
    citation_type: CitationType
    source: str
    excerpt: Optional[str]
    status: VerificationStatus
    message: str = ""

@dataclass
class ValidationResult:
    original_text: str
    citations: List[Citation]
    verified_count: int
    unverified_count: int
    inferred_count: int
    
    @property
    def summary(self) -> str:
        total = len(self.citations)
        if total == 0:
            return "无引用"
        return f"{self.verified_count}✅ {self.unverified_count}⚠️ {self.inferred_count}ℹ️ / {total} 引用"

class CitationValidator:
    
    MITRE_PATTERN = re.compile(r'^T\d{4}(?:\.\d{3})?$')
    
    CITATION_REF_PATTERN = re.compile(r'\[(\d+)\]')
    
    SOURCE_PATTERN = re.compile(
        r'\[(\d+)\]\s*(CTI|MITRE|KNOWN):\s*(.+?)(?:\s*[-–—]\s*["""\'](.+?)["""\'])?(?:\s*$|\s*\n|\s*\[)',
        re.IGNORECASE | re.MULTILINE
    )
    
    def __init__(self, cti_sources: List[str] = None):
        self.cti_sources = set(cti_sources or [])
        
        self.valid_mitre_ids = set()
        mitre_file = Path(__file__).parent.parent.parent / "knowledge_base" / "mitre_ttps.json"
        if mitre_file.exists():
            try:
                with open(mitre_file, "r") as f:
                    mitre_data = json.load(f)
                    for item in mitre_data:
                        self.valid_mitre_ids.add(item["id"])
            except Exception:
                pass
    
    def set_cti_sources(self, sources: List[str]):
        self.cti_sources = set(sources)
    
    def validate(self, text: str) -> ValidationResult:
        citations = self._parse_citations(text)
        
        for citation in citations:
            self._verify_citation(citation)
        
        verified = sum(1 for c in citations if c.status == VerificationStatus.VERIFIED)
        unverified = sum(1 for c in citations if c.status in [VerificationStatus.UNVERIFIED, VerificationStatus.INVALID])
        inferred = sum(1 for c in citations if c.status == VerificationStatus.INFERRED)
        
        return ValidationResult(
            original_text=text,
            citations=citations,
            verified_count=verified,
            unverified_count=unverified,
            inferred_count=inferred
        )
    
    def _parse_citations(self, text: str) -> List[Citation]:
        citations = []
        
        for match in self.SOURCE_PATTERN.finditer(text):
            index = int(match.group(1))
            type_str = match.group(2).upper()
            source = match.group(3).strip()
            excerpt = match.group(4).strip() if match.group(4) else None
            
            try:
                citation_type = CitationType(type_str)
            except ValueError:
                citation_type = CitationType.SUSPECT
            
            citations.append(Citation(
                index=index,
                citation_type=citation_type,
                source=source,
                excerpt=excerpt,
                status=VerificationStatus.UNVERIFIED
            ))
        
        return citations
    
    def _verify_citation(self, citation: Citation):
        
        if citation.citation_type == CitationType.CTI:
            self._verify_cti(citation)
        
        elif citation.citation_type == CitationType.MITRE:
            self._verify_mitre(citation)
        
        elif citation.citation_type == CitationType.KNOWN:

            citation.status = VerificationStatus.INFERRED
            citation.message = "LLM 推断的已知攻击模式"
        
        else:
            citation.status = VerificationStatus.INVALID
            citation.message = f"未知引用类型: {citation.citation_type}"
    
    def _verify_cti(self, citation: Citation):
        source = citation.source.strip()
        
        if source in self.cti_sources:
            citation.status = VerificationStatus.VERIFIED
            citation.message = "CTI 来源已验证"
        else:

            source_with_txt = source if source.endswith('.txt') else source + '.txt'
            source_without_txt = source[:-4] if source.endswith('.txt') else source
            
            if source_with_txt in self.cti_sources or source_without_txt in self.cti_sources:
                citation.status = VerificationStatus.VERIFIED
                citation.message = "CTI 来源已验证"
            else:
                citation.status = VerificationStatus.UNVERIFIED
                citation.message = f"CTI 来源 '{source}' 未在检索结果中找到"
    
    def _verify_mitre(self, citation: Citation):
        source = citation.source.strip()
        
        tech_id_match = re.match(r'(T\d{4}(?:\.\d{3})?)', source)
        
        if tech_id_match:
            tech_id = tech_id_match.group(1)
            if self.MITRE_PATTERN.match(tech_id):
                if not self.valid_mitre_ids or tech_id in self.valid_mitre_ids:
                    citation.status = VerificationStatus.VERIFIED
                    citation.message = f"MITRE 技术 ID {tech_id} 验证通过"
                else:
                    citation.status = VerificationStatus.UNVERIFIED
                    citation.message = f"MITRE 技术 ID {tech_id} 在知识库中不存在"
            else:
                citation.status = VerificationStatus.INVALID
                citation.message = f"MITRE 技术 ID 格式无效: {tech_id}"
        else:
            citation.status = VerificationStatus.UNVERIFIED
            citation.message = f"无法识别 MITRE 技术 ID: {source}"
    
    def format_validation_report(self, result: ValidationResult) -> str:
        if not result.citations:
            return "📋 引用验证: 无引用"
        
        lines = [f"📋 引用验证: {result.summary}"]
        
        for c in result.citations:
            status_icon = c.status.value
            type_str = c.citation_type.value
            excerpt_str = f' - "{c.excerpt[:50]}..."' if c.excerpt and len(c.excerpt) > 50 else (f' - "{c.excerpt}"' if c.excerpt else '')
            lines.append(f"  [{c.index}] {status_icon} {type_str}: {c.source}{excerpt_str}")
            if c.message and c.status != VerificationStatus.VERIFIED:
                lines.append(f"      └─ {c.message}")
        
        return "\n".join(lines)

def validate_citations(text: str, cti_sources: List[str] = None) -> ValidationResult:
    validator = CitationValidator(cti_sources)
    return validator.validate(text)
