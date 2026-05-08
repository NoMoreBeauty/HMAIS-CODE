
import pickle
import numpy as np
from pathlib import Path
from typing import List, Optional, Dict, Any
import dashscope
from dashscope import TextEmbedding
import jieba
from rich.console import Console
import config

dashscope.api_key = config.LLM_API_KEY

console = Console()

INDEX_FILE = Path(__file__).parent.parent.parent / "knowledge_base" / "cti_index.pkl"
EMBEDDING_MODEL = "text-embedding-v2"

class RAGRetriever:
    
    def __init__(self, index_path: Path = None):
        self.index_path = index_path or INDEX_FILE
        self.chunks = []
        self.embeddings = []
        self.bm25 = None
        self._loaded = False
        
    def load_index(self) -> bool:
        if self._loaded:
            return True
            
        if not self.index_path.exists():
            console.print(f"[yellow]⚠️ CTI 索引文件不存在: {self.index_path}[/yellow]")
            console.print("[yellow]   请先运行 build_index.py 构建索引[/yellow]")
            return False
        
        try:
            with open(self.index_path, "rb") as f:
                index_data = pickle.load(f)
            
            self.chunks = index_data["chunks"]
            self.embeddings = np.array(index_data["embeddings"])
            self.bm25 = index_data["bm25"]
            self._loaded = True
            
            console.print(f"[green]✓ CTI 索引已加载: {len(self.chunks)} chunks[/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]❌ 加载索引失败: {e}[/red]")
            return False
    
    def search(self, 
               narrative_context: str, 
               keywords: List[str],
               top_k: int = 3) -> Optional[Dict[str, Any]]:
        if not self._loaded:
            if not self.load_index():
                return None
        
        if not self.chunks:
            return None
        
        alpha = 0.5
        
        embedding_scores = self._embedding_search(narrative_context)
        
        bm25_scores = self._bm25_search(keywords)
        
        embedding_scores_norm = self._normalize_scores(embedding_scores)
        bm25_scores_norm = self._normalize_scores(bm25_scores)
        
        final_scores = alpha * embedding_scores_norm + (1 - alpha) * bm25_scores_norm
        
        top_indices = np.argsort(final_scores)[::-1]
        
        results_cti = []
        results_mitre = []
        
        for idx in top_indices:
            if len(results_cti) >= top_k and len(results_mitre) >= top_k:
                break
                
            chunk = self.chunks[idx]
            source_type = chunk.get("source_type", "CTI")
            
            item = {
                "text": chunk["text"],
                "source": chunk["source"],
                "source_type": source_type,
                "score": float(final_scores[idx]),
                "embedding_score": float(embedding_scores_norm[idx]),
                "bm25_score": float(bm25_scores_norm[idx])
            }
            
            if source_type == "CTI" and len(results_cti) < top_k:
                results_cti.append(item)
            elif source_type == "MITRE" and len(results_mitre) < top_k:
                results_mitre.append(item)
        
        results = results_cti + results_mitre
        
        return results
    
    def _embedding_search(self, query: str) -> np.ndarray:

        response = TextEmbedding.call(
            model=EMBEDDING_MODEL,
            input=[query]
        )
        
        if response.status_code != 200:
            console.print(f"[red]嵌入 API 调用失败: {response.message}[/red]")
            return np.zeros(len(self.chunks))
        
        query_embedding = np.array(response.output["embeddings"][0]["embedding"])
        
        query_norm = np.linalg.norm(query_embedding)
        doc_norms = np.linalg.norm(self.embeddings, axis=1)
        
        doc_norms = np.where(doc_norms == 0, 1e-10, doc_norms)
        
        similarities = np.dot(self.embeddings, query_embedding) / (doc_norms * query_norm)
        
        return similarities
    
    def _bm25_search(self, keywords: List[str]) -> np.ndarray:
        if not keywords or self.bm25 is None:
            return np.zeros(len(self.chunks))
        
        query_text = " ".join(keywords)
        query_tokens = list(jieba.cut(query_text))
        query_tokens = [t.lower() for t in query_tokens if len(t) > 1]
        
        scores = self.bm25.get_scores(query_tokens)
        
        return np.array(scores)
    
    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        if len(scores) == 0:
            return scores
            
        min_score = np.min(scores)
        max_score = np.max(scores)
        
        if max_score == min_score:
            return np.ones_like(scores) * 0.5
        
        return (scores - min_score) / (max_score - min_score)

_retriever_instance = None

def get_retriever() -> RAGRetriever:
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = RAGRetriever()
    return _retriever_instance
