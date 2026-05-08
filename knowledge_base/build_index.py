#!/usr/bin/env python3
"""
CTI 知识库索引构建脚本

读取 CTI 报告，按段落分 chunk，生成嵌入向量，保存索引文件。

使用方法：
    python build_index.py

输出：
    cti_index.pkl - 包含嵌入向量、原文和 BM25 索引的 pickle 文件
"""

import os
import pickle
import re
from pathlib import Path
from typing import List, Dict
import dashscope
from dashscope import TextEmbedding
from rank_bm25 import BM25Okapi
import jieba
import json

# 导入配置并设置 API Key
import sys
sys.path.append(str(Path(__file__).parent.parent))
import config
dashscope.api_key = config.LLM_API_KEY

# 配置
CTI_DIR = Path(__file__).parent / "cti_reports"
INDEX_FILE = Path(__file__).parent / "cti_index.pkl"
EMBEDDING_MODEL = "text-embedding-v2"
KNOWLEDGE_DIR = Path(__file__).parent


def load_cti_files(cti_dir: Path) -> List[Dict[str, str]]:
    """
    加载所有 CTI txt 文件。
    
    Returns:
        文件列表，每个元素包含 filename 和 content
    """
    files = []
    for txt_file in sorted(cti_dir.glob("*.txt")):
        with open(txt_file, "r", encoding="utf-8") as f:
            content = f.read()
        files.append({
            "filename": txt_file.name,
            "content": content
        })
        print(f"  ✓ 加载: {txt_file.name}")
    return files


def split_into_chunks(files: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """
    将文件内容按段落分割成 chunks。
    
    分割策略：以连续的空行为分隔符。
    
    Returns:
        chunk 列表，每个元素包含 source（来源文件）和 text（内容）
    """
    chunks = []
    for file_info in files:
        filename = file_info["filename"]
        content = file_info["content"]
        
        # 按连续空行分割段落
        paragraphs = re.split(r'\n\s*\n', content)
        
        for para in paragraphs:
            text = para.strip()
            # 过滤太短的段落（少于 50 字符）
            if len(text) < 50:
                continue
            chunks.append({
                "source": filename,
                "text": text,
                "source_type": "CTI"
            })
    
    print(f"  共分割出 {len(chunks)} 个 CTI chunks")
    return chunks

def load_knowledge_bases() -> List[Dict[str, str]]:
    kb_chunks = []
    
    # 1. MITRE
    mitre_file = KNOWLEDGE_DIR / "mitre_ttps.json"
    if mitre_file.exists():
        with open(mitre_file, "r", encoding="utf-8") as f:
            mitre_data = json.load(f)
            
        for item in mitre_data:
            text = f"MITRE Technique {item['id']} ({item['name']}): {item['description']} Example: {item['example']}"
            kb_chunks.append({
                "source": item['id'],
                "source_type": "MITRE",
                "text": text
            })
        print(f"  ✓ 加载: {len(mitre_data)} 条 MITRE 技术")
        
    return kb_chunks


def generate_embeddings(chunks: List[Dict[str, str]]) -> List[List[float]]:
    """
    调用 DashScope text-embedding-v2 生成嵌入向量。
    
    Returns:
        嵌入向量列表
    """
    embeddings = []
    batch_size = 10  # DashScope 支持批量处理
    
    texts = [chunk["text"] for chunk in chunks]
    
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        print(f"  生成嵌入: {i+1}-{min(i+batch_size, len(texts))}/{len(texts)}")
        
        response = TextEmbedding.call(
            model=EMBEDDING_MODEL,
            input=batch
        )
        
        if response.status_code != 200:
            raise Exception(f"Embedding API 调用失败: {response.message}")
        
        for item in response.output["embeddings"]:
            embeddings.append(item["embedding"])
    
    return embeddings


def build_bm25_index(chunks: List[Dict[str, str]]) -> BM25Okapi:
    """
    构建 BM25 关键字索引。
    
    使用 jieba 分词。
    
    Returns:
        BM25Okapi 索引对象
    """
    # 分词
    tokenized_corpus = []
    for chunk in chunks:
        # 中英文混合分词
        tokens = list(jieba.cut(chunk["text"]))
        # 过滤停用词和短词
        tokens = [t.lower() for t in tokens if len(t) > 1]
        tokenized_corpus.append(tokens)
    
    bm25 = BM25Okapi(tokenized_corpus)
    print(f"  BM25 索引构建完成")
    return bm25


def save_index(chunks: List[Dict[str, str]], 
               embeddings: List[List[float]], 
               bm25: BM25Okapi,
               output_path: Path):
    """
    保存索引到 pickle 文件。
    """
    index_data = {
        "chunks": chunks,           # 原始文本和来源
        "embeddings": embeddings,   # 嵌入向量
        "bm25": bm25,               # BM25 索引
        "version": "1.0"
    }
    
    with open(output_path, "wb") as f:
        pickle.dump(index_data, f)
    
    print(f"  索引已保存: {output_path}")
    print(f"    - Chunks: {len(chunks)}")
    print(f"    - 嵌入维度: {len(embeddings[0]) if embeddings else 0}")


def main():
    print("=" * 60)
    print("CTI 知识库索引构建")
    print("=" * 60)
    
    # 检查 CTI 目录
    if not CTI_DIR.exists():
        print(f"❌ CTI 目录不存在: {CTI_DIR}")
        return
    
    # 1. 加载文件
    print("\n[1/4] 加载 CTI 文件...")
    files = load_cti_files(CTI_DIR)
    print(f"  共加载 {len(files)} 个文件")
    
    # 2. 分割 chunks 和加载知识库
    print("\n[2/4] 准备知识库 chunks...")
    chunks = split_into_chunks(files)
    
    kb_chunks = load_knowledge_bases()
    chunks.extend(kb_chunks)
    print(f"  合并后共 {len(chunks)} 个 chunks")
    
    # 3. 生成嵌入
    print("\n[3/4] 生成嵌入向量...")
    embeddings = generate_embeddings(chunks)
    
    # 4. 构建 BM25 索引
    print("\n[4/4] 构建 BM25 索引...")
    bm25 = build_bm25_index(chunks)
    
    # 5. 保存索引
    print("\n保存索引文件...")
    save_index(chunks, embeddings, bm25, INDEX_FILE)
    
    print("\n✓ 索引构建完成！")


if __name__ == "__main__":
    main()
