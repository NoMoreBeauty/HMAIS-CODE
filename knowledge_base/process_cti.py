#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
此脚本用于处理当前目录下的所有 .txt CTI 报告。
它会执行以下操作：
1. 查找所有 .txt 文件。
2. 读取每个文件的内容。
3. 使用阿里云 DashScope 的 LLM (deepseek-r1) 提取报告标题和 MITRE ATT&CK 技术。
4. 并发执行所有 API 调用。
5. 将结果汇总并写入一个 'metadata.json' 文件。

如何运行:
1. 安装依赖: pip install dashscope loguru anthropic
2. 设置 API Key: export DASHSCOPE_API_KEY='sk-your_actual_api_key'
3. 运行脚本: python process_cti.py
"""

import os
import json
import glob
import asyncio
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from loguru import logger
from http import HTTPStatus
import dashscope
from dashscope import Generation
from dashscope.api_entities.dashscope_response import Role

# ----------------------------------------------------------------------------
# 1. 配置类 (替代你代码中的 from ..config import LLMConfig)
# ----------------------------------------------------------------------------
@dataclass
class LLMConfig:
    """LLM 客户端的配置"""
    provider: str
    api_key: str
    model: str
    max_tokens: int = 4096
    temperature: float = 0.1
    max_retries: int = 3
    max_concurrent_requests: int = 5

# ----------------------------------------------------------------------------
# 2. 你提供的 LLMClient 类 (已集成)
# ----------------------------------------------------------------------------
# 导入 anthropic 以便 LLMClient 类能正常工作
try:
    from anthropic import Anthropic, AsyncAnthropic
except ImportError:
    logger.warning("anthropic SDK 未安装。如果只使用 dashscope, 可以忽略此消息。")
    # 创建假的类以防万一
    class Anthropic: pass
    class AsyncAnthropic: pass

class LLMClient:
    """
    Unified LLM API client.
    Supports Anthropic Claude and Alibaba DashScope.
    """

    def __init__(self, config: LLMConfig):
        """
        Initialize LLM client.

        Args:
            config: LLM configuration
        """
        self.config = config

        if config.provider == "anthropic":
            self.client = Anthropic(api_key=config.api_key)
            self.async_client = AsyncAnthropic(api_key=config.api_key)
        elif config.provider == "dashscope":
            # DashScope SDK 倾向于使用全局 API Key
            dashscope.api_key = config.api_key
            # DashScope SDK 没有分离的 client 实例
            self.client = None
            self.async_client = None
        else:
            raise ValueError(f"Unsupported LLM provider: {config.provider}. Supported: [anthropic, dashscope]")

        logger.info(f"LLM client initialized: {config.provider} / {config.model}")

    def _build_dashscope_messages(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> list:
        """Helper to build message list for DashScope."""
        messages = []
        if system_prompt:
            messages.append({"role": Role.SYSTEM, "content": system_prompt})
        messages.append({"role": Role.USER, "content": prompt})
        return messages

    def _dashscope_sync_call(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Private helper for a single synchronous DashScope call.
        This function does NOT handle retries, it's called BY the retry loops.
        """
        messages = self._build_dashscope_messages(prompt, system_prompt)
        
        # DashScope 将 max_tokens 放在 parameters 字典中
        parameters = {}
        if max_tokens:
            parameters["max_tokens"] = max_tokens
        
        # DashScope 的 temperature 范围是 (0, 2)，设置一个合理的默认值
        temp_for_call = temperature if temperature is not None else 0.1
        if temp_for_call == 0.0:
            temp_for_call = 0.01 # DashScope 不允许为 0

        response = Generation.call(
            model=self.config.model,
            messages=messages,
            temperature=temp_for_call,
            parameters=parameters,
            result_format="message",  # 确保返回格式一致
        )

        if response.status_code == HTTPStatus.OK:
            # 确保返回的是字符串内容
            content = response.output.choices[0].message.content
            # 移除潜在的代码块标记
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            return content.strip()
        else:
            # 抛出异常，由外层重试循环捕获
            raise Exception(f"DashScope API error: {response.code} - {response.message}")

    def call(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Synchronous LLM API call.
        """
        max_tokens = max_tokens or self.config.max_tokens
        temperature = temperature if temperature is not None else self.config.temperature

        for attempt in range(self.config.max_retries):
            try:
                text = ""
                if self.config.provider == "anthropic":
                    messages = [{"role": "user", "content": prompt}]
                    kwargs = {
                        "model": self.config.model,
                        "messages": messages,
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                    }
                    if system_prompt:
                        kwargs["system"] = system_prompt
                    
                    response = self.client.messages.create(**kwargs)
                    text = response.content[0].text
                
                elif self.config.provider == "dashscope":
                    text = self._dashscope_sync_call(
                        prompt, system_prompt, max_tokens, temperature
                    )

                logger.debug(f"LLM call successful (attempt {attempt + 1})")
                return text

            except Exception as e:
                logger.warning(f"LLM call failed (attempt {attempt + 1}/{self.config.max_retries}): {e}")
                if attempt < self.config.max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"LLM call failed after {self.config.max_retries} attempts")
                    raise

        raise RuntimeError("LLM call failed")

    async def call_async(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """
        Asynchronous LLM API call.
        """
        max_tokens = max_tokens or self.config.max_tokens
        temperature = temperature if temperature is not None else self.config.temperature


        for attempt in range(self.config.max_retries):
            try:
                text = ""
                if self.config.provider == "anthropic":
                    messages = [{"role": "user", "content": prompt}]
                    kwargs = {
                        "model": self.config.model,
                        "messages": messages,
                        "max_tokens": max_tokens,
                        "temperature": temperature,
                    }
                    if system_prompt:
                        kwargs["system"] = system_prompt

                    response = await self.async_client.messages.create(**kwargs)
                    text = response.content[0].text
                
                elif self.config.provider == "dashscope":
                    # 在线程中运行同步的 DashScope 调用
                    text = await asyncio.to_thread(
                        self._dashscope_sync_call,
                        prompt,
                        system_prompt,
                        max_tokens,
                        temperature
                    )

                logger.debug(f"Async LLM call successful (attempt {attempt + 1})")
                return text

            except Exception as e:
                logger.warning(f"Async LLM call failed (attempt {attempt + 1}/{self.config.max_retries}): {e}")
                if attempt < self.config.max_retries - 1:
                    wait_time = 2 ** attempt
                    logger.info(f"Retrying in {wait_time} seconds...")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"Async LLM call failed after {self.config.max_retries} attempts")
                    raise

        raise RuntimeError("Async LLM call failed")

    async def call_batch_async(
        self,
        prompts: list[str],
        system_prompt: Optional[str] = None,
        max_concurrent: Optional[int] = None,
    ) -> list[str]:
        """
        Batch asynchronous LLM calls with concurrency control.
        """
        max_concurrent = max_concurrent or self.config.max_concurrent_requests

        semaphore = asyncio.Semaphore(max_concurrent)

        async def call_with_semaphore(prompt: str) -> str:
            async with semaphore:
                return await self.call_async(prompt, system_prompt)

        tasks = [call_with_semaphore(prompt) for prompt in prompts]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理在 gather 中捕获的异常
        processed_responses = []
        for i, res in enumerate(responses):
            if isinstance(res, Exception):
                logger.error(f"Task {i} failed in batch: {res}")
                processed_responses.append(f'{{"error": "LLM call failed: {res}"}}') # 返回一个错误 JSON
            else:
                processed_responses.append(res)

        return processed_responses

    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count (rough approximation).
        (此函数无需更改)
        """
        return len(text) // 3

# ----------------------------------------------------------------------------
# 3. 新增的脚本逻辑
# ----------------------------------------------------------------------------

# 1. 为 LLM 定义 Prompt
SYSTEM_PROMPT = """
你是一名网络安全和网络威胁情报 (CTI) 专家。
你的任务是分析提供的 CTI 报告文本。
你必须提取两个信息：
1. 报告的主要标题 (title)。
2. 报告中提到的所有 MITRE ATT&CK 技术 ID (techniques) 列表 (例如, T1059, T1059.003)。

你必须只输出一个有效的 JSON 对象，格式如下。
不要包含任何其他文本、解释、前言或 Markdown 标记 (例如 ```json)。
"""

USER_PROMPT_TEMPLATE = """
请分析以下的 CTI 报告内容。
严格按照系统指令，只返回 JSON 对象。

CTI 报告内容:
---
{report_content}
---
"""

# 2. 异步处理函数
async def process_cti_reports(client: LLMClient, files: List[str]) -> Dict[str, Any]:
    """
    异步读取、处理所有 CTI 报告并返回元数据字典。
    """
    metadata = {}
    prompts_to_send = []
    file_order = [] # 保持文件名和 prompt 的对应关系

    logger.info(f"发现 {len(files)} 个 .txt 文件待处理...")

    for filepath in files:
        filename = os.path.basename(filepath)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if not content.strip():
                logger.warning(f"跳过空文件: {filename}")
                continue
            
            # 格式化 prompt 并添加到列表
            prompt = USER_PROMPT_TEMPLATE.format(report_content=content)
            prompts_to_send.append(prompt)
            file_order.append(filename)

        except Exception as e:
            logger.error(f"读取文件失败 {filepath}: {e}")

    if not prompts_to_send:
        logger.error("没有找到有效的文件内容进行处理。")
        return {}

    # 批量异步调用 LLM
    logger.info(f"正在向 LLM 提交 {len(prompts_to_send)} 份报告进行分析 (并发数: {client.config.max_concurrent_requests})...")
    
    llm_responses = await client.call_batch_async(
        prompts_to_send, 
        system_prompt=SYSTEM_PROMPT
    )

    logger.info("LLM 响应处理完成，正在解析 JSON...")

    # 处理返回的 JSON 字符串
    for filename, llm_output in zip(file_order, llm_responses):
        try:
            # LLM 的输出应该是一个 JSON 字符串
            data = json.loads(llm_output)
            
            # 基本验证
            if "title" in data and "techniques" in data:
                metadata[filename] = data
                logger.success(f"成功处理: {filename} (提取到 {len(data['techniques'])} 个技术)")
            elif "error" in data:
                 logger.error(f"处理文件 {filename} 时 LLM API 调用失败: {data['error']}")
            else:
                logger.warning(f"为 {filename} 返回的 JSON 结构不正确: {llm_output[:100]}...")
        
        except json.JSONDecodeError:
            logger.error(f"为 {filename} 解析 JSON 失败。LLM 返回: {llm_output[:200]}...")
        except Exception as e:
            logger.error(f"处理 {filename} 的响应时发生未知错误: {e}")

    return metadata

# 3. 主执行函数
def main():
    """
    脚本主入口。
    """
    # 从环境变量中获取 API Key
    api_key = 'sk-7945679eea2842ed8b85f47c4aa16440'

    # 配置 LLMClient
    # !! 注意: 按你的要求使用 'deepseek-r1'。如果无效，请修改此处的 model 字符串
    llm_config = LLMConfig(
        provider="dashscope",
        api_key=api_key,
        model="deepseek-r1", 
        max_tokens=2048,      # 限制输出 token，防止过长
        temperature=0.0,     # 设为 0 以获得更稳定、确定性的 JSON 输出
        max_retries=3,
        max_concurrent_requests=5 # 并发5个请求
    )

    client = LLMClient(llm_config)

    # 查找当前目录下的所有 .txt 文件
    current_directory = os.getcwd()
    txt_files = glob.glob(os.path.join(current_directory, "*.txt"))

    if not txt_files:
        logger.warning(f"在 {current_directory} 中未找到 .txt 文件。")
        return

    # 运行异步处理
    # 使用 asyncio.run() 来启动异步主函数
    logger.info("开始处理 CTI 报告...")
    metadata_result = asyncio.run(process_cti_reports(client, txt_files))

    # 5. 将结果写入 JSON 文件
    if metadata_result:
        output_filename = "metadata.json"
        try:
            with open(output_filename, 'w', encoding='utf-8') as f:
                json.dump(metadata_result, f, indent=4, ensure_ascii=False)
            logger.success(f"成功生成元数据文件: {output_filename}")
        except Exception as e:
            logger.error(f"写入 {output_filename} 失败: {e}")
    else:
        logger.warning("没有生成任何元数据。")

if __name__ == "__main__":
    # 配置 loguru 日志
    logger.add(
        "cti_processing.log", 
        rotation="10 MB", 
        level="DEBUG",
        format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | {name}:{function}:{line} - {message}"
    )
    main()