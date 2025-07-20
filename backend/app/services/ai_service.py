# JADE Ultimate Security Platform - Enhanced AI Service
# Supporting: OpenAI, GitHub Models, Cerebras, Google Gemini

import os
import asyncio
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import structlog
import openai
import google.generativeai as genai
from azure.ai.inference import ChatCompletionsClient
from azure.core.credentials import AzureKeyCredential
import httpx

from app.core.config import settings, AI_MODELS

logger = structlog.get_logger()

@dataclass
class AIResponse:
    content: str
    model: str
    provider: str
    tokens_used: Optional[int] = None
    latency_ms: Optional[float] = None

class AIService:
    """Enhanced AI Service supporting multiple providers"""
    
    def __init__(self):
        self.providers = {}
        self.initialized = False
        
    async def initialize(self):
        """Initialize AI providers"""
        try:
            # Initialize OpenAI
            if settings.OPENAI_API_KEY:
                self.providers['openai'] = {
                    'client': openai.AsyncOpenAI(api_key=settings.OPENAI_API_KEY),
                    'initialized': True
                }
                logger.info("openai_initialized")
            
            # Initialize Google Gemini
            if settings.GEMINI_API_KEY:
                genai.configure(api_key=settings.GEMINI_API_KEY)
                self.providers['google'] = {
                    'client': genai,
                    'initialized': True
                }
                logger.info("gemini_initialized")
            
            # Initialize GitHub Models (using Azure AI Inference)
            if settings.GITHUB_TOKEN:
                self.providers['github'] = {
                    'client': ChatCompletionsClient(
                        endpoint="https://models.github.ai/inference",
                        credential=AzureKeyCredential(settings.GITHUB_TOKEN)
                    ),
                    'initialized': True
                }
                logger.info("github_models_initialized")
            
            # Initialize Cerebras (using HTTP client)
            if settings.CEREBRAS_API_KEY:
                self.providers['cerebras'] = {
                    'client': httpx.AsyncClient(
                        base_url="https://api.cerebras.ai/v1",
                        headers={
                            "Authorization": f"Bearer {settings.CEREBRAS_API_KEY}",
                            "Content-Type": "application/json"
                        }
                    ),
                    'initialized': True
                }
                logger.info("cerebras_initialized")
            
            self.initialized = True
            logger.info("ai_service_initialized", providers=list(self.providers.keys()))
            
        except Exception as e:
            logger.error("ai_service_initialization_error", error=str(e))
            raise

    async def cleanup(self):
        """Cleanup AI service resources"""
        try:
            if 'cerebras' in self.providers:
                await self.providers['cerebras']['client'].aclose()
            logger.info("ai_service_cleanup_completed")
        except Exception as e:
            logger.error("ai_service_cleanup_error", error=str(e))

    async def generate_completion(self, 
                                prompt: str, 
                                model: str = "gpt-4",
                                system_prompt: Optional[str] = None,
                                temperature: float = 0.1,
                                max_tokens: int = 4000) -> AIResponse:
        """Generate AI completion using specified model"""
        
        if not self.initialized:
            await self.initialize()
        
        if model not in AI_MODELS:
            raise ValueError(f"Model {model} not supported")
        
        model_config = AI_MODELS[model]
        provider = model_config['provider']
        
        if provider not in self.providers:
            raise ValueError(f"Provider {provider} not initialized")
        
        import time
        start_time = time.time()
        
        try:
            if provider == 'openai':
                response = await self._openai_completion(prompt, model_config, system_prompt, temperature, max_tokens)
            elif provider == 'google':
                response = await self._gemini_completion(prompt, model_config, system_prompt, temperature, max_tokens)
            elif provider == 'github':
                response = await self._github_completion(prompt, model_config, system_prompt, temperature, max_tokens)
            elif provider == 'cerebras':
                response = await self._cerebras_completion(prompt, model_config, system_prompt, temperature, max_tokens)
            else:
                raise ValueError(f"Provider {provider} not implemented")
            
            latency_ms = (time.time() - start_time) * 1000
            response.latency_ms = latency_ms
            
            logger.info("ai_completion_success", 
                       model=model, 
                       provider=provider, 
                       latency_ms=latency_ms,
                       tokens_used=response.tokens_used)
            
            return response
            
        except Exception as e:
            logger.error("ai_completion_error", 
                        model=model, 
                        provider=provider, 
                        error=str(e))
            raise

    async def _openai_completion(self, prompt: str, model_config: Dict, 
                               system_prompt: Optional[str], temperature: float, 
                               max_tokens: int) -> AIResponse:
        """OpenAI completion"""
        client = self.providers['openai']['client']
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        response = await client.chat.completions.create(
            model=model_config['model'],
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        return AIResponse(
            content=response.choices[0].message.content,
            model=model_config['model'],
            provider='openai',
            tokens_used=response.usage.total_tokens if response.usage else None
        )

    async def _gemini_completion(self, prompt: str, model_config: Dict,
                               system_prompt: Optional[str], temperature: float,
                               max_tokens: int) -> AIResponse:
        """Google Gemini completion"""
        client = genai.GenerativeModel(model_config['model'])
        
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"System: {system_prompt}\n\nUser: {prompt}"
        
        response = await asyncio.to_thread(
            client.generate_content,
            full_prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens
            )
        )
        
        return AIResponse(
            content=response.text,
            model=model_config['model'],
            provider='google'
        )

    async def _github_completion(self, prompt: str, model_config: Dict,
                               system_prompt: Optional[str], temperature: float,
                               max_tokens: int) -> AIResponse:
        """GitHub Models completion"""
        client = self.providers['github']['client']
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        response = client.complete(
            messages=messages,
            model=model_config['model'],
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        if response.status_code != 200:
            raise Exception(f"GitHub Models API error: {response.status_code}")
        
        result = response.json()
        
        return AIResponse(
            content=result['choices'][0]['message']['content'],
            model=model_config['model'],
            provider='github',
            tokens_used=result.get('usage', {}).get('total_tokens')
        )

    async def _cerebras_completion(self, prompt: str, model_config: Dict,
                                 system_prompt: Optional[str], temperature: float,
                                 max_tokens: int) -> AIResponse:
        """Cerebras completion"""
        client = self.providers['cerebras']['client']
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": model_config['model'],
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }
        
        response = await client.post("/chat/completions", json=payload)
        
        if response.status_code != 200:
            raise Exception(f"Cerebras API error: {response.status_code}, {response.text}")
        
        result = response.json()
        
        return AIResponse(
            content=result['choices'][0]['message']['content'],
            model=model_config['model'],
            provider='cerebras',
            tokens_used=result.get('usage', {}).get('total_tokens')
        )

    async def analyze_scan_results(self, scan_data: Dict[str, Any], model: str = "gpt-4") -> Dict[str, Any]:
        """Analyze security scan results using AI"""
        
        system_prompt = """You are an expert cybersecurity analyst specializing in vulnerability assessment and threat analysis. 
        Analyze the provided scan results and provide:
        1. Executive summary of findings
        2. Critical vulnerabilities and their risk levels
        3. Recommended remediation actions
        4. Potential attack vectors
        5. Compliance impact assessment
        
        Format your response as structured JSON."""
        
        prompt = f"""
        Please analyze these security scan results:
        
        Scan Type: {scan_data.get('scan_type', 'Unknown')}
        Target: {scan_data.get('target', 'Unknown')}
        Status: {scan_data.get('status', 'Unknown')}
        Duration: {scan_data.get('duration', 'Unknown')}
        
        Raw Results: {json.dumps(scan_data.get('results', {}), indent=2)}
        
        Provide a comprehensive security analysis focusing on actionable insights.
        """
        
        response = await self.generate_completion(
            prompt=prompt,
            model=model,
            system_prompt=system_prompt,
            temperature=0.1,
            max_tokens=4000
        )
        
        try:
            # Try to parse as JSON, fallback to structured text
            analysis = json.loads(response.content)
        except json.JSONDecodeError:
            analysis = {
                "analysis": response.content,
                "model_used": response.model,
                "provider": response.provider
            }
        
        return analysis

    async def generate_threat_intelligence(self, indicators: List[str], model: str = "gemini-pro") -> Dict[str, Any]:
        """Generate threat intelligence analysis"""
        
        system_prompt = """You are a threat intelligence analyst. Analyze the provided indicators and provide:
        1. Threat assessment
        2. Attribution analysis
        3. Campaign identification
        4. Recommended countermeasures"""
        
        prompt = f"""
        Analyze these security indicators:
        {json.dumps(indicators, indent=2)}
        
        Provide comprehensive threat intelligence analysis.
        """
        
        response = await self.generate_completion(
            prompt=prompt,
            model=model,
            system_prompt=system_prompt
        )
        
        return {
            "threat_intelligence": response.content,
            "model_used": response.model,
            "provider": response.provider,
            "indicators_analyzed": len(indicators)
        }

    def get_available_models(self) -> Dict[str, Any]:
        """Get list of available AI models"""
        available_models = {}
        
        for model_name, config in AI_MODELS.items():
            provider = config['provider']
            is_available = (provider in self.providers and 
                          self.providers[provider].get('initialized', False))
            
            available_models[model_name] = {
                "provider": provider,
                "model": config['model'],
                "use_case": config['use_case'],
                "available": is_available
            }
        
        return available_models

    async def health_check(self) -> Dict[str, Any]:
        """Check AI service health"""
        health_status = {
            "initialized": self.initialized,
            "providers": {}
        }
        
        for provider, config in self.providers.items():
            health_status["providers"][provider] = {
                "initialized": config['initialized'],
                "available": True
            }
        
        return health_status

# Global AI service instance
ai_service = AIService()