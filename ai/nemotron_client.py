import os
import json
from dataclasses import dataclass
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()

@dataclass
class AIAnalysisResponse:
    summary: str
    key_risks: List[str]
    recommendations: List[str]
    technical_interpretation: str

class NemotronAnalyst:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("NVIDIA_API_KEY")
        self.client = None
        
        if self.api_key and not self.api_key.startswith("your_"):
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    base_url="https://integrate.api.nvidia.com/v1",
                    api_key=self.api_key
                )
            except ImportError:
                self.client = None

    def is_available(self) -> bool:
        return self.client is not None

    def analyze_scan(self, structured_context: dict) -> Optional[AIAnalysisResponse]:
        if not self.is_available():
            return None

        system_prompt = (
            "You are an expert Wi-Fi Security Analyst. Synthesize the provided deterministic "
            "scan JSON. Do not recalculate risk scores or alter facts. Respond ONLY with "
            "valid JSON matching this schema:\n"
            "{\n"
            '  "summary": "High-level scan overview",\n'
            '  "key_risks": ["Risk 1", "Risk 2"],\n'
            '  "recommendations": ["Action 1", "Action 2"],\n'
            '  "technical_interpretation": "Technical reasoning"\n'
            "}"
        )

        try:
            response = self.client.chat.completions.create(
                model="nvidia/nemotron-4-340b-instruct",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(structured_context)}
                ],
                temperature=0.2,
                max_tokens=1024
            )
            data = json.loads(response.choices[0].message.content)
            return AIAnalysisResponse(
                summary=data.get("summary", ""),
                key_risks=data.get("key_risks", []),
                recommendations=data.get("recommendations", []),
                technical_interpretation=data.get("technical_interpretation", "")
            )
        except Exception:
            return None
