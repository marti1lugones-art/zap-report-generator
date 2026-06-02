"""
ai_enhancer.py — Integración con la API de Anthropic para enriquecer hallazgos
con lenguaje profesional en español y generar el resumen ejecutivo.
"""

import os
import json
from typing import List, Optional

import anthropic

from .parser import Finding


# Modelo por defecto: claude-sonnet-4-6 para calidad profesional
DEFAULT_MODEL = "claude-sonnet-4-6"


class AIEnhancer:
    """
    Usa la API de Anthropic para:
    - Traducir y profesionalizar descripciones y soluciones de vulnerabilidades
    - Generar el resumen ejecutivo del informe
    """

    def __init__(self, model: str = DEFAULT_MODEL):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY no encontrada. "
                "Creá un archivo .env con la variable o exportala en tu entorno."
            )
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def enhance_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Procesa cada hallazgo con la API de Claude y agrega versiones en español
        profesional de la descripción y la solución.
        """
        total = len(findings)
        for i, finding in enumerate(findings):
            print(f"  [{i + 1}/{total}] Procesando: {finding.name}", flush=True)
            enhanced = self._enhance_single_finding(finding)
            finding.description_es = enhanced.get("descripcion", finding.description)
            finding.solution_es = enhanced.get("solucion", finding.solution)

        return findings

    def _enhance_single_finding(self, finding: Finding) -> dict:
        """
        Llama a Claude UNA vez por hallazgo y recibe descripción + solución
        en un único JSON estructurado (menos tokens, menos latencia).
        """
        # Preparar contexto de instancias para dar más contexto a Claude
        instances_context = ""
        if finding.instances:
            sample = finding.instances[0]
            instances_context = (
                f"URL afectada: {sample.uri}\n"
                f"Método: {sample.method}\n"
                f"Parámetro: {sample.param or 'N/A'}\n"
                f"Evidencia: {sample.evidence or 'N/A'}"
            )

        prompt = f"""Sos un consultor senior de ciberseguridad redactando un informe profesional para un cliente corporativo en Argentina.

VULNERABILIDAD DETECTADA:
Nombre: {finding.name}
Severidad: {finding.risk}
CWE: {finding.cwe_id or 'N/A'}
Descripción técnica: {finding.description}
Solución técnica: {finding.solution}
{instances_context}

TAREA:
Reescribí en español profesional y formal:
1. Una descripción clara de la vulnerabilidad (máximo 180 palabras): explicá qué es, cómo puede ser explotada y cuál es el impacto para el negocio.
2. Una solución concreta y accionable (máximo 130 palabras): pasos específicos para remediar el problema.

Respondé ÚNICAMENTE con un JSON válido con esta estructura exacta:
{{
  "descripcion": "...",
  "solucion": "..."
}}"""

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = message.content[0].text.strip()

            # Extraer JSON aunque Claude agregue texto extra
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start == -1 or end == 0:
                raise ValueError("No se encontró JSON en la respuesta")

            return json.loads(raw[start:end])

        except (json.JSONDecodeError, ValueError, IndexError) as e:
            # Fallback: usar texto original si la respuesta no es parseable
            print(f"    ⚠️  Error al parsear respuesta de AI para '{finding.name}': {e}")
            return {"descripcion": finding.description, "solucion": finding.solution}

    def generate_executive_summary(
        self,
        findings: List[Finding],
        client_name: str,
        target_url: str,
    ) -> str:
        """
        Genera el resumen ejecutivo completo del informe basado en los hallazgos.
        """
        # Contar hallazgos por severidad
        counts: dict = {}
        for f in findings:
            counts[f.risk] = counts.get(f.risk, 0) + 1

        counts_text = ", ".join(
            f"{v} {k.lower()}{'s' if v > 1 else ''}"
            for k, v in counts.items()
        )

        # Tomar los 5 hallazgos más graves para el contexto
        top_findings = "\n".join(
            f"- [{f.risk}] {f.name}" for f in findings[:5]
        )

        prompt = f"""Sos un consultor senior de ciberseguridad redactando el resumen ejecutivo de un informe de auditoría de seguridad web para un cliente en Argentina.

DATOS DE LA AUDITORÍA:
Cliente: {client_name}
URL auditada: {target_url}
Total de hallazgos: {len(findings)}
Distribución: {counts_text}

Hallazgos principales:
{top_findings}

INSTRUCCIONES:
Redactá un resumen ejecutivo profesional y formal en español rioplatense (sin "vosotros", usando "ustedes" para plurales). El resumen debe:
- Abrir con el propósito y alcance de la auditoría (1 párrafo)
- Describir el estado general de seguridad del sistema auditado (1 párrafo)
- Destacar los hallazgos de mayor impacto y su riesgo para el negocio (1 párrafo)
- Cerrar con la recomendación de priorizar la remediación (1 párrafo)
- Extensión: entre 200 y 280 palabras
- Tono: formal, directo, orientado a ejecutivos no técnicos

Respondé ÚNICAMENTE con el texto del resumen ejecutivo, sin encabezados ni formato extra."""

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}],
            )
            return message.content[0].text.strip()

        except Exception as e:
            print(f"⚠️  Error al generar resumen ejecutivo: {e}")
            return (
                f"Se realizó una auditoría de seguridad web sobre {target_url} para {client_name}. "
                f"Se identificaron {len(findings)} hallazgos en total ({counts_text}). "
                "Se recomienda abordar los hallazgos de alta severidad de forma inmediata."
            )
