"""
ai_enhancer.py — Integración con la API de Anthropic para enriquecer hallazgos
con lenguaje profesional en español y generar el resumen ejecutivo.
"""

import os
import json
from typing import List, Optional

import anthropic

from .parser import Finding


DEFAULT_MODEL = "claude-sonnet-4-6"

SOURCE_LABELS = {
    "zap":     "Escaneo OWASP ZAP",
    "headers": "Análisis de Headers HTTP",
    "ssl":     "Evaluación SSL/TLS",
    "email":   "Verificación de Seguridad de Email",
}


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
        Procesa TODOS los hallazgos (de cualquier source) con la API de Claude
        y agrega versiones en español profesional de la descripción y la solución.
        """
        total = len(findings)
        for i, finding in enumerate(findings):
            src_label = SOURCE_LABELS.get(finding.source, finding.source.upper())
            print(f"  [{i + 1}/{total}] [{src_label}] {finding.name}", flush=True)
            enhanced = self._enhance_single_finding(finding)
            finding.description_es = enhanced.get("descripcion") or finding.description
            finding.solution_es    = enhanced.get("solucion")    or finding.solution
        return findings

    def _enhance_single_finding(self, finding: Finding) -> dict:
        """
        Llama a Claude una vez por hallazgo y recibe descripción + solución en JSON.
        Reintenta si el JSON viene truncado (max_tokens bajo) o malformado.
        """
        # Evidencia técnica: solo incluir si hay datos reales (no campos vacíos)
        evidence_lines = []
        if finding.instances:
            s = finding.instances[0]
            if s.uri:     evidence_lines.append(f"URL afectada: {s.uri}")
            if s.method:  evidence_lines.append(f"Método: {s.method}")
            if s.param:   evidence_lines.append(f"Parámetro: {s.param}")
            if s.evidence: evidence_lines.append(f"Evidencia: {s.evidence[:200]}")
        evidence_ctx = "\n".join(evidence_lines)

        module_ctx = SOURCE_LABELS.get(finding.source, "Auditoría de Seguridad")

        prompt = f"""Sos un consultor senior de ciberseguridad redactando un informe profesional para un cliente corporativo en Argentina.

MÓDULO: {module_ctx}

VULNERABILIDAD DETECTADA:
Nombre: {finding.name}
Severidad: {finding.risk}
CWE: {finding.cwe_id or 'N/A'}
Descripción técnica (en inglés): {finding.description}
Solución técnica (en inglés): {finding.solution}
{evidence_ctx}

TAREA:
Reescribí en español rioplatense profesional y formal:
1. Descripción (máximo 150 palabras): qué es la vulnerabilidad, cómo puede explotarse, impacto para el negocio.
2. Solución (máximo 120 palabras): pasos concretos y accionables para remediar el problema.

Respondé ÚNICAMENTE con este JSON válido, sin texto adicional antes ni después:
{{
  "descripcion": "...",
  "solucion": "..."
}}"""

        for attempt in range(2):
            try:
                message = self.client.messages.create(
                    model=self.model,
                    max_tokens=900,
                    messages=[{"role": "user", "content": prompt}],
                )
                raw = message.content[0].text.strip()

                start = raw.find("{")
                end   = raw.rfind("}") + 1
                if start == -1 or end == 0:
                    raise ValueError(f"Sin JSON en respuesta (intento {attempt + 1})")

                result = json.loads(raw[start:end])

                # Validar que ambas claves están presentes y no vacías
                if result.get("descripcion") and result.get("solucion"):
                    return result

                raise ValueError("JSON incompleto: falta descripcion o solucion")

            except (json.JSONDecodeError, ValueError) as e:
                if attempt == 0:
                    print(f"    ↩️  Reintentando '{finding.name}' ({e})", flush=True)
                    continue
                print(f"    ⚠️  Fallback a inglés para '{finding.name}': {e}", flush=True)
                return {}

            except Exception as e:
                print(f"    ⚠️  Error de API para '{finding.name}': {e}", flush=True)
                return {}

        return {}

    def generate_executive_summary(
        self,
        findings: List[Finding],
        client_name: str,
        target_url: str,
    ) -> str:
        """Genera el resumen ejecutivo completo del informe basado en los hallazgos."""
        counts: dict = {}
        for f in findings:
            counts[f.risk] = counts.get(f.risk, 0) + 1
        counts_text = ", ".join(
            f"{v} {k.lower()}{'s' if v > 1 else ''}"
            for k, v in counts.items()
        )

        # Módulos activos
        active_sources = sorted({f.source for f in findings})
        modules_used = [SOURCE_LABELS.get(s, s) for s in active_sources]

        top_findings = "\n".join(f"- [{f.risk}] {f.name}" for f in findings[:5])

        prompt = f"""Sos un consultor senior de ciberseguridad redactando el resumen ejecutivo de un informe de auditoría de seguridad web para un cliente en Argentina.

DATOS DE LA AUDITORÍA:
Cliente: {client_name}
URL auditada: {target_url}
Módulos ejecutados: {', '.join(modules_used)}
Total de hallazgos: {len(findings)}
Distribución: {counts_text}

Hallazgos principales:
{top_findings}

INSTRUCCIONES:
Redactá un resumen ejecutivo profesional en español rioplatense (sin "vosotros"). El resumen debe:
- Abrir con el propósito y alcance de la auditoría (1 párrafo)
- Describir el estado general de seguridad (1 párrafo)
- Destacar los hallazgos de mayor impacto y su riesgo para el negocio (1 párrafo)
- Cerrar con la recomendación de priorizar la remediación (1 párrafo)
- Entre 200 y 280 palabras. Tono: formal, orientado a ejecutivos no técnicos.

Respondé ÚNICAMENTE con el texto del resumen ejecutivo, sin encabezados ni formato extra."""

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=700,
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
