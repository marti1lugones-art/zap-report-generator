"""
parser.py — Parsea el XML exportado por OWASP ZAP y devuelve una lista de Finding.
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import List, Optional


# Mapeo de códigos de riesgo numérico a etiqueta legible
RISK_CODE_MAP = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}

# Orden de severidad para ordenar hallazgos (menor = más grave)
SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}


@dataclass
class Instance:
    """Una instancia concreta donde se encontró la vulnerabilidad."""
    uri: str
    method: str
    param: str
    attack: str
    evidence: str


@dataclass
class Finding:
    """Representa un hallazgo de seguridad extraído del reporte ZAP."""
    plugin_id: str
    name: str
    risk: str           # "High", "Medium", "Low", "Informational"
    risk_code: str      # "3", "2", "1", "0"
    confidence: str
    description: str
    solution: str
    reference: str
    cwe_id: str
    wasc_id: str
    count: int
    instances: List[Instance] = field(default_factory=list)
    other_info: str = ""

    # Campos enriquecidos por IA (None si se usa --no-ai)
    description_es: Optional[str] = None
    solution_es: Optional[str] = None


class ZAPParser:
    """
    Parsea el archivo XML generado por OWASP ZAP.
    Compatible con los formatos de ZAP 2.x y 2.14+.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> List[Finding]:
        """
        Lee el XML y devuelve los hallazgos ordenados por severidad descendente.
        """
        try:
            tree = ET.parse(self.filepath)
        except ET.ParseError as e:
            raise ValueError(f"Error al parsear el XML: {e}")

        root = tree.getroot()
        findings: List[Finding] = []

        # El XML de ZAP puede tener uno o varios nodos <site>
        for site in root.findall(".//site"):
            alerts_node = site.find("alerts")
            if alerts_node is None:
                continue
            for alert_item in alerts_node.findall("alertitem"):
                finding = self._parse_alert_item(alert_item)
                findings.append(finding)

        if not findings:
            raise ValueError(
                "No se encontraron hallazgos en el XML. "
                "Verificá que el archivo sea un reporte válido de OWASP ZAP."
            )

        # Ordenar de más a menos grave
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.risk, 99))
        return findings

    def _parse_alert_item(self, item) -> Finding:
        """Extrae todos los campos de un <alertitem>."""
        get = lambda tag, default="": self._text(item, tag, default)

        risk_code = get("riskcode", "0")
        risk = RISK_CODE_MAP.get(risk_code, "Informational")

        # ZAP usa <alert> en versiones viejas y <name> en versiones nuevas
        name = get("alert") or get("name") or "Sin nombre"

        instances = [
            Instance(
                uri=self._text(inst, "uri"),
                method=self._text(inst, "method"),
                param=self._text(inst, "param"),
                attack=self._text(inst, "attack"),
                evidence=self._text(inst, "evidence"),
            )
            for inst in item.findall(".//instance")
        ]

        return Finding(
            plugin_id=get("pluginid"),
            name=name,
            risk=risk,
            risk_code=risk_code,
            confidence=get("confidence", "2"),
            description=get("desc"),
            solution=get("solution"),
            reference=get("reference"),
            cwe_id=get("cweid"),
            wasc_id=get("wascid"),
            other_info=get("otherinfo"),
            count=int(get("count", "1") or "1"),
            instances=instances,
        )

    @staticmethod
    def _text(parent, tag: str, default: str = "") -> str:
        """Helper: devuelve el texto de un elemento hijo, o default si no existe."""
        el = parent.find(tag)
        if el is not None and el.text:
            return el.text.strip()
        return default
