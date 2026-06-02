#!/usr/bin/env python3
"""
ZAP Report Generator
====================
Convierte un reporte XML de OWASP ZAP en un PDF de auditoría profesional,
enriquecido con descripciones en español generadas por Claude (Anthropic).

Uso:
    python generate_report.py --input scan.xml --client "Empresa S.A." \
                              --url "https://app.empresa.com" --output reporte.pdf

Opciones:
    --no-ai     Genera el PDF sin llamar a la API de Anthropic (usa texto original en inglés)
    --auditor   Nombre del auditor/equipo (default: "Equipo de Seguridad")
    --model     Modelo de Claude a usar (default: claude-sonnet-4-6)
"""

import argparse
import sys
import os
from pathlib import Path

from dotenv import load_dotenv


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="generate_report.py",
        description="Genera un PDF de auditoría de seguridad a partir de un reporte OWASP ZAP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        metavar="scan.xml",
        help="Ruta al archivo XML exportado por OWASP ZAP",
    )
    parser.add_argument(
        "--client", "-c",
        required=True,
        metavar="'Nombre Empresa'",
        help="Nombre del cliente para la portada del informe",
    )
    parser.add_argument(
        "--url", "-u",
        required=True,
        metavar="https://sitio.com",
        help="URL auditada",
    )
    parser.add_argument(
        "--output", "-o",
        default="reporte.pdf",
        metavar="reporte.pdf",
        help="Ruta del PDF de salida (default: reporte.pdf)",
    )
    parser.add_argument(
        "--auditor",
        default="Equipo de Seguridad",
        help="Nombre del auditor o equipo (default: 'Equipo de Seguridad')",
    )
    parser.add_argument(
        "--model",
        default="claude-sonnet-4-6",
        help="Modelo de Claude a usar (default: claude-sonnet-4-6)",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="No usar la API de Anthropic. Genera el reporte con el texto original en inglés.",
    )
    return parser.parse_args()


def main() -> None:
    # Cargar variables de entorno desde .env
    load_dotenv()

    args = parse_args()

    # ── Validaciones de entrada ────────────────────────────
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"❌ Error: No se encontró el archivo '{args.input}'")
        sys.exit(1)

    if not input_path.suffix.lower() == ".xml":
        print(f"⚠️  Advertencia: el archivo '{args.input}' no tiene extensión .xml")

    if not args.no_ai and not os.getenv("ANTHROPIC_API_KEY"):
        print(
            "❌ Error: ANTHROPIC_API_KEY no configurada.\n"
            "   Creá un archivo .env con:\n"
            "     ANTHROPIC_API_KEY=sk-ant-...\n"
            "   O usá --no-ai para generar el reporte sin IA."
        )
        sys.exit(1)

    # ── Imports diferidos (evita errores si faltan dependencias) ──
    try:
        from src.parser import ZAPParser
        from src.report_generator import ReportGenerator
    except ImportError as e:
        print(f"❌ Error al importar módulos: {e}")
        print("   Asegurate de haber instalado las dependencias: pip install -r requirements.txt")
        sys.exit(1)

    print(f"\n{'═' * 55}")
    print(f"  ZAP Report Generator")
    print(f"{'═' * 55}")
    print(f"  Cliente  : {args.client}")
    print(f"  URL      : {args.url}")
    print(f"  Input    : {args.input}")
    print(f"  Output   : {args.output}")
    print(f"  Modo IA  : {'Desactivado (--no-ai)' if args.no_ai else f'Activado ({args.model})'}")
    print(f"{'─' * 55}\n")

    # ── 1. Parsear XML ────────────────────────────────────
    print("🔍 Parseando reporte ZAP...")
    try:
        parser = ZAPParser(args.input)
        findings = parser.parse()
    except (ValueError, FileNotFoundError) as e:
        print(f"❌ Error al parsear el XML: {e}")
        sys.exit(1)

    print(f"   ✓ {len(findings)} hallazgo(s) encontrado(s)\n")

    # ── 2. Enriquecer con IA ──────────────────────────────
    executive_summary = None

    if not args.no_ai:
        try:
            from src.ai_enhancer import AIEnhancer
        except ImportError as e:
            print(f"❌ Error al importar AIEnhancer: {e}")
            sys.exit(1)

        print("🤖 Enriqueciendo hallazgos con Claude AI...")
        try:
            enhancer = AIEnhancer(model=args.model)
            findings = enhancer.enhance_findings(findings)

            print("\n📝 Generando resumen ejecutivo...")
            executive_summary = enhancer.generate_executive_summary(
                findings=findings,
                client_name=args.client,
                target_url=args.url,
            )
            print("   ✓ Resumen ejecutivo generado\n")

        except EnvironmentError as e:
            print(f"❌ Error de configuración: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"⚠️  Error con la API de Anthropic: {e}")
            print("   Continuando sin enriquecimiento de IA...\n")
    else:
        print("⏭️  Modo --no-ai: saltando enriquecimiento con IA\n")

    # ── 3. Generar PDF ────────────────────────────────────
    try:
        generator = ReportGenerator()
        generator.generate(
            findings=findings,
            client_name=args.client,
            target_url=args.url,
            output_path=args.output,
            executive_summary=executive_summary,
            auditor=args.auditor,
        )
    except Exception as e:
        print(f"❌ Error al generar el PDF: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # ── Resumen final ─────────────────────────────────────
    print(f"\n{'═' * 55}")
    print(f"  ✅ Reporte generado exitosamente")
    print(f"{'─' * 55}")
    print(f"  Archivo : {Path(args.output).resolve()}")
    print(f"  Tamaño  : {Path(args.output).stat().st_size / 1024:.1f} KB")
    print(f"{'═' * 55}\n")


if __name__ == "__main__":
    main()
