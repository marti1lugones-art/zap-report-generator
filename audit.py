#!/usr/bin/env python3
"""
audit.py — CLI unificado para el generador de reportes de seguridad.

Corre chequeos directos (headers, SSL/TLS, email) y/o procesa un reporte
OWASP ZAP, generando un PDF profesional con enriquecimiento de IA en español.

Uso básico:
    python audit.py --url "https://sitio.com" --client "Empresa S.A."

Con ZAP combinado:
    python audit.py --url "https://sitio.com" --client "Empresa" --input scan.xml

Solo algunos módulos:
    python audit.py --url "https://sitio.com" --client "X" --skip-ssl --skip-email

Sin IA:
    python audit.py --url "https://sitio.com" --client "X" --no-ai
"""

import argparse
import sys
import os
from pathlib import Path

from dotenv import load_dotenv


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="audit.py",
        description="Genera un reporte de auditoría de seguridad web completo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", "-u", required=True, metavar="https://sitio.com",
                        help="URL objetivo a auditar")
    parser.add_argument("--client", "-c", required=True, metavar="'Nombre Empresa'",
                        help="Nombre del cliente para la portada")
    parser.add_argument("--input", "-i", metavar="scan.xml",
                        help="(Opcional) Reporte XML de OWASP ZAP a incluir")
    parser.add_argument("--output", "-o", default="reporte.pdf", metavar="reporte.pdf",
                        help="Ruta del PDF de salida (default: reporte.pdf)")
    parser.add_argument("--auditor", default="Equipo de Seguridad",
                        help="Nombre del auditor o equipo")
    parser.add_argument("--model", default="claude-sonnet-4-6",
                        help="Modelo de Claude (default: claude-sonnet-4-6)")
    parser.add_argument("--no-ai", action="store_true",
                        help="Generar reporte sin llamar a la API de Anthropic")
    parser.add_argument("--skip-headers", action="store_true",
                        help="Omitir chequeo de headers HTTP")
    parser.add_argument("--skip-ssl", action="store_true",
                        help="Omitir chequeo de SSL/TLS")
    parser.add_argument("--skip-email", action="store_true",
                        help="Omitir chequeo de seguridad de email (SPF/DKIM/DMARC)")
    return parser.parse_args()


def main() -> None:
    load_dotenv()
    args = parse_args()

    # Validaciones
    if args.input:
        p = Path(args.input)
        if not p.exists():
            print(f"❌ Error: No se encontró el archivo '{args.input}'")
            sys.exit(1)

    if not args.no_ai and not os.getenv("ANTHROPIC_API_KEY"):
        print(
            "❌ Error: ANTHROPIC_API_KEY no configurada.\n"
            "   Creá un archivo .env con:\n"
            "     ANTHROPIC_API_KEY=sk-ant-...\n"
            "   O usá --no-ai para generar el reporte sin IA."
        )
        sys.exit(1)

    try:
        from src.parser import ZAPParser
        from src.report_generator import ReportGenerator
        from src.checkers.headers import HeadersChecker
        from src.checkers.ssl_checker import SSLChecker
        from src.checkers.email_security import EmailSecurityChecker
    except ImportError as e:
        print(f"❌ Error al importar módulos: {e}")
        print("   Asegurate de haber instalado: pip install -r requirements.txt")
        sys.exit(1)

    modules_enabled = []
    if not args.skip_headers:
        modules_enabled.append("Headers HTTP")
    if not args.skip_ssl:
        modules_enabled.append("SSL/TLS")
    if not args.skip_email:
        modules_enabled.append("Email (SPF/DKIM/DMARC)")

    print(f"\n{'═' * 58}")
    print(f"  Security Audit Report Generator")
    print(f"{'═' * 58}")
    print(f"  Cliente  : {args.client}")
    print(f"  URL      : {args.url}")
    if args.input:
        print(f"  ZAP XML  : {args.input}")
    print(f"  Módulos  : {', '.join(modules_enabled) if modules_enabled else 'ninguno'}")
    print(f"  Output   : {args.output}")
    print(f"  Modo IA  : {'Desactivado' if args.no_ai else f'Activado ({args.model})'}")
    print(f"{'─' * 58}\n")

    all_findings = []

    # ── 1. ZAP (opcional) ─────────────────────────────────────────────────
    if args.input:
        print("🔍 Parseando reporte ZAP...")
        try:
            parser = ZAPParser(args.input)
            zap_findings = parser.parse()
            print(f"   ✓ {len(zap_findings)} hallazgo(s) de ZAP\n")
            all_findings.extend(zap_findings)
        except (ValueError, FileNotFoundError) as e:
            print(f"❌ Error al parsear el XML: {e}")
            sys.exit(1)

    # ── 2. Headers HTTP ───────────────────────────────────────────────────
    if not args.skip_headers:
        print("🔒 Verificando headers HTTP de seguridad...")
        try:
            findings = HeadersChecker().check(args.url)
            print(f"   ✓ {len(findings)} hallazgo(s)\n")
            all_findings.extend(findings)
        except Exception as e:
            print(f"   ⚠️  Error en módulo headers: {e}\n")

    # ── 3. SSL/TLS ────────────────────────────────────────────────────────
    if not args.skip_ssl:
        print("🔐 Analizando configuración SSL/TLS...")
        try:
            findings = SSLChecker().check(args.url)
            print(f"   ✓ {len(findings)} hallazgo(s)\n")
            all_findings.extend(findings)
        except Exception as e:
            print(f"   ⚠️  Error en módulo SSL: {e}\n")

    # ── 4. Email (DNS) ────────────────────────────────────────────────────
    if not args.skip_email:
        print("📧 Verificando seguridad de email (SPF/DKIM/DMARC)...")
        try:
            findings = EmailSecurityChecker().check(args.url)
            print(f"   ✓ {len(findings)} hallazgo(s)\n")
            all_findings.extend(findings)
        except Exception as e:
            print(f"   ⚠️  Error en módulo email: {e}\n")

    if not all_findings:
        print("ℹ️  No se encontraron hallazgos. Generando reporte vacío.\n")

    # ── 5. Enriquecimiento con IA ─────────────────────────────────────────
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
            all_findings = enhancer.enhance_findings(all_findings)

            print("\n📝 Generando resumen ejecutivo...")
            executive_summary = enhancer.generate_executive_summary(
                findings=all_findings,
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

    # ── 6. Generar PDF ────────────────────────────────────────────────────
    try:
        generator = ReportGenerator()
        generator.generate(
            findings=all_findings,
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

    # ── Resumen final ─────────────────────────────────────────────────────
    from src.parser import SEVERITY_ORDER
    by_source = {}
    by_severity = {}
    for f in all_findings:
        by_source[f.source] = by_source.get(f.source, 0) + 1
        by_severity[f.risk] = by_severity.get(f.risk, 0) + 1

    print(f"\n{'═' * 58}")
    print(f"  ✅ Reporte generado exitosamente")
    print(f"{'─' * 58}")
    print(f"  Archivo  : {Path(args.output).resolve()}")
    print(f"  Tamaño   : {Path(args.output).stat().st_size / 1024:.1f} KB")
    print(f"  Hallazgos: {len(all_findings)} total")
    for src, count in by_source.items():
        labels = {"zap": "ZAP", "headers": "Headers", "ssl": "SSL/TLS", "email": "Email"}
        print(f"    · {labels.get(src, src)}: {count}")
    print(f"{'═' * 58}\n")


if __name__ == "__main__":
    main()
