"""
report_generator.py — Genera el PDF de auditoría usando reportlab (puro Python).
También produce el gráfico de distribución de severidades con matplotlib.
"""

import base64
import html as _html
import io
from datetime import datetime
from typing import List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    BaseDocTemplate, PageTemplate, Frame,
    Paragraph, Spacer, Table, TableStyle,
    NextPageTemplate, PageBreak, Image, HRFlowable,
)

from .parser import Finding


# ── Dimensiones de página ─────────────────────────────────────
PAGE_W, PAGE_H = A4                    # 595.27 × 841.89 pt
MARGIN   = 18 * mm                    # margen lateral
FOOT_H   = 15 * mm                    # altura reservada para el footer
FRAME_W  = PAGE_W - 2 * MARGIN        # ancho del frame de contenido
CARD_PAD = 4 * mm                     # padding interno de tarjetas
CARD_IW  = FRAME_W - 2 * CARD_PAD    # ancho interior de tarjeta

# ── Paleta de colores ─────────────────────────────────────────
C_BG      = HexColor('#0d1117')
C_BG2     = HexColor('#161b22')
C_BG3     = HexColor('#1c2128')
C_CHART   = HexColor('#12121e')
C_BORDER  = HexColor('#30363d')
C_BORDER2 = HexColor('#21262d')
C_ACCENT  = HexColor('#00b4d8')
C_TEXT    = HexColor('#e6edf3')
C_TEXT2   = HexColor('#c9d1d9')
C_MUTED   = HexColor('#8b949e')
C_MUTED2  = HexColor('#555e6a')

SEVERITY_COLORS = {
    'Critical':      HexColor('#ff3b3b'),
    'High':          HexColor('#ff6b35'),
    'Medium':        HexColor('#ffb800'),
    'Low':           HexColor('#4fc3f7'),
    'Informational': HexColor('#78909c'),
}

SEVERITY_BG = {
    'Critical':      HexColor('#180000'),
    'High':          HexColor('#160a00'),
    'Medium':        HexColor('#141000'),
    'Low':           HexColor('#001018'),
    'Informational': HexColor('#0e1214'),
}

SEVERITY_ES = {
    'Critical':      'Crítica',
    'High':          'Alta',
    'Medium':        'Media',
    'Low':           'Baja',
    'Informational': 'Informativa',
}

CONFIDENCE_LABELS = {
    '0': 'False Positive', '1': 'Low', '2': 'Medium',
    '3': 'High',           '4': 'Confirmed',
}

SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational']
CHART_HEX = {
    'Critical':      '#ff3b3b',
    'High':          '#ff6b35',
    'Medium':        '#ffb800',
    'Low':           '#4fc3f7',
    'Informational': '#78909c',
}


def esc(text) -> str:
    """Escapa caracteres HTML para usar en Paragraph."""
    return _html.escape(str(text or ''), quote=False)


def _hex(color) -> str:
    """Convierte HexColor a formato '#rrggbb' para markup XML de reportlab."""
    return '#' + color.hexval()[2:]


class ReportGenerator:
    """Orquesta la generación del PDF: gráfico → reportlab → PDF."""

    def generate(
        self,
        findings: List[Finding],
        client_name: str,
        target_url: str,
        output_path: str,
        executive_summary: Optional[str] = None,
        auditor: str = "Equipo de Seguridad",
    ) -> None:
        print("📊 Generando gráfico de severidades...")
        chart_b64 = self._build_severity_chart(findings)

        print("📄 Construyendo documento PDF...")
        sev_counts = self._count_by_severity(findings)
        grouped    = self._group_by_severity(findings)
        date_str   = self._format_date()

        print(f"📝 Convirtiendo a PDF → {output_path}")
        self._build_pdf(
            findings=findings,
            client_name=client_name,
            target_url=target_url,
            output_path=output_path,
            executive_summary=executive_summary,
            auditor=auditor,
            chart_b64=chart_b64,
            sev_counts=sev_counts,
            grouped=grouped,
            date_str=date_str,
        )

    # ═══════════════════════════════════════════════════════════
    # Construcción del PDF
    # ═══════════════════════════════════════════════════════════

    def _build_pdf(self, findings, client_name, target_url, output_path,
                   executive_summary, auditor, chart_b64,
                   sev_counts, grouped, date_str):

        # ── Callbacks de página ──────────────────────────────
        def draw_cover(canvas, _):
            canvas.saveState()
            canvas.setFillColor(C_BG)
            canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
            canvas.setFillColor(C_ACCENT)
            canvas.rect(0, PAGE_H - 6 * mm, PAGE_W, 6 * mm, fill=1, stroke=0)
            # Línea inferior
            canvas.setStrokeColor(C_BORDER)
            canvas.setLineWidth(0.5)
            canvas.line(MARGIN, 22 * mm, PAGE_W - MARGIN, 22 * mm)
            canvas.setFillColor(C_MUTED2)
            canvas.setFont('Helvetica', 7.5)
            canvas.drawString(MARGIN, 17 * mm,
                'Generado con ZAP Report Generator · Powered by Claude AI')
            canvas.drawRightString(PAGE_W - MARGIN, 17 * mm, date_str)
            canvas.restoreState()

        def draw_content(canvas, _):
            canvas.saveState()
            canvas.setFillColor(C_BG)
            canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
            # Footer
            canvas.setStrokeColor(C_BORDER)
            canvas.setLineWidth(0.5)
            canvas.line(MARGIN, FOOT_H - 3 * mm, PAGE_W - MARGIN, FOOT_H - 3 * mm)
            canvas.setFillColor(C_MUTED2)
            canvas.setFont('Helvetica', 7)
            canvas.drawString(MARGIN, FOOT_H - 7 * mm,
                f'CONFIDENCIAL — {client_name} — Auditoría de Seguridad Web')
            canvas.drawRightString(PAGE_W - MARGIN, FOOT_H - 7 * mm,
                f'Pág. {canvas.getPageNumber() - 1}')
            canvas.restoreState()

        # ── Frames y templates ───────────────────────────────
        cover_frame = Frame(
            MARGIN, 28 * mm,
            FRAME_W, PAGE_H - 6 * mm - 30 * mm,
            leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
        )
        content_frame = Frame(
            MARGIN, FOOT_H,
            FRAME_W, PAGE_H - MARGIN - FOOT_H,
            leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
        )

        doc = BaseDocTemplate(
            output_path,
            pagesize=A4,
            pageTemplates=[
                PageTemplate(id='cover',   frames=[cover_frame],   onPage=draw_cover),
                PageTemplate(id='content', frames=[content_frame], onPage=draw_content),
            ],
            leftMargin=0, rightMargin=0, topMargin=0, bottomMargin=0,
        )

        # ── Story ─────────────────────────────────────────────
        story = []
        story += self._cover(client_name, target_url, date_str, auditor,
                             findings, sev_counts)
        story += [NextPageTemplate('content'), PageBreak()]
        story += self._section01_executive(executive_summary, target_url, findings)
        story += self._section02_distribution(sev_counts, findings, chart_b64)
        story += self._section03_findings(grouped)
        story += self._section04_methodology()

        doc.build(story)

    # ═══════════════════════════════════════════════════════════
    # Secciones
    # ═══════════════════════════════════════════════════════════

    def _cover(self, client_name, target_url, date_str, auditor, findings, sev_counts):
        story = []
        story.append(Spacer(1, 10 * mm))

        # Etiqueta superior
        story.append(Paragraph(
            'INFORME DE CIBERSEGURIDAD &nbsp;·&nbsp; CONFIDENCIAL',
            self._ps('Helvetica', 8.5, C_ACCENT, leading=12),
        ))
        story.append(Spacer(1, 5 * mm))

        # Título principal
        story.append(Paragraph(
            'Auditoría de<br/>Seguridad Web',
            self._ps('Helvetica-Bold', 26, C_TEXT, leading=31),
        ))
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(
            'Análisis de Vulnerabilidades — OWASP ZAP',
            self._ps('Helvetica', 13, C_MUTED, leading=18),
        ))
        story.append(Spacer(1, 4 * mm))
        story.append(HRFlowable(width=FRAME_W, thickness=0.5, color=C_BORDER, spaceAfter=6 * mm))

        # Metadatos
        has_critical = sev_counts.get('Critical', 0) > 0
        has_high     = sev_counts.get('High', 0) > 0
        total_txt    = str(len(findings))
        if has_critical:
            total_txt += '    ⚠ Incluye hallazgos CRÍTICOS'
        elif has_high:
            total_txt += '    ⚠ Incluye hallazgos de ALTA severidad'

        rows = [
            ('CLIENTE',            esc(client_name)),
            ('URL AUDITADA',       esc(target_url)),
            ('FECHA',              date_str),
            ('AUDITADO POR',       esc(auditor)),
            ('TOTAL DE HALLAZGOS', total_txt),
        ]
        meta_data = []
        for label, val in rows:
            is_url = label == 'URL AUDITADA'
            meta_data.append([
                Paragraph(label, self._ps('Helvetica', 7.5, C_MUTED2, leading=10)),
                Paragraph(val, self._ps(
                    'Helvetica-Bold', 9 if is_url else 12,
                    C_ACCENT if is_url else C_TEXT,
                    leading=12 if is_url else 15,
                )),
            ])

        meta_table = Table(meta_data, colWidths=[38 * mm, FRAME_W - 38 * mm])
        meta_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
            ('TOPPADDING',    (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4 * mm),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 4 * mm))

        # Aviso de confidencialidad
        conf_text = (
            f'<b><font color="#ff6b35">⚠ DOCUMENTO CONFIDENCIAL</font></b> — '
            f'Este informe contiene información sensible sobre la infraestructura de '
            f'seguridad de <b>{esc(client_name)}</b>. Su distribución debe limitarse '
            f'exclusivamente al personal autorizado. Queda prohibida su reproducción '
            f'o divulgación sin autorización expresa.'
        )
        conf_box = Table(
            [[Paragraph(conf_text, self._ps('Helvetica', 8, C_MUTED, leading=13))]],
            colWidths=[FRAME_W],
        )
        conf_box.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C_BG3),
            ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
            ('LINEBEFORE',    (0, 0), (0, -1),  3, HexColor('#ff6b35')),
            ('LEFTPADDING',   (0, 0), (-1, -1), 5 * mm),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 4 * mm),
            ('TOPPADDING',    (0, 0), (-1, -1), 3 * mm),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3 * mm),
        ]))
        story.append(conf_box)
        return story

    def _section01_executive(self, executive_summary, target_url, findings):
        story = []
        story += self._section_header('01', 'Resumen Ejecutivo')

        if executive_summary:
            paragraphs = [p.strip() for p in executive_summary.split('\n') if p.strip()]
        else:
            n = len(findings)
            paragraphs = [
                f'Se realizó una auditoría de seguridad web automatizada sobre '
                f'<b>{esc(target_url)}</b> utilizando OWASP ZAP. Se identificaron '
                f'<b>{n} hallazgo{"s" if n != 1 else ""}</b> de seguridad. '
                f'Se recomienda abordar los hallazgos de mayor severidad de forma prioritaria.'
            ]

        p_style = self._ps('Helvetica', 10, C_TEXT2, leading=17, align=TA_JUSTIFY)
        content = []
        for i, p in enumerate(paragraphs):
            content.append(Paragraph(esc(p), p_style))
            if i < len(paragraphs) - 1:
                content.append(Spacer(1, 3 * mm))

        box = Table([[content]], colWidths=[FRAME_W])
        box.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C_BG2),
            ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
            ('LINEBEFORE',    (0, 0), (0, -1),  4, C_ACCENT),
            ('LEFTPADDING',   (0, 0), (-1, -1), 7 * mm),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 5 * mm),
            ('TOPPADDING',    (0, 0), (-1, -1), 5 * mm),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5 * mm),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(box)
        story.append(Spacer(1, 6 * mm))
        return story

    def _section02_distribution(self, sev_counts, findings, chart_b64):
        story = []
        story += self._section_header('02', 'Distribución de Hallazgos')

        # Tarjetas de severidad
        present = [s for s in SEV_ORDER if sev_counts.get(s, 0) > 0]
        if present:
            n = len(present)
            card_w = FRAME_W / n
            cnt_style = self._ps('Helvetica-Bold', 20, C_TEXT, leading=24, align=TA_CENTER)
            lbl_style = self._ps('Helvetica', 7.5, C_MUTED, leading=10, align=TA_CENTER)

            cells = []
            for sev in present:
                c = SEVERITY_COLORS[sev]
                cells.append([
                    Paragraph(
                        f'<font color="{_hex(c)}">{sev_counts[sev]}</font>',
                        cnt_style,
                    ),
                    Paragraph(SEVERITY_ES[sev].upper(), lbl_style),
                ])

            cards = Table([cells], colWidths=[card_w] * n)
            style_cmds = [
                ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
                ('BACKGROUND',    (0, 0), (-1, -1), C_BG2),
                ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
                ('INNERGRID',     (0, 0), (-1, -1), 0.5, C_BORDER),
                ('TOPPADDING',    (0, 0), (-1, -1), 4 * mm),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4 * mm),
                ('LEFTPADDING',   (0, 0), (-1, -1), 1 * mm),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 1 * mm),
            ]
            for i, sev in enumerate(present):
                style_cmds.append(('LINEABOVE', (i, 0), (i, 0), 2.5, SEVERITY_COLORS[sev]))
            cards.setStyle(TableStyle(style_cmds))
            story.append(cards)
            story.append(Spacer(1, 5 * mm))

        # Gráfico
        chart_img = self._b64_to_image(chart_b64, max_width=FRAME_W - 8 * mm)
        chart_box = Table([[chart_img]], colWidths=[FRAME_W])
        chart_box.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C_CHART),
            ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
            ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING',    (0, 0), (-1, -1), 4 * mm),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4 * mm),
            ('LEFTPADDING',   (0, 0), (-1, -1), 4 * mm),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 4 * mm),
        ]))
        story.append(chart_box)
        story.append(Spacer(1, 5 * mm))

        # Tabla resumen
        th = self._ps('Helvetica-Bold', 7.5, C_MUTED, leading=10)
        td = self._ps('Helvetica', 9, C_TEXT2, leading=12)
        td_mono = self._ps('Courier', 8, C_MUTED, leading=11)
        td_num  = self._ps('Helvetica', 8.5, C_MUTED, leading=11, align=TA_CENTER)

        W = FRAME_W
        col_w = [8 * mm, 22 * mm, W - 8*mm - 22*mm - 20*mm - 18*mm, 20 * mm, 18 * mm]
        headers = ['#', 'Severidad', 'Vulnerabilidad', 'CWE', 'Inst.']
        tbl_data = [[Paragraph(h, th) for h in headers]]

        for i, f in enumerate(findings):
            c = SEVERITY_COLORS.get(f.risk, C_MUTED)
            badge = f'<font color="{_hex(c)}"><b>{SEVERITY_ES.get(f.risk, f.risk).upper()}</b></font>'
            cwe = f'CWE-{f.cwe_id}' if f.cwe_id else '—'
            tbl_data.append([
                Paragraph(str(i + 1), td_num),
                Paragraph(badge, td),
                Paragraph(esc(f.name), td),
                Paragraph(cwe, td_mono),
                Paragraph(str(f.count), td_num),
            ])

        tbl_styles = [
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING',   (0, 0), (-1, -1), 3 * mm),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 3 * mm),
            ('TOPPADDING',    (0, 0), (-1, -1), 2.5 * mm),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5 * mm),
            ('BACKGROUND',    (0, 0), (-1, 0),  C_BG3),
            ('LINEBELOW',     (0, 0), (-1, 0),  0.5, C_BORDER),
        ]
        for i in range(1, len(tbl_data)):
            bg = C_BG2 if i % 2 == 1 else C_BG
            tbl_styles += [
                ('BACKGROUND', (0, i), (-1, i), bg),
                ('LINEBELOW',  (0, i), (-1, i), 0.3, C_BORDER2),
            ]

        summary = Table(tbl_data, colWidths=col_w)
        summary.setStyle(TableStyle(tbl_styles))
        story.append(summary)
        story.append(Spacer(1, 6 * mm))
        return story

    def _section03_findings(self, grouped):
        story = []
        story += self._section_header('03', 'Hallazgos Detallados')

        first = True
        for severity, group_findings in grouped.items():
            if not first:
                story.append(PageBreak())

            # Encabezado de grupo
            sev_color = SEVERITY_COLORS[severity]
            sev_bg    = SEVERITY_BG[severity]
            desc_map  = {
                'Critical':      'Requiere atención inmediata. Explotación activa probable.',
                'High':          'Alta prioridad. Riesgo significativo para el negocio.',
                'Medium':        'Prioridad media. Debe remediarse en el corto plazo.',
                'Low':           'Impacto limitado. Remediar en ciclo de mantenimiento.',
                'Informational': 'Sin impacto directo. Buenas prácticas recomendadas.',
            }
            n = len(group_findings)
            grp_content = [
                Paragraph(
                    f'{SEVERITY_ES[severity].upper()} — {n} hallazgo{"s" if n != 1 else ""}',
                    self._ps('Helvetica-Bold', 13, sev_color, leading=16),
                ),
                Spacer(1, 2),
                Paragraph(
                    desc_map.get(severity, ''),
                    self._ps('Helvetica', 9, C_MUTED, leading=13),
                ),
            ]
            grp_box = Table([[grp_content]], colWidths=[FRAME_W])
            grp_box.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (-1, -1), sev_bg),
                ('LINEBEFORE',    (0, 0), (0, -1),  5, sev_color),
                ('LEFTPADDING',   (0, 0), (-1, -1), 5 * mm),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 4 * mm),
                ('TOPPADDING',    (0, 0), (-1, -1), 4 * mm),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4 * mm),
                ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(grp_box)
            story.append(Spacer(1, 4 * mm))

            for finding in group_findings:
                story.append(self._finding_card(finding, severity))
                story.append(Spacer(1, 5 * mm))

            first = False
        return story

    def _finding_card(self, finding, severity):
        sev_color  = SEVERITY_COLORS[severity]
        conf_label = CONFIDENCE_LABELS.get(str(finding.confidence), str(finding.confidence))

        meta_parts = []
        if finding.plugin_id:
            meta_parts.append(f'Plugin: {finding.plugin_id}')
        if finding.cwe_id:
            meta_parts.append(f'CWE-{finding.cwe_id}')
        if finding.wasc_id:
            meta_parts.append(f'WASC-{finding.wasc_id}')
        meta_parts.append(f'Instancias: {finding.count}')

        # Header
        RIGHT_W = 42 * mm
        LEFT_W  = CARD_IW - RIGHT_W

        header_left = [
            Paragraph(esc(finding.name),
                      self._ps('Helvetica-Bold', 11, C_TEXT, leading=14)),
            Spacer(1, 1.5 * mm),
            Paragraph('  '.join(meta_parts),
                      self._ps('Helvetica', 7.5, C_MUTED, leading=11)),
        ]
        header_right = [
            Paragraph(
                f'<font color="{_hex(sev_color)}"><b>{SEVERITY_ES[severity].upper()}</b></font>',
                self._ps('Helvetica-Bold', 9, C_TEXT, leading=13, align=TA_RIGHT),
            ),
            Spacer(1, 2),
            Paragraph(
                f'Confianza: {conf_label}',
                self._ps('Helvetica', 7.5, C_MUTED, leading=11, align=TA_RIGHT),
            ),
        ]

        hdr_inner = Table([[header_left, header_right]],
                          colWidths=[LEFT_W, RIGHT_W])
        hdr_inner.setStyle(TableStyle([
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
            ('TOPPADDING',    (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        card_header = Table([[hdr_inner]], colWidths=[FRAME_W])
        card_header.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C_BG3),
            ('LINEBELOW',     (0, 0), (-1, -1), 0.5, C_BORDER),
            ('LEFTPADDING',   (0, 0), (-1, -1), CARD_PAD),
            ('RIGHTPADDING',  (0, 0), (-1, -1), CARD_PAD),
            ('TOPPADDING',    (0, 0), (-1, -1), 3.5 * mm),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5 * mm),
        ]))

        # Body
        sec_title_style = self._ps('Helvetica-Bold', 7.5, C_ACCENT, leading=11)
        body_style      = self._ps('Helvetica', 9.5, C_TEXT2, leading=15, align=TA_JUSTIFY)

        body = []

        # Descripción
        desc = esc(finding.description_es or finding.description or 'Sin descripción disponible.')
        body += [
            Paragraph('DESCRIPCIÓN', sec_title_style),
            HRFlowable(width='100%', thickness=0.3, color=C_BG3, spaceAfter=2),
            Paragraph(desc, body_style),
            Spacer(1, 3 * mm),
        ]

        # Evidencia
        body.append(Paragraph('EVIDENCIA DETECTADA', sec_title_style))
        body.append(HRFlowable(width='100%', thickness=0.3, color=C_BG3, spaceAfter=2))
        if finding.instances:
            ev_th  = self._ps('Helvetica-Bold', 7, C_MUTED, leading=9)
            ev_td  = self._ps('Courier', 7, C_TEXT2, leading=10)
            W_ev   = CARD_IW
            cols   = [W_ev - 70*mm, 14*mm, 22*mm, 34*mm]

            ev_data = [[Paragraph(h, ev_th) for h in ['URL', 'Método', 'Parámetro', 'Evidencia']]]
            for inst in finding.instances[:3]:
                ev_str = inst.evidence or '—'
                if len(ev_str) > 55:
                    ev_str = ev_str[:55] + '…'
                ev_data.append([
                    Paragraph(esc(inst.uri or '—'), ev_td),
                    Paragraph(esc(inst.method or '—'), ev_td),
                    Paragraph(esc(inst.param or '—'), ev_td),
                    Paragraph(esc(ev_str), ev_td),
                ])
            extra = len(finding.instances) - 3
            span_style = [('SPAN', (0, len(ev_data)), (-1, len(ev_data)))] if extra > 0 else []
            if extra > 0:
                ev_data.append([
                    Paragraph(
                        f'+ {extra} instancia{"s" if extra != 1 else ""} adicional no mostrada',
                        self._ps('Helvetica', 7.5, C_MUTED, leading=10, align=TA_CENTER),
                    ),
                    Paragraph('', ev_td), Paragraph('', ev_td), Paragraph('', ev_td),
                ])

            ev_styles = [
                ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
                ('LEFTPADDING',   (0, 0), (-1, -1), 2 * mm),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 2 * mm),
                ('TOPPADDING',    (0, 0), (-1, -1), 1.5 * mm),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 1.5 * mm),
                ('BACKGROUND',    (0, 0), (-1, 0),  C_BG3),
                ('LINEBELOW',     (0, 0), (-1, 0),  0.5, C_BORDER),
                ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
                ('INNERGRID',     (0, 0), (-1, -1), 0.3, C_BORDER2),
            ]
            for i in range(1, len(ev_data)):
                ev_styles.append(('BACKGROUND', (0, i), (-1, i), C_BG2 if i % 2 == 1 else C_BG))
            ev_styles += span_style

            ev_table = Table(ev_data, colWidths=cols)
            ev_table.setStyle(TableStyle(ev_styles))
            body.append(ev_table)
        else:
            body.append(Paragraph(
                '<i>No se registraron instancias específicas.</i>',
                self._ps('Helvetica', 8.5, C_MUTED2, leading=12),
            ))

        body.append(Spacer(1, 3 * mm))

        # Solución
        sol = esc(finding.solution_es or finding.solution or 'Consultar la documentación de OWASP.')
        body += [
            Paragraph('SOLUCIÓN RECOMENDADA', sec_title_style),
            HRFlowable(width='100%', thickness=0.3, color=C_BG3, spaceAfter=2),
            Paragraph(sol, body_style),
        ]

        # Referencias
        if finding.reference:
            refs = [r.strip() for r in finding.reference.split('\n') if r.strip()]
            if refs:
                body.append(Spacer(1, 3 * mm))
                body.append(Paragraph('REFERENCIAS', sec_title_style))
                body.append(HRFlowable(width='100%', thickness=0.3, color=C_BG3, spaceAfter=2))
                for ref in refs[:4]:
                    body.append(Paragraph(
                        esc(ref),
                        self._ps('Courier', 7.5, C_MUTED2, leading=11),
                    ))

        card_body = Table([[body]], colWidths=[FRAME_W])
        card_body.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C_BG2),
            ('LEFTPADDING',   (0, 0), (-1, -1), CARD_PAD),
            ('RIGHTPADDING',  (0, 0), (-1, -1), CARD_PAD),
            ('TOPPADDING',    (0, 0), (-1, -1), 4 * mm),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4 * mm),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ]))

        card = Table([[card_header], [card_body]], colWidths=[FRAME_W])
        card.setStyle(TableStyle([
            ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
            ('TOPPADDING',    (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        return card

    def _section04_methodology(self):
        story = [PageBreak()]
        story += self._section_header('04', 'Metodología')

        story.append(Paragraph(
            'Esta auditoría fue realizada utilizando herramientas y metodologías estándar '
            'de la industria, alineadas con los frameworks internacionales de seguridad.',
            self._ps('Helvetica', 9.5, C_MUTED, leading=15),
        ))
        story.append(Spacer(1, 5 * mm))

        # Grid 2×2
        items = [
            ('Herramienta de Escaneo',
             'OWASP ZAP (Zed Attack Proxy) — escáner de seguridad web de código abierto '
             'mantenido por la Open Web Application Security Project Foundation.'),
            ('Estándar de referencia',
             'OWASP Top 10 — lista de las vulnerabilidades web más críticas. Los hallazgos '
             'están categorizados según CWE (Common Weakness Enumeration).'),
            ('Tipo de análisis',
             'Análisis dinámico (DAST) — pruebas realizadas sobre la aplicación en ejecución, '
             'simulando ataques reales desde el exterior.'),
            ('Enriquecimiento con IA',
             'Las descripciones y recomendaciones fueron procesadas con Claude (Anthropic) '
             'para ofrecer un lenguaje claro y orientado al negocio.'),
        ]

        cell_w = FRAME_W / 2 - 1.5 * mm

        def meth_cell(title, body_txt):
            inner = Table(
                [[Paragraph(title, self._ps('Helvetica-Bold', 9, C_ACCENT, leading=12))],
                 [Paragraph(body_txt, self._ps('Helvetica', 8.5, C_MUTED, leading=13))]],
                colWidths=[cell_w - 6 * mm],
            )
            inner.setStyle(TableStyle([
                ('LEFTPADDING',   (0, 0), (-1, -1), 0),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
                ('TOPPADDING',    (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (0, 0), 2),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 0),
                ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ]))
            outer = Table([[inner]], colWidths=[cell_w])
            outer.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (-1, -1), C_BG2),
                ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
                ('LINEBEFORE',    (0, 0), (0, -1),  3, C_ACCENT),
                ('LEFTPADDING',   (0, 0), (-1, -1), 4 * mm),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 3 * mm),
                ('TOPPADDING',    (0, 0), (-1, -1), 3 * mm),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3 * mm),
            ]))
            return outer

        grid = Table(
            [[meth_cell(*items[0]), meth_cell(*items[1])],
             [meth_cell(*items[2]), meth_cell(*items[3])]],
            colWidths=[FRAME_W / 2, FRAME_W / 2],
        )
        grid.setStyle(TableStyle([
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (0, -1),  1.5 * mm),
            ('RIGHTPADDING',  (1, 0), (1, -1),  0),
            ('TOPPADDING',    (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, 0),  1.5 * mm),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 0),
        ]))
        story.append(grid)
        story.append(Spacer(1, 5 * mm))

        # Lista de pasos
        steps = [
            ('01', 'Reconocimiento pasivo y mapeo de la aplicación objetivo'),
            ('02', 'Escaneo activo de vulnerabilidades con OWASP ZAP'),
            ('03', 'Análisis y clasificación de hallazgos por severidad (CVSS)'),
            ('04', 'Validación manual de hallazgos de alta criticidad'),
            ('05', 'Generación de recomendaciones de remediación'),
            ('06', 'Documentación y elaboración del informe final'),
        ]
        for num, text in steps:
            row = Table(
                [[Paragraph(num, self._ps('Helvetica-Bold', 9, C_ACCENT, leading=12)),
                  Paragraph(text, self._ps('Helvetica', 9, C_TEXT2, leading=12))]],
                colWidths=[8 * mm, FRAME_W - 8 * mm],
            )
            row.setStyle(TableStyle([
                ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING',   (0, 0), (0, -1),  3 * mm),
                ('LEFTPADDING',   (1, 0), (1, -1),  3 * mm),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 3 * mm),
                ('TOPPADDING',    (0, 0), (-1, -1), 2.5 * mm),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5 * mm),
            ]))
            outer = Table([[row]], colWidths=[FRAME_W])
            outer.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (-1, -1), C_BG2),
                ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
                ('LEFTPADDING',   (0, 0), (-1, -1), 0),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
                ('TOPPADDING',    (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ]))
            story.append(outer)
            story.append(Spacer(1, 1.5 * mm))

        story.append(Spacer(1, 4 * mm))

        # Nota de alcance
        scope_text = (
            '<b><font color="#e6edf3">Alcance y limitaciones:</font></b> '
            'Este informe representa los resultados del escaneo automatizado realizado en la '
            'fecha indicada. Los resultados son válidos únicamente para el estado de la '
            'aplicación en el momento del análisis. Se recomienda repetir la auditoría '
            'periódicamente y ante cambios significativos. Un escaneo DAST automatizado puede '
            'generar falsos positivos; se recomienda validar manualmente los hallazgos críticos '
            'antes de iniciar la remediación.'
        )
        scope_box = Table(
            [[Paragraph(scope_text, self._ps('Helvetica', 8.5, C_MUTED, leading=14))]],
            colWidths=[FRAME_W],
        )
        scope_box.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C_BG2),
            ('BOX',           (0, 0), (-1, -1), 0.5, C_BORDER),
            ('LINEBEFORE',    (0, 0), (0, -1),  3, C_BORDER),
            ('LEFTPADDING',   (0, 0), (-1, -1), 5 * mm),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 4 * mm),
            ('TOPPADDING',    (0, 0), (-1, -1), 3 * mm),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3 * mm),
        ]))
        story.append(scope_box)
        return story

    # ═══════════════════════════════════════════════════════════
    # Helpers
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def _ps(font, size, color, leading=None, align=TA_LEFT) -> ParagraphStyle:
        """Crea un ParagraphStyle con los parámetros dados."""
        return ParagraphStyle(
            f'_ps_{font}_{size}',
            fontName=font,
            fontSize=size,
            textColor=color,
            leading=leading or size * 1.4,
            alignment=align,
        )

    def _section_header(self, number: str, title: str) -> list:
        """Devuelve la lista de flowables que forman el encabezado de sección."""
        num_badge = Table(
            [[Paragraph(number, self._ps('Helvetica-Bold', 8, C_BG, leading=11, align=TA_CENTER))]],
            colWidths=[9 * mm],
        )
        num_badge.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C_ACCENT),
            ('LEFTPADDING',   (0, 0), (-1, -1), 1 * mm),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 1 * mm),
            ('TOPPADDING',    (0, 0), (-1, -1), 1.5 * mm),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 1.5 * mm),
            ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        hdr_row = Table(
            [[num_badge,
              Paragraph(title, self._ps('Helvetica-Bold', 14, C_TEXT, leading=18))]],
            colWidths=[11 * mm, FRAME_W - 11 * mm],
        )
        hdr_row.setStyle(TableStyle([
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
            ('TOPPADDING',    (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2 * mm),
        ]))
        wrapper = Table([[hdr_row]], colWidths=[FRAME_W])
        wrapper.setStyle(TableStyle([
            ('LINEBELOW',     (0, 0), (-1, -1), 2, C_ACCENT),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
            ('TOPPADDING',    (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        return [wrapper, Spacer(1, 5 * mm)]

    @staticmethod
    def _b64_to_image(b64_str: str, max_width: float = None) -> Image:
        """Convierte una cadena base64 PNG a un flowable Image de reportlab."""
        img_data = base64.b64decode(b64_str)
        buf = io.BytesIO(img_data)
        img = Image(buf)
        if max_width and img.drawWidth > max_width:
            ratio = max_width / img.drawWidth
            img.drawWidth  = max_width
            img.drawHeight = img.drawHeight * ratio
        return img

    def _build_severity_chart(self, findings: List[Finding]) -> str:
        order  = ['Critical', 'High', 'Medium', 'Low', 'Informational']
        counts = self._count_by_severity(findings)
        labels = [s for s in order if counts.get(s, 0) > 0]
        values = [counts[s] for s in labels]
        clrs   = [CHART_HEX[s] for s in labels]
        lbls_es = [SEVERITY_ES[s] for s in labels]

        fig, ax = plt.subplots(
            figsize=(7, max(2.5, len(labels) * 0.7)),
            facecolor='#12121e',
        )
        ax.set_facecolor('#12121e')
        bars = ax.barh(lbls_es[::-1], values[::-1], color=clrs[::-1],
                       height=0.55, edgecolor='none')
        for bar, val in zip(bars, values[::-1]):
            ax.text(
                bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                str(val), va='center', ha='left',
                color='white', fontsize=11, fontweight='bold',
            )
        ax.set_xlabel('Cantidad de hallazgos', color='#aaaaaa', fontsize=10)
        ax.tick_params(axis='y', colors='#e0e0e0', labelsize=11)
        ax.tick_params(axis='x', colors='#666666', labelsize=9)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['bottom'].set_color('#333355')
        ax.spines['left'].set_color('#333355')
        ax.set_xlim(0, max(values) + max(values) * 0.25 + 1)
        plt.tight_layout(pad=0.5)
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150, bbox_inches='tight', facecolor='#12121e')
        plt.close(fig)
        buf.seek(0)
        return base64.b64encode(buf.read()).decode('utf-8')

    @staticmethod
    def _count_by_severity(findings: List[Finding]) -> dict:
        counts: dict = {}
        for f in findings:
            counts[f.risk] = counts.get(f.risk, 0) + 1
        return counts

    @staticmethod
    def _group_by_severity(findings: List[Finding]) -> dict:
        order   = ['Critical', 'High', 'Medium', 'Low', 'Informational']
        grouped = {s: [] for s in order}
        for f in findings:
            grouped.setdefault(f.risk, []).append(f)
        return {k: v for k, v in grouped.items() if v}

    @staticmethod
    def _format_date() -> str:
        months = ['', 'enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio',
                  'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre']
        now = datetime.now()
        return f'{now.day} de {months[now.month]} de {now.year}'
