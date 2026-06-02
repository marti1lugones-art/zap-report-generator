# ZAP Report Generator — Security Audit Suite

Herramienta de auditoría de seguridad web que genera reportes PDF profesionales en español. Combina el análisis dinámico de OWASP ZAP con tres módulos de chequeo automático que corren directamente sobre cualquier URL, sin necesitar ZAP instalado.

## Modos de uso

### Auditoría completa (recomendado)

Corre los tres módulos de chequeo automático contra el sitio y genera el reporte:

```bash
python audit.py --url "https://sitio.com" --client "Empresa S.A."
```

### Auditoría completa + resultados de ZAP

Combina los chequeos automáticos con un reporte XML exportado de OWASP ZAP:

```bash
python audit.py --url "https://sitio.com" --client "Empresa S.A." --input scan.xml
```

### Solo procesamiento de ZAP (modo legado)

```bash
python generate_report.py --input scan.xml --client "Empresa S.A." --url "https://sitio.com"
```

---

## Módulos de auditoría

### 1. Headers HTTP de Seguridad

Hace una request al sitio y evalúa la presencia y configuración de:

| Header | Ausente | Mal configurado |
|--------|---------|-----------------|
| Content-Security-Policy | High | Medium |
| Strict-Transport-Security (HSTS) | High | Low |
| X-Frame-Options | Medium | Low |
| X-Content-Type-Options | Low | — |
| Referrer-Policy | Low | Low |
| Permissions-Policy | Informational | — |

### 2. Configuración SSL/TLS

Analiza el certificado digital y la configuración de protocolos del servidor:

| Hallazgo | Severidad |
|----------|-----------|
| Certificado expirado | Critical |
| Certificado expira en < 14 días | High |
| Certificado expira en 15–30 días | Medium |
| Certificado auto-firmado | Medium |
| Mismatch de hostname | Critical |
| TLS 1.0 habilitado | High |
| TLS 1.1 habilitado | Medium |

No requiere dependencias externas — usa la librería `ssl` y `socket` de Python.

### 3. Seguridad de Email (SPF/DKIM/DMARC)

Consulta los registros DNS del dominio y evalúa la protección contra spoofing de correo:

| Hallazgo | Severidad |
|----------|-----------|
| Sin registro SPF | High |
| SPF con `+all` | Critical |
| SPF con `?all` (neutral) | Medium |
| SPF con `~all` (softfail) | Low |
| Sin registro DMARC | High |
| DMARC `p=none` | Medium |
| DMARC `p=quarantine` | Low |
| DKIM no encontrado en selectores comunes | Medium |

Selectores DKIM consultados: `google`, `selector1`, `selector2`, `default`, `mail`, `dkim`, `k1`.
> Nota: la ausencia en estos selectores no garantiza que DKIM no exista con un selector personalizado.

### 4. OWASP ZAP (opcional)

Procesa el XML exportado por OWASP ZAP e incluye los hallazgos del escaneo dinámico junto con los demás módulos en el mismo reporte.

---

## Reporte PDF generado

Cada corrida genera un PDF profesional con:

- **Portada** con datos del cliente, fecha y aviso de confidencialidad
- **Resumen ejecutivo** redactado en español por Claude AI, adaptado al cliente y los módulos activos
- **Distribución de hallazgos** con gráfico de barras y tabla resumen (con columna "Módulo" cuando hay múltiples fuentes)
- **Sección por módulo** con detalle de cada hallazgo: descripción en español, evidencia técnica, solución accionable
- **Metodología** con descripción del proceso de auditoría

Las descripciones y soluciones de **todos los módulos** se reescriben en español profesional usando Claude AI, independientemente de la fuente del hallazgo.

---

## Requisitos

- Python 3.9+
- `ANTHROPIC_API_KEY` (solo si no se usa `--no-ai`)
- Los módulos Headers y SSL usan solo stdlib de Python (sin dependencias extra)
- El módulo Email requiere `dnspython` (incluido en `requirements.txt`)

---

## Instalación

```bash
git clone https://github.com/tu-usuario/zap-report-generator.git
cd zap-report-generator

python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Editar .env y agregar ANTHROPIC_API_KEY
```

---

## Opciones de `audit.py`

```
python audit.py --url URL --client NOMBRE [opciones]

Requeridos:
  --url, -u         URL del sitio a auditar (ej: https://sitio.com)
  --client, -c      Nombre del cliente para la portada

Opcionales:
  --input, -i       Archivo XML de OWASP ZAP a incluir
  --output, -o      Ruta del PDF de salida (default: reporte.pdf)
  --auditor         Nombre del auditor o equipo (default: Equipo de Seguridad)
  --model           Modelo de Claude (default: claude-sonnet-4-6)
  --no-ai           Generar reporte sin llamar a la API de Anthropic
  --skip-headers    Omitir chequeo de headers HTTP
  --skip-ssl        Omitir chequeo de SSL/TLS
  --skip-email      Omitir chequeo de SPF/DKIM/DMARC
```

### Ejemplos

```bash
# Auditoría completa con IA
python audit.py --url "https://app.empresa.com" --client "Empresa S.A."

# Solo headers y SSL, sin email
python audit.py --url "https://app.empresa.com" --client "X" --skip-email

# ZAP + chequeos automáticos, sin IA (más rápido)
python audit.py --url "https://app.empresa.com" --client "X" --input scan.xml --no-ai

# Auditor personalizado y modelo más potente
python audit.py --url "https://app.empresa.com" --client "X" \
  --auditor "Juan Pérez — Red Team" --model claude-opus-4-8
```

---

## Opciones de `generate_report.py` (modo legado — solo ZAP)

```bash
python generate_report.py \
  --input scan.xml \
  --client "Empresa S.A." \
  --url "https://sitio.com" \
  --output informe.pdf
```

Compatible con todos los reportes XML de OWASP ZAP 2.x.

---

## Estructura del proyecto

```
zap-report-generator/
├── audit.py                    # CLI unificado (punto de entrada principal)
├── generate_report.py          # CLI legado (solo ZAP)
├── requirements.txt
├── .env.example
├── sample_scan.xml             # XML de ejemplo con 11 hallazgos
└── src/
    ├── parser.py               # Parser de XML de ZAP
    ├── ai_enhancer.py          # Enriquecimiento con Claude API
    ├── report_generator.py     # Generación del PDF con reportlab
    └── checkers/
        ├── headers.py          # Módulo: Headers HTTP
        ├── ssl_checker.py      # Módulo: SSL/TLS
        └── email_security.py   # Módulo: SPF/DKIM/DMARC
```

---

## Exportar XML desde OWASP ZAP

1. Ejecutar el escaneo en OWASP ZAP
2. **Report → Generate Report → XML**
3. Usar ese archivo como `--input`

O desde la línea de comandos:
```bash
./zap.sh -cmd -quickurl https://sitio.com -quickout scan.xml
```

## Licencia

MIT
