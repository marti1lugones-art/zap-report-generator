# ZAP Report Generator

Convierte reportes XML de OWASP ZAP en PDFs de auditoría de seguridad profesionales, con descripciones en español generadas por Claude (Anthropic).

## Ejemplo de salida

El reporte generado incluye:

- **Portada** con datos del cliente, URL auditada y fecha
- **Resumen ejecutivo** redactado en español profesional por Claude AI
- **Gráfico de distribución** de hallazgos por severidad
- **Tabla resumen** con totales por categoría
- **Detalle de cada hallazgo** con descripción, impacto, evidencia técnica y solución accionable
- **Sección de metodología** con descripción del proceso de auditoría

Diseño oscuro y profesional, listo para entregar a clientes corporativos.

## Características

- Parsea el formato XML nativo de OWASP ZAP
- Traduce y profesionaliza cada hallazgo al español usando `claude-sonnet-4-6`
- Genera el resumen ejecutivo automáticamente con contexto del cliente
- Produce un PDF con diseño oscuro de alta calidad usando WeasyPrint
- Gráfico de barras horizontal con distribución de severidades
- Modo `--no-ai` para generar el PDF sin llamar a la API (texto original en inglés)
- CLI simple con todas las opciones configurables

## Requisitos

- Python 3.9+
- ANTHROPIC_API_KEY (solo si no usás `--no-ai`)
- WeasyPrint requiere dependencias del sistema (ver abajo)

### Dependencias del sistema para WeasyPrint

**macOS:**
```bash
brew install pango libffi
```

**Ubuntu/Debian:**
```bash
sudo apt-get install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libfontconfig1
```

## Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/zap-report-generator.git
cd zap-report-generator

# 2. Crear entorno virtual (recomendado)
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# 3. Instalar dependencias Python
pip install -r requirements.txt

# 4. Configurar API key
cp .env.example .env
# Editar .env y agregar tu ANTHROPIC_API_KEY
```

## Configuración

Crear un archivo `.env` en la raíz del proyecto:

```env
ANTHROPIC_API_KEY=sk-ant-...
```

O exportar la variable directamente en el entorno:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

## Uso

### Ejemplo básico

```bash
python generate_report.py \
  --input scan.xml \
  --client "Empresa S.A." \
  --url "https://app.empresa.com" \
  --output reporte_auditoria.pdf
```

### Sin llamadas a la API (modo offline)

```bash
python generate_report.py \
  --input scan.xml \
  --client "Empresa S.A." \
  --url "https://app.empresa.com" \
  --no-ai
```

### Todas las opciones

```bash
python generate_report.py \
  --input scan.xml \
  --client "Empresa S.A." \
  --url "https://app.empresa.com" \
  --output reporte.pdf \
  --auditor "Equipo Red Team" \
  --model claude-opus-4-7
```

### Opciones disponibles

| Opción | Descripción | Default |
|--------|-------------|---------|
| `--input`, `-i` | Ruta al archivo XML de ZAP | *(requerido)* |
| `--client`, `-c` | Nombre del cliente para la portada | *(requerido)* |
| `--url`, `-u` | URL auditada | *(requerido)* |
| `--output`, `-o` | Ruta del PDF generado | `reporte.pdf` |
| `--auditor` | Nombre del auditor o equipo | `Equipo de Seguridad` |
| `--model` | Modelo de Claude a usar | `claude-sonnet-4-6` |
| `--no-ai` | Omitir la API de Anthropic | `false` |

## Exportar el XML desde OWASP ZAP

1. Ejecutar el escaneo en OWASP ZAP
2. Ir a **Report → Generate Report...**
3. Seleccionar formato **XML**
4. Guardar el archivo y usarlo como `--input`

También se puede exportar desde la línea de comandos de ZAP:

```bash
./zap.sh -cmd -quickurl https://sitio.com -quickout /tmp/scan.xml
```

## Probar con el ejemplo incluido

El repositorio incluye un XML de muestra con 9 hallazgos realistas:

```bash
python generate_report.py \
  --input sample_scan.xml \
  --client "Acme Corp" \
  --url "https://app.acmecorp.com" \
  --output demo.pdf
```

## Estructura del proyecto

```
zap-report-generator/
├── generate_report.py        # CLI principal
├── requirements.txt          # Dependencias Python
├── .env.example              # Template de configuración
├── sample_scan.xml           # XML de ejemplo con 9 hallazgos
└── src/
    ├── __init__.py
    ├── parser.py             # Parser del XML de ZAP
    ├── ai_enhancer.py        # Integración con la API de Anthropic
    ├── report_generator.py   # Generación del PDF con WeasyPrint
    └── templates/
        └── report.html       # Template Jinja2 del reporte
```

## Severidades soportadas

| Nivel | Color | Descripción |
|-------|-------|-------------|
| Critical | Rojo | Vulnerabilidades de impacto crítico |
| High | Naranja | Riesgo alto, remediación urgente |
| Medium | Amarillo | Riesgo moderado |
| Low | Azul | Bajo impacto |
| Informational | Gris | Sin impacto directo, buenas prácticas |

## Limitaciones

- El tiempo de generación depende de la cantidad de hallazgos y la latencia de la API de Claude (aproximadamente 3–5 segundos por hallazgo con `--model claude-sonnet-4-6`)
- WeasyPrint no soporta JavaScript, por lo que el template HTML es completamente estático
- El modo `--no-ai` genera el reporte con el texto original en inglés de ZAP, sin traducción ni profesionalización

## Licencia

MIT
