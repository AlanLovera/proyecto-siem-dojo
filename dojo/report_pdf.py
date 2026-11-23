"""PDF A4 locales a partir de un único snapshot. Sin análisis ni acceso a Excel."""

from collections import defaultdict
from datetime import date
from html import escape
from io import BytesIO
from pathlib import Path
from threading import Lock

import reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    CondPageBreak, LongTable, PageBreak, Paragraph,
    SimpleDocTemplate, Spacer, TableStyle,
)
from reportlab.platypus.doctemplate import LayoutError

from dojo.dashboard import CRITICALITIES
from dojo.report_model import counted


KINDS = {"corporativo": "Informe corporativo", "tecnico": "Informe técnico", "consolidado": "Informe consolidado"}
NAVY, BLUE, INK, MUTED = map(colors.HexColor, ("#0f2747", "#2563eb", "#1e293b", "#64748b"))
LIGHT = colors.HexColor("#f1f5f9")
WIDTH = A4[0] - 36 * mm
FONT_LOCK = Lock()


class ReportPDFError(ValueError):
    pass


class ReportDocument(SimpleDocTemplate):
    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name == "H1":
            number = getattr(self, "_outline_number", 0) + 1
            self._outline_number = number
            name = f"section-{number}"
            self.canv.bookmarkPage(name)
            self.canv.addOutlineEntry(flowable.getPlainText(), name, level=0, closed=False)


def _fonts():
    with FONT_LOCK:
        if "Dojo" not in pdfmetrics.getRegisteredFontNames():
            directory = Path(reportlab.__file__).parent / "fonts"
            pdfmetrics.registerFont(TTFont("Dojo", str(directory / "Vera.ttf")))
            pdfmetrics.registerFont(TTFont("DojoBold", str(directory / "VeraBd.ttf")))
            pdfmetrics.registerFontFamily("Dojo", normal="Dojo", bold="DojoBold", italic="Dojo", boldItalic="DojoBold")


def plain(value):
    if value is None:
        return "(Sin dato)"
    if isinstance(value, dict):
        return "; ".join(f"{k}: {plain(v)}" for k, v in value.items()) or "(Sin datos)"
    if isinstance(value, (list, tuple)):
        return "; ".join(plain(v) for v in value) or "(Sin datos)"
    return str(value)


class PDFStory:
    def __init__(self, model):
        self.m = model
        self.evidence = {e["ref"]: e for e in model["evidence"]}
        self.by_key = {(e["sha256"], e["sheet"], e["excel_row"]): e["ref"] for e in model["evidence"]}
        self.detection_refs = {f["finding_id"]: f"D{i:02d}" for i, f in enumerate(model["findings"], 1)}
        self.line_refs = {g["group_id"]: g["ref"] for g in model["lines"]}
        self.styles = {
            "body": ParagraphStyle("Body", fontName="Dojo", fontSize=9, leading=13, textColor=INK,
                                   alignment=TA_JUSTIFY, spaceAfter=6, splitLongWords=True, allowWidows=0, allowOrphans=0),
            "small": ParagraphStyle("Small", fontName="Dojo", fontSize=7.6, leading=10.5, textColor=INK, alignment=TA_JUSTIFY, spaceAfter=3, splitLongWords=True),
            "table_small": ParagraphStyle("TableSmall", fontName="Dojo", fontSize=7.6, leading=10.5, textColor=INK, alignment=TA_LEFT, spaceAfter=3, splitLongWords=True),
            "cell": ParagraphStyle("Cell", fontName="Dojo", fontSize=8, leading=11, textColor=INK, splitLongWords=True),
            "h1": ParagraphStyle("H1", fontName="DojoBold", fontSize=19, leading=24, textColor=NAVY, spaceAfter=14, keepWithNext=True),
            "h2": ParagraphStyle("H2", fontName="DojoBold", fontSize=12, leading=16, textColor=NAVY, spaceBefore=12, spaceAfter=7, keepWithNext=True),
            "h3": ParagraphStyle("H3", fontName="DojoBold", fontSize=9.5, leading=13, textColor=BLUE, spaceBefore=8, spaceAfter=5, keepWithNext=True),
        }

    def p(self, value, style="body"):
        value = plain(value)
        # Controles se representan, no se ejecutan ni se pierden silenciosamente.
        value = "".join(c if c in "\n\r" or ord(c) >= 32 else f"\\u{ord(c):04x}" for c in value)
        unsupported = {c for c in value if c not in "\n\r" and ord(c) not in pdfmetrics.getFont("Dojo").face.charToGlyph}
        if unsupported:
            codes = ", ".join(f"U+{ord(c):04X}" for c in sorted(unsupported))
            raise ReportPDFError(f"La fuente Unicode incluida no cubre {codes}. No se sustituye ni trunca el texto.")
        markup = escape(value).replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br/>")
        return Paragraph(markup, self.styles[style])

    def refs(self, refs, include_ids=False):
        """Vínculos internos al anexo; no launch actions ni URLs del Excel."""
        refs = list(dict.fromkeys(refs))
        return Paragraph(" · ".join(f'<link href="#ev-{r}" color="#2563eb">{r}</link>'
                                    + (" / " + escape(plain(self.evidence[r]["values"]["Log_ID"])) if include_ids else "") for r in refs)
                         or "Sin referencias", self.styles["table_small"])

    def proof_refs(self, proofs):
        return [self.by_key[(e["sha256"], e["sheet"], e["excel_row"])] for e in proofs]

    def table(self, rows, widths, header=True, small=False):
        data = [[cell if isinstance(cell, Paragraph) else self.p(cell, "table_small" if small else "cell") for cell in row] for row in rows]
        table = LongTable(data, colWidths=[WIDTH * w for w in widths], repeatRows=1 if header else 0,
                          hAlign="LEFT", splitByRow=1, splitInRow=1)
        commands = [("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                    ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0"))]
        if header:
            commands += [("BACKGROUND", (0, 0), (-1, 0), LIGHT),
                         ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fafbfd")])]
        table.setStyle(TableStyle(commands))
        return table

    def bullets(self, items):
        return [self.p("- " + plain(item)) for item in items]

    def title(self, kind):
        m, source = self.m, self.m["provenance"]
        return [self.p("DOJO SIEM Analyzer / CASO FICTICIO", "h3"), self.p(KINDS[kind], "h1"),
                self.p(m["case_name"], "h2"),
                self.p(f"Emisión: {m['issued_date']} | Alcance: exportación local de SIEM, hoja completa."),
                self.p(f"Período interpretable: {source['time_start'] or '(Sin dato)'} a {source['time_end'] or '(Sin dato)'}. {source['timezone']}.", "small"),
                self.table([["Identificación", "Referencia"], ["Archivo / hoja", f"{source['file']} / {source['sheet']}"],
                            ["SHA-256 del Excel", source["sha256"]], ["Análisis", m["analysis_id"]],
                            ["Correlación", m["correlation_id"]], ["Snapshot de informe", m["report_id"]]], [.25, .75], small=True),
                Spacer(1, 8 * mm)]

    def summary_table(self):
        m, s = self.m, self.m["summary"]
        return self.table([["Registros analizados", "Fuentes de logs", "Activaciones", "Líneas", "Eventos asociados únicos"],
                           [m["provenance"]["records"], len(m["sources"]), s["detections"], s["groups"], s["unique_events"]]], [.20] * 5)

    def line_summary(self):
        rows = [["Línea / investigación", "Criticidad", "Confianza", "Estado", "Eventos"]]
        for line in self.m["lines"]:
            rows.append([f"{line['ref']} / {line['title']}", line["severity"]["label"], line["confidence"]["label"],
                         line["investigation_state"], len(line["evidence_refs"])])
        return self.table(rows, [.40, .14, .13, .20, .13], small=True)

    def corporate(self):
        m, s = self.m, self.m["summary"]
        story = self.title("corporativo")
        story += [self.p("Resumen ejecutivo", "h2")] + [self.p(p) for p in m["executive_summary"]]
        story += [self.p(p) for p in m["executive_observations"]]
        story += [self.summary_table(), self.p("Una activación de regla no equivale a un incidente. Los eventos de contexto no se presumen maliciosos.", "small"),
                  self.p("Alcance y certeza", "h2"), self.p(m["conclusion"]), PageBreak(),
                  self.p("Prioridades y líneas de investigación", "h1"),
                  self.table([["Criticidad potencial", *CRITICALITIES], ["Líneas", *[s["severities"].get(c, 0) for c in CRITICALITIES]]], [.28, .18, .18, .18, .18]),
                  self.line_summary(), self.p("Trazabilidad detallada por línea y evento: consultar el informe técnico del mismo snapshot.", "small"), self.p("Confianza, estado e impacto", "h2"),
                  self.p("Confianza observacional: " + plain(s["confidences"]) + ". Estados: " + plain(s["states"]) + ". No son probabilidades de ataque."),
                  self.p("Impactos potenciales / efectos no confirmados", "h3")]
        impacts = defaultdict(list)
        for line in m["lines"]:
            for impact in line["severity"]["potential_impacts"]:
                impacts[impact["description"]].append(line["ref"])
        story += self.bullets([f"{', '.join(refs)}: {description}" for description, refs in impacts.items()]
                              or ["No se aportan impactos confirmados; ampliar evidencia antes de valorar consecuencias."])
        story += [PageBreak(), self.p("Decisiones sugeridas y límites", "h1")]
        story += self.bullets([item["decision"] for item in m["priorities"]] or ["Sin líneas activas para priorizar; no acredita ausencia de actividad."])
        for key, label in [("investigation", "Investigación"), ("containment", "Contención condicionada"), ("remediation", "Remediación condicionada")]:
            story += [self.p(label, "h3"), self.p(m["recommendation_policy"][key])]
        story += [self.p("Limitaciones relevantes", "h2")]
        story += self.bullets(m["limitations"])
        partial = [v for v, d in zip(m["coverage"], m["diagnostics"]) if d["state"] != "evaluada"]
        story += self.bullets(partial)
        story += [self.p("Conclusión", "h2"), self.p(m["conclusion"])]
        return story

    def technical(self):
        m, s = self.m, self.m["summary"]
        story = self.title("tecnico") + [self.summary_table(), self.p("Alcance de este documento", "h2"),
            self.p(m["conclusion"]), self.p("Estructura: metodología y configuración; detecciones; desarrollo de cada línea; catálogo de vínculos; anexo único de evidencias. Las referencias E apuntan al anexo y conservan su relación con cada detección y línea."),
            PageBreak(), self.p("1. Fuentes, metodología y cobertura", "h1"),
            self.p(f"Versiones consumidas: normalización {m['normalization_version']}, detección {m['engine_version']}, correlación {m['correlation_version']}, riesgo {m['risk_version']}; informe {m['version']}. Sin IA ni ejecución de reglas al exportar."),
            self.table([["Fuente de logs", "Registros"], *[[k, v] for k, v in m["sources"].items()]], [.75, .25]),
            self.p("Severity original del SIEM", "h2"), self.table([["Etiqueta original", "Eventos"], *[[k, v] for k, v in m["siem_severities"].items()]], [.75, .25]),
            self.p("Severidad original, criticidad calculada y confianza son dimensiones independientes. Valores originales preservados; sin alias de host ni zona horaria inferidos.")]
        story += [self.p("Cobertura por regla", "h2"), self.table([["Regla", "Estado", "Candidatos", "Utilizables", "Incompletos"],
            *[[d["rule_id"], d["state"], d["candidate_records"], d["eligible_records"], d["skipped_incomplete"]] for d in m["diagnostics"]]], [.22, .21, .19, .19, .19]),
            self.p(f"Observaciones de importación: {len(m['import_issues'])}; normalización: {len(m['normalization_issues'])}. No se corrigen ni completan valores.")]
        for d in m["diagnostics"]:
            if d["missing_by_field"]:
                story.append(self.p(f"{d['rule_id']} / faltantes por campo: {plain(d['missing_by_field'])}. Un registro puede faltar en varios campos.", "small"))
        story += [self.p("Reglas habilitadas y parámetros efectivos", "h2")]
        for rule in m["rules"]:
            story += [self.p(f"{rule['rule_id']} / {rule['name']}", "h3"), self.p(rule["conditions"]),
                      self.p("Parámetros: " + plain(rule["parameters"]), "small")]
            story += self.bullets(rule["limitations"])
        story += [self.p("Correlación y modelo de clasificación consumidos", "h2"),
                  self.p("Parámetros de correlación: " + plain(m["correlation_parameters"])),
                  self.p("Agrupación de enlace completo con vínculos directos. El contexto temporal no acredita causalidad. Se conserva el scoring ya calculado; no se suman reglas superpuestas."),
                  self.table([["Configuración del modelo", "Valor efectivo"], *[[k, plain(v)] for k, v in m["risk_model"].items()]], [.36, .64], small=True),
                  self.p("Calidad de origen y observaciones", "h2"), self.table([["Columna", "Faltantes", "% faltante"],
                  *[[d["columna"], d["faltantes"], d["porcentaje_faltante"]] for d in m["quality"]]], [.5, .25, .25], small=True)]
        for title, issues in [("Importación", m["import_issues"]), ("Normalización", m["normalization_issues"])]:
            if issues:
                story += [self.p(title, "h3")]
                story += [self.p(plain(issue), "small") for issue in issues]
        story += [PageBreak(), self.p("2. Detecciones y líneas de investigación", "h1"), self.line_summary(),
                  self.p(f"{counted(s['event_references'], 'referencia en detecciones', 'referencias en detecciones')}; {counted(s['duplicate_event_references'], 'repetición eliminada del agregado', 'repeticiones eliminadas del agregado')}; {counted(s['unique_events'], 'evento único', 'eventos únicos')}. {counted(s['primary_unique_events'], 'evento tiene rol primario', 'eventos tienen rol primario')} en alguna detección."),
                  self.p("Registro de activaciones", "h2")]
        for f in m["findings"]:
            story += [self.p(f"{self.detection_refs[f['finding_id']]} / {f['rule_id']} / {f['status']}", "h3"),
                      self.p(f["finding_id"], "small"), self.p(m["finding_narratives"][f["finding_id"]]), self.p("Parámetros utilizados: " + plain(f["parameters"]), "small"),
                      self.refs(self.proof_refs(f["evidence"]))]
        for line in m["lines"]:
            story += [PageBreak()] + self.line(line)
        story += [PageBreak(), self.p("3. Catálogo de vínculos observacionales", "h1"),
                  self.p("Fuerte describe el criterio de agrupación; contextual/temporal no fusiona líneas ni eleva riesgo. Todos los vínculos conservan causal=false. Los testigos remiten al anexo completo.")]
        for link in m["links"]:
            group_refs = [self.line_refs[g] for g in link["group_ids"]]
            story += [CondPageBreak(40 * mm), self.p(f"{link['kind'].capitalize()} / {', '.join(group_refs)}", "h3"), self.p(link["link_id"], "small"),
                      self.p("Agrupación: " + ("utilizado" if link["used_for_grouping"] else "no utilizado") + "; " + plain(link.get("not_merged_reason", "asociación sin atribución causal")), "small")]
            for criterion in link["criteria"]:
                story += [self.p(criterion["reason"]), self.p(f"Criterio {criterion['criterion']}; campos {plain(criterion['matched_fields'])}; ventana {criterion['window_seconds']} s; diferencia/duración {criterion['observed_seconds']} s; base {criterion['window_basis']}.", "small"),
                          self.refs(self.proof_refs(criterion["evidence"]))]
        if not m["links"]:
            story.append(self.p("Sin vínculos registrados en el resultado recibido."))
        story += [self.p("Conclusión técnica", "h2"), self.p(m["conclusion"])]
        story += self.bullets(m["limitations"])
        story += [PageBreak(), self.p("4. Anexo probatorio de registros originales", "h1"),
                  self.p(f"{counted(len(m['evidence']), 'evento único asociado', 'eventos únicos asociados')}, sin truncamiento. Cada ficha contiene valores originales, procedencia y roles por línea/detección. Un evento compartido aparece una sola vez; las relaciones se conservan."),
                  self.p("P01 / procedencia común", "h2"), self.p(m["provenance"]["file"]),
                  self.p("SHA-256: " + m["provenance"]["sha256"], "small"), self.p("Hoja: " + m["provenance"]["sheet"]),
                  self.p("E0001… son referencias locales al snapshot, no sustituyen Log_ID. Timestamp se conserva literal; zona horaria no especificada. Sin dato representa una celda ausente; cadenas '-' permanecen literales. Los comandos son texto inerte. No se generan enlaces ejecutables al libro.", "small")]
        for evidence in m["evidence"]:
            story += self.evidence_card(evidence)
        if not m["evidence"]:
            story.append(self.p("Sin registros asociados para anexar; no demuestra ausencia de actividad."))
        return story

    def line(self, line):
        story = [self.p(f"{line['ref']} / {line['title']}", "h1"), self.p(line["group_id"], "small"),
                 self.p(f"Clasificación: {line['classification_id']}", "small"),
                 self.table([["Criticidad potencial", "Confianza observacional", "Estado"],
                             [f"{line['severity']['label']} / {counted(line['severity']['score'], 'punto', 'puntos')}", f"{line['confidence']['label']} / {counted(line['confidence']['score'], 'punto', 'puntos')}", line["investigation_state"]]], [.34, .36, .30]),
                 self.p(line["report_description"]), self.p("Reglas: " + ", ".join(line["rules"]), "small"),
                 self.p("Hechos observados", "h2")]
        facts = line["facts"]
        labels = {"unique_events": "Eventos únicos", "primary_events": "Con rol primario", "event_counts": "Event_ID / cantidad",
                  "failed_authentications": "Fallos de autenticación", "distinct_failed_accounts": "Cuentas distintas con fallos",
                  "later_authentications": "Autenticaciones posteriores", "outbound_post_events": "POST salientes",
                  "recorded_bytes_out": "Bytes salientes registrados", "suspicious_web_requests": "Solicitudes con comando", "http_events": "Eventos HTTP"}
        story.append(self.table([["Hecho", "Valor registrado"], *[[label, plain(facts[k])] for k, label in labels.items()]], [.48, .52], small=True))
        for obs in facts["behavior_observations"]:
            story += [self.p(obs["statement"]), self.refs(self.proof_refs(obs["evidence"]))]
        story += [self.p("Interpretaciones pendientes e hipótesis", "h2")] + self.bullets(line["hypotheses"])
        story += [self.p("Explicaciones alternativas", "h3")] + self.bullets(line["alternatives"])
        story += [self.p("Correlación sustentada y su alcance", "h2"), self.p(line["grouping_method"])]
        for bridge in line["corroborations"]:
            story += [self.p(bridge["activity"]), self.p(bridge["scope"]),
                      self.p(f"Campos coincidentes: {plain(bridge['fields'])}; ventana {bridge['window_seconds']} s; diferencia {bridge['observed_seconds']} s.", "small"),
                      self.refs(self.proof_refs(bridge["evidence"]))]
        if not line["corroborations"]:
            story.append(self.p("No se aportó corroboración adicional de actividad/coincidencia conforme al modelo vigente."))
        story += [self.p(f"Vínculos internos: {len(line['links'])}; externos: {len(line['external_links'])}. Criterios y testigos completos en el catálogo de vínculos.", "small"),
                  self.p("Justificación de criticidad", "h2"), self.p(line["severity"]["scope"])]
        factors = [f for f in line["severity"]["factors"] if f["active"]]
        story.append(self.table([["Factor observado", "Puntos / peso", "Fundamento y evidencia"],
            *[[f["factor"], f"{f['points']} / {f['weight']}", self.p(f["reason"] + (" Suprimido por " + f["suppressed_by"] if f["suppressed_by"] else ""), "small")] for f in factors]], [.31, .16, .53], small=True))
        for impact in line["severity"]["potential_impacts"]:
            story.append(self.p(impact["description"]))
        story += [self.p("Justificación de confianza", "h3"), self.p(line["confidence"]["scope"]),
                  self.table([["Criterio", "Cumple / puntos", "Fundamento"], *[[f["factor"], f"{f['active']} / {f['points']}", f["reason"]] for f in line["confidence"]["factors"]]], [.30, .20, .50], small=True)]
        if line["review"]:
            story += [self.p("Revisión explícita del analista", "h3"), self.p(line["review"]["reason"]),
                      self.p(f"Estado automático: {line['automatic_state']}; revisión: {line['investigation_state']}. Decisión no validada externamente."),
                      self.refs(self.proof_refs(line["review"]["evidence"]))]
        story += [self.p("Línea temporal / timestamps originales", "h2")]
        story.append(self.table([["Referencia / Log_ID", "Timestamp original", "Event_ID / función"],
            *[[self.refs([r], include_ids=True), self.evidence[r]["values"]["Timestamp"],
               f"{self.evidence[r]['values']['Event_ID']} / " + ("primaria" if next(v for v in self.evidence[r]["memberships"] if v["group_id"] == line["group_id"])["primary"] else "contextual")]
              for r in line["timeline_refs"]]], [.22, .40, .38], small=True))
        story.append(self.p("Los empates no acreditan orden causal; fechas no interpretables quedan al final. Log_ID y campos originales completos en la ficha enlazada.", "small"))
        indicators = {field: sorted({plain(self.evidence[r]["values"][field]) for r in line["evidence_refs"]})
                      for field in ("User", "Hostname", "Source_IP", "Destination")}
        story += [self.p("Valores observados / contexto de investigación", "h3"),
                  self.p("No constituyen IoC maliciosos validados ni atribución geográfica."),
                  self.table([["Campo", "Valores registrados"], *[[k, plain(v)] for k, v in indicators.items()]], [.25, .75], small=True),
                  self.p("Recomendaciones / propuestas, no acciones ejecutadas", "h2")]
        for key, title in [("investigation", "Investigación"), ("containment", "Contención condicionada"), ("remediation", "Remediación condicionada")]:
            story += [self.p(title, "h3")] + self.bullets(line["recommendations"][key])
        story += [self.p("Información faltante y limitaciones", "h2")]
        story += self.bullets(list(dict.fromkeys(line["missing_information"] + line["limitations"])))
        return story

    def evidence_card(self, evidence):
        ref, values = evidence["ref"], evidence["values"]
        heading = self.p(f"{ref} / Log_ID {plain(values['Log_ID'])} / fila Excel {evidence['excel_row']}", "h3")
        heading.text = f'<a name="ev-{ref}"/>' + heading.text
        # Reparsear el markup interno ya escapado para registrar el destino PDF.
        heading = Paragraph(heading.text, self.styles["h3"])
        relation = []
        for membership in evidence["memberships"]:
            roles = "; ".join(f"{self.detection_refs[d]}: {', '.join(v)}" for d, v in membership["detection_roles"].items())
            relation.append(f"{membership['line']} ({'primaria' if membership['primary'] else 'contextual'}): {roles}")
        rows = [["Procedencia", f"P01 / {evidence['file']} / hoja {evidence['sheet']} / fila Excel {evidence['excel_row']}"],
                ["Relaciones y roles", " | ".join(relation)],
                ["Timestamp / Event_ID", f"{plain(values['Timestamp'])} | {plain(values['Event_ID'])} (tipo Excel {evidence['event_id_excel_type']})"],
                ["Host / usuario", f"{plain(values['Hostname'])} | {plain(values['User'])}"],
                ["IP / destino", f"{plain(values['Source_IP'])} | {plain(values['Destination'])}"],
                ["Fuente / resultado / Severity", f"{plain(values['Log_Source'])} | {plain(values['Result'])} | {plain(values['Severity'])}"],
                ["Descripción original", values["Event_Description"]], ["Comando original", values["Process_CommandLine"]]]
        for column in self.m["provenance"]["columns"]:
            if column not in ("Log_ID", "Timestamp", "Event_ID", "Hostname", "User", "Source_IP", "Destination", "Log_Source", "Result", "Severity", "Event_Description", "Process_CommandLine"):
                rows.append([column, values[column]])
        return [CondPageBreak(36 * mm), heading, self.table(rows, [.27, .73], header=False, small=True), Spacer(1, 3 * mm)]


def generate_pdf(model, kind):
    if kind not in KINDS:
        raise ReportPDFError("Tipo de informe desconocido.")
    _fonts()
    builder = PDFStory(model)
    story = []
    if kind in ("corporativo", "consolidado"):
        story += builder.corporate()
    if kind == "consolidado":
        story += [PageBreak()]
    if kind in ("tecnico", "consolidado"):
        story += builder.technical()
    buffer = BytesIO()
    doc = ReportDocument(buffer, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
                            topMargin=22 * mm, bottomMargin=20 * mm,
                            title=f"DOJO SIEM Analyzer - {KINDS[kind]} - Caso ficticio", author="DOJO SIEM Analyzer",
                            subject=f"Caso ficticio; snapshot {model['report_id']}", pageCompression=1, invariant=1)

    def page(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(BLUE)
        canvas.setLineWidth(1)
        canvas.line(18 * mm, A4[1] - 16 * mm, A4[0] - 18 * mm, A4[1] - 16 * mm)
        canvas.setFont("DojoBold", 8)
        canvas.setFillColor(NAVY)
        canvas.drawString(18 * mm, A4[1] - 12 * mm, "DOJO SIEM Analyzer / CASO FICTICIO")
        canvas.setFont("Dojo", 7)
        canvas.drawRightString(A4[0] - 18 * mm, A4[1] - 12 * mm, KINDS[kind])
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 11 * mm, model["report_id"] + " / zona horaria de logs no especificada")
        canvas.drawRightString(A4[0] - 18 * mm, 11 * mm, f"Página {document.page}")
        canvas.restoreState()

    def snapshot_canvas(*args, **kwargs):
        canvas = Canvas(*args, **kwargs)
        # Precisión de día: no inventar hora ni zona para la emisión. El modo
        # invariante conserva el resto de metadatos/IDs reproducibles.
        canvas.setDateFormatter(lambda *_: "D:" + date.fromisoformat(model["issued_date"]).strftime("%Y%m%d"))
        return canvas

    try:
        doc.build(story, onFirstPage=page, onLaterPages=page, canvasmaker=snapshot_canvas)
    except LayoutError as exc:
        raise ReportPDFError("El contenido excede el diseño disponible. No se entrega un PDF parcial ni se trunca evidencia.") from exc
    return buffer.getvalue()
