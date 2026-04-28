import io
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional

# PDF Generation
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, HRFlowable,
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.legends import Legend

# For map generation
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt

# Report color scheme
class ReportColors:
    PRIMARY = colors.HexColor('#1e3a5f')      # Dark blue
    SECONDARY = colors.HexColor('#3b82f6')    # Blue
    ACCENT = colors.HexColor('#10b981')       # Green
    WARNING = colors.HexColor('#f59e0b')      # Orange
    DANGER = colors.HexColor('#ef4444')       # Red
    SUCCESS = colors.HexColor('#22c55e')      # Green
    LIGHT_GRAY = colors.HexColor('#f3f4f6')   # Light gray
    DARK_GRAY = colors.HexColor('#374151')    # Dark gray
    WHITE = colors.white
    BLACK = colors.black


class PCAPReportGenerator:
    #Generate professional PDF reports for PCAP analysis

    def __init__(self, output_path: str = None):
       
        self.output_path = output_path
        self.buffer = io.BytesIO()
        self.styles = self._create_styles()
        self.page_width, self.page_height = A4
        self.margin = 0.75 * inch
        self.content_width = self.page_width - (2 * self.margin)

    def _create_styles(self) -> Dict[str, ParagraphStyle]:
        base_styles = getSampleStyleSheet()

        styles = {
            'title': ParagraphStyle(
                'CustomTitle',
                parent=base_styles['Title'],
                fontSize=28,
                textColor=ReportColors.PRIMARY,
                spaceAfter=6,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'subtitle': ParagraphStyle(
                'CustomSubtitle',
                parent=base_styles['Normal'],
                fontSize=12,
                textColor=ReportColors.DARK_GRAY,
                spaceAfter=20,
                alignment=TA_CENTER,
                fontName='Helvetica'
            ),
            'heading1': ParagraphStyle(
                'CustomH1',
                parent=base_styles['Heading1'],
                fontSize=16,
                textColor=ReportColors.PRIMARY,
                spaceBefore=20,
                spaceAfter=12,
                fontName='Helvetica-Bold',
                borderPadding=(0, 0, 5, 0),
                borderWidth=0,
                borderColor=ReportColors.PRIMARY
            ),
            'heading2': ParagraphStyle(
                'CustomH2',
                parent=base_styles['Heading2'],
                fontSize=13,
                textColor=ReportColors.SECONDARY,
                spaceBefore=15,
                spaceAfter=8,
                fontName='Helvetica-Bold'
            ),
            'heading3': ParagraphStyle(
                'CustomH3',
                parent=base_styles['Heading3'],
                fontSize=11,
                textColor=ReportColors.DARK_GRAY,
                spaceBefore=10,
                spaceAfter=6,
                fontName='Helvetica-Bold'
            ),
            'body': ParagraphStyle(
                'CustomBody',
                parent=base_styles['Normal'],
                fontSize=10,
                textColor=ReportColors.DARK_GRAY,
                spaceAfter=8,
                alignment=TA_JUSTIFY,
                fontName='Helvetica',
                leading=14
            ),
            'body_center': ParagraphStyle(
                'CustomBodyCenter',
                parent=base_styles['Normal'],
                fontSize=10,
                textColor=ReportColors.DARK_GRAY,
                spaceAfter=8,
                alignment=TA_CENTER,
                fontName='Helvetica'
            ),
            'caption': ParagraphStyle(
                'CustomCaption',
                parent=base_styles['Normal'],
                fontSize=9,
                textColor=ReportColors.DARK_GRAY,
                spaceAfter=12,
                alignment=TA_CENTER,
                fontName='Helvetica-Oblique'
            ),
            'footer': ParagraphStyle(
                'CustomFooter',
                parent=base_styles['Normal'],
                fontSize=8,
                textColor=colors.gray,
                alignment=TA_CENTER,
                fontName='Helvetica'
            ),
            'metric_value': ParagraphStyle(
                'MetricValue',
                parent=base_styles['Normal'],
                fontSize=24,
                textColor=ReportColors.PRIMARY,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'metric_label': ParagraphStyle(
                'MetricLabel',
                parent=base_styles['Normal'],
                fontSize=9,
                textColor=ReportColors.DARK_GRAY,
                alignment=TA_CENTER,
                fontName='Helvetica'
            ),
            'grade_a': ParagraphStyle(
                'GradeA',
                fontSize=36,
                textColor=ReportColors.SUCCESS,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'grade_b': ParagraphStyle(
                'GradeB',
                fontSize=36,
                textColor=ReportColors.ACCENT,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'grade_c': ParagraphStyle(
                'GradeC',
                fontSize=36,
                textColor=ReportColors.WARNING,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'grade_d': ParagraphStyle(
                'GradeD',
                fontSize=36,
                textColor=colors.HexColor('#f97316'),
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'grade_f': ParagraphStyle(
                'GradeF',
                fontSize=36,
                textColor=ReportColors.DANGER,
                alignment=TA_CENTER,
                fontName='Helvetica-Bold'
            ),
            'note': ParagraphStyle(
                'Note',
                parent=base_styles['Normal'],
                fontSize=9,
                textColor=ReportColors.DARK_GRAY,
                spaceBefore=6,
                spaceAfter=6,
                alignment=TA_CENTER,
                fontName='Helvetica-Oblique',
                backColor=ReportColors.LIGHT_GRAY,
                borderPadding=8
            )
        }

        return styles

    def _create_header(self, canvas, doc):
        canvas.saveState()

        canvas.setStrokeColor(ReportColors.PRIMARY)
        canvas.setLineWidth(2)
        canvas.line(self.margin, self.page_height - 0.5 * inch,
                    self.page_width - self.margin, self.page_height - 0.5 * inch)

        canvas.setFont('Helvetica-Bold', 10)
        canvas.setFillColor(ReportColors.PRIMARY)
        canvas.drawString(self.margin, self.page_height - 0.4 * inch, "PCAP Network Analysis Report")

        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(ReportColors.DARK_GRAY)
        date_str = datetime.now().strftime("%d %B %Y")
        canvas.drawRightString(self.page_width - self.margin, self.page_height - 0.4 * inch, date_str)

        canvas.restoreState()

    def _create_footer(self, canvas, doc):
        canvas.saveState()

        canvas.setStrokeColor(ReportColors.LIGHT_GRAY)
        canvas.setLineWidth(1)
        canvas.line(self.margin, 0.5 * inch, self.page_width - self.margin, 0.5 * inch)

        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(ReportColors.DARK_GRAY)
        page_num = f"Page {doc.page}"
        canvas.drawCentredString(self.page_width / 2, 0.3 * inch, page_num)

        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(colors.gray)
        canvas.drawString(self.margin, 0.3 * inch, "Generated by PCAP Analyzer")

        canvas.restoreState()

    def _header_footer(self, canvas, doc):
        self._create_header(canvas, doc)
        self._create_footer(canvas, doc)

    def _create_section_header(self, title: str) -> List:
        elements = []
        elements.append(Paragraph(title, self.styles['heading1']))
        elements.append(HRFlowable(
            width="100%",
            thickness=2,
            color=ReportColors.PRIMARY,
            spaceBefore=0,
            spaceAfter=10
        ))
        return elements

    def _create_metric_card(self, value: str, label: str, color: colors.Color = None) -> Table:
        if color is None:
            color = ReportColors.PRIMARY

        value_len = len(str(value))
        if value_len > 8:
            font_size = 14
        elif value_len > 5:
            font_size = 16
        else:
            font_size = 20

        value_style = ParagraphStyle(
            'MetricValueCustom',
            fontSize=font_size,
            textColor=color,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            leading=font_size + 4
        )

        data = [
            [Paragraph(str(value), value_style)],
            [Paragraph(label, self.styles['metric_label'])]
        ]

        table = Table(data, colWidths=[1.4 * inch])
        table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 0), (-1, -1), ReportColors.LIGHT_GRAY),
            ('BOX', (0, 0), (-1, -1), 1, ReportColors.LIGHT_GRAY),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))

        return table

    def _create_metrics_row(self, metrics: List[Dict]) -> Table:
        #Create a row of metric cards.
        cards = []
        for metric in metrics:
            card = self._create_metric_card(
                metric['value'],
                metric['label'],
                metric.get('color', ReportColors.PRIMARY)
            )
            cards.append(card)

        num_metrics = len(metrics)
        if num_metrics <= 4:
            col_width = self.content_width / num_metrics
        else:
            col_width = self.content_width / 5

        table = Table([cards], colWidths=[col_width] * len(metrics))
        table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 3),
            ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ]))

        return table

    def _create_protocol_pie_chart(self, protocol_data: Dict) -> Optional[Drawing]:
        #Create a pie chart for protocol distribution.
        if not protocol_data:
            return None

        labels = list(protocol_data.keys())[:8]
        values = [protocol_data[k]['count'] for k in labels]
        total = sum(values)
        if total <= 0:
            return None

        percentages = [(v / total) * 100 for v in values]

        pie_colors = [
            ReportColors.PRIMARY,
            ReportColors.SECONDARY,
            ReportColors.ACCENT,
            ReportColors.WARNING,
            colors.HexColor('#8b5cf6'),
            colors.HexColor('#ec4899'),
            colors.HexColor('#06b6d4'),
            colors.HexColor('#84cc16'),
        ]

        drawing = Drawing(400, 200)

        pie = Pie()
        pie.x = 50
        pie.y = 25
        pie.width = 150
        pie.height = 150
        pie.data = values
        pie.labels = None
        pie.slices.strokeWidth = 1
        pie.slices.strokeColor = colors.white

        for i in range(min(len(values), len(pie_colors))):
            pie.slices[i].fillColor = pie_colors[i]

        drawing.add(pie)

        legend = Legend()
        legend.x = 220
        legend.y = 150
        legend.dx = 8
        legend.dy = 8
        legend.fontName = 'Helvetica'
        legend.fontSize = 9
        legend.boxAnchor = 'nw'
        legend.columnMaximum = 8
        legend.strokeWidth = 0
        legend.strokeColor = None
        legend.deltax = 75
        legend.deltay = 10
        legend.autoXPadding = 5
        legend.yGap = 0
        legend.dxTextSpace = 5
        legend.alignment = 'right'
        legend_data = [(pie_colors[i], f"{labels[i]}: {percentages[i]:.1f}%") for i in range(len(labels))]
        legend.colorNamePairs = legend_data
        drawing.add(legend)

        return drawing

    def _create_bar_chart(self, data: List[tuple], title: str,
                          color: colors.Color = None, max_items: int = 10) -> Optional[Drawing]:
        #Create a horizontal bar chart.
        if not data:
            return None

        if color is None:
            color = ReportColors.SECONDARY

        data = data[:max_items]

        labels = [str(item[0])[:30] for item in data]
        values = [item[1] for item in data]

        labels = labels[::-1]
        values = values[::-1]

        max_val = max(values) if values else 1

        drawing = Drawing(500, 25 + len(data) * 22)

        chart = HorizontalBarChart()
        chart.x = 120
        chart.y = 10
        chart.width = 350
        chart.height = max(len(data) * 20, 80)
        chart.data = [values]
        chart.categoryAxis.categoryNames = labels
        chart.categoryAxis.labels.fontName = 'Helvetica'
        chart.categoryAxis.labels.fontSize = 8
        chart.categoryAxis.labels.dx = -5
        chart.valueAxis.valueMin = 0
        chart.valueAxis.valueMax = max_val * 1.1
        chart.valueAxis.labels.fontName = 'Helvetica'
        chart.valueAxis.labels.fontSize = 8
        chart.bars[0].fillColor = color
        chart.bars[0].strokeColor = None
        chart.barWidth = 15

        drawing.add(chart)

        return drawing

    def _create_table(self, headers: List[str], rows: List[List],
                      col_widths: List = None) -> Table:
        #Create a styled table.
        table_data = [headers] + rows

        if col_widths:
            table = Table(table_data, colWidths=col_widths)
        else:
            table = Table(table_data)

        style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), ReportColors.PRIMARY),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('TEXTCOLOR', (0, 1), (-1, -1), ReportColors.DARK_GRAY),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, ReportColors.LIGHT_GRAY]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
            ('BOX', (0, 0), (-1, -1), 1, ReportColors.PRIMARY),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ])

        table.setStyle(style)
        return table

    def _create_world_map(self, geolocation: Dict) -> Optional[io.BytesIO]:
        #Generate a static world map image with IP locations and visible continents.
        if not geolocation or not geolocation.get('available'):
            return None

        try:
            fig, ax = plt.subplots(1, 1, figsize=(10, 5), facecolor='white')

            ax.set_xlim(-180, 180)
            ax.set_ylim(-90, 90)
            ax.set_facecolor('#dbeafe')

            continents = {
                'north_america': [
                    (-168, 65), (-168, 72), (-140, 70), (-130, 72), (-120, 75),
                    (-85, 75), (-80, 72), (-65, 60), (-55, 50), (-65, 45),
                    (-75, 35), (-80, 25), (-90, 20), (-105, 20), (-118, 32),
                    (-125, 48), (-168, 65)
                ],
                'south_america': [
                    (-80, 10), (-60, 10), (-35, -5), (-35, -20), (-55, -55),
                    (-70, -55), (-75, -45), (-70, -20), (-80, -5), (-80, 10)
                ],
                'europe': [
                    (-10, 35), (0, 35), (5, 45), (10, 45), (25, 35), (40, 40),
                    (40, 55), (60, 70), (30, 72), (10, 70), (-10, 60), (-10, 35)
                ],
                'africa': [
                    (-15, 35), (-5, 35), (10, 30), (35, 30), (50, 10), (50, -5),
                    (40, -20), (30, -35), (20, -35), (15, -25), (-5, 5), (-15, 10),
                    (-20, 15), (-15, 35)
                ],
                'asia': [
                    (40, 40), (60, 35), (70, 35), (80, 25), (90, 25), (100, 20),
                    (105, 10), (120, 25), (125, 35), (130, 45), (140, 45), (145, 50),
                    (160, 65), (180, 68), (180, 75), (100, 78), (70, 75), (60, 70),
                    (40, 55), (40, 40)
                ],
                'australia': [
                    (115, -20), (130, -12), (150, -12), (155, -25), (150, -38),
                    (140, -38), (130, -32), (115, -32), (115, -20)
                ]
            }

            for _name, coords in continents.items():
                if coords:
                    xs, ys = zip(*coords)
                    ax.fill(xs, ys, color='#e8e8e8', edgecolor='#cccccc', linewidth=0.5, zorder=1)

            for lat in range(-60, 90, 30):
                ax.axhline(y=lat, color='#cccccc', linewidth=0.3, alpha=0.5, zorder=0)
            for lon in range(-150, 180, 30):
                ax.axvline(x=lon, color='#cccccc', linewidth=0.3, alpha=0.5, zorder=0)

            connection_lines = geolocation.get('connection_lines', [])
            for line in connection_lines[:30]:
                if all(k in line for k in ['src_lon', 'src_lat', 'dst_lon', 'dst_lat']):
                    slat, slon = line.get('src_lat'), line.get('src_lon')
                    dlat, dlon = line.get('dst_lat'), line.get('dst_lon')
                    if slat is not None and dlat is not None and slon is not None and dlon is not None:
                        ax.plot(
                            [slon, dlon], [slat, dlat],
                            color='#ef4444', alpha=0.5, linewidth=1.5, zorder=3
                        )

            dst_points = geolocation.get('dst_map_points', [])
            dst_lons = [p['lon'] for p in dst_points if not p.get('is_private') and p.get('lon') is not None]
            dst_lats = [p['lat'] for p in dst_points if not p.get('is_private') and p.get('lat') is not None]
            if dst_lons and dst_lats:
                ax.scatter(dst_lons, dst_lats, c='#10b981', s=60, marker='D',
                          label='Destination', zorder=5, edgecolors='white', linewidths=1.5)

            src_points = geolocation.get('src_map_points', [])
            src_lons = [p['lon'] for p in src_points if not p.get('is_private') and p.get('lon') is not None]
            src_lats = [p['lat'] for p in src_points if not p.get('is_private') and p.get('lat') is not None]
            if src_lons and src_lats:
                ax.scatter(src_lons, src_lats, c='#3b82f6', s=70, marker='o',
                          label='Source', zorder=6, edgecolors='white', linewidths=1.5)

            ax.set_xlabel('Longitude', fontsize=9, color='#374151')
            ax.set_ylabel('Latitude', fontsize=9, color='#374151')
            ax.tick_params(axis='both', labelsize=8, colors='#374151')
            ax.legend(loc='lower left', fontsize=8, framealpha=0.9)

            ax.set_title('Geographic Distribution of Network Traffic',
                        fontsize=11, fontweight='bold', color='#1e3a5f', pad=10)

            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)

            plt.tight_layout()

            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight',
                        facecolor='white', edgecolor='none')
            plt.close(fig)
            img_buffer.seek(0)

            return img_buffer

        except Exception as e:
            print(f"Error creating map: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return None

    def _get_grade_style(self, grade: str) -> ParagraphStyle:
        grade_styles = {
            'A': self.styles['grade_a'],
            'B': self.styles['grade_b'],
            'C': self.styles['grade_c'],
            'D': self.styles['grade_d'],
            'F': self.styles['grade_f'],
        }
        return grade_styles.get(str(grade).upper() if grade else 'F', self.styles['grade_f'])

    def _get_severity_color(self, severity: str) -> colors.Color:
        severity_colors = {
            'low': ReportColors.SUCCESS,
            'medium': ReportColors.WARNING,
            'high': colors.HexColor('#f97316'),
            'critical': ReportColors.DANGER,
        }
        return severity_colors.get(str(severity).lower() if severity else 'low', ReportColors.DARK_GRAY)

    def _format_bytes(self, bytes_val: int) -> str:
        if bytes_val is None or bytes_val < 0:
            return "0 B"
        if bytes_val >= 1_000_000_000:
            return f"{bytes_val / 1_000_000_000:.2f} GB"
        elif bytes_val >= 1_000_000:
            return f"{bytes_val / 1_000_000:.2f} MB"
        elif bytes_val >= 1_000:
            return f"{bytes_val / 1_000:.2f} KB"
        return f"{bytes_val} B"

    def _sanitize_text(self, text: str) -> str:
        if not text:
            return text or ""

        replacements = {
            '\u0101': 'a', '\u012b': 'i', '\u016b': 'u', '\u0113': 'e', '\u014d': 'o',
            '\u0100': 'A', '\u012a': 'I', '\u016a': 'U', '\u0112': 'E', '\u014c': 'O',
            '\u00e1': 'a', '\u00ed': 'i', '\u00fa': 'u', '\u00e9': 'e', '\u00f3': 'o',
            '\u00e0': 'a', '\u00ec': 'i', '\u00f9': 'u', '\u00e8': 'e', '\u00f2': 'o',
            '\u00e4': 'a', '\u00ef': 'i', '\u00fc': 'u', '\u00eb': 'e', '\u00f6': 'o',
            '\u00e2': 'a', '\u00ee': 'i', '\u00fb': 'u', '\u00ea': 'e', '\u00f4': 'o',
            '\u00e3': 'a', '\u00f1': 'n', '\u00f5': 'o',
            '\u00e7': 'c', '\u00c7': 'C',
            '\u00df': 'ss',
            '\u2013': '-', '\u2014': '-',
            '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
            '\u2026': '...',
        }

        result = str(text)
        for unicode_char, ascii_char in replacements.items():
            result = result.replace(unicode_char, ascii_char)

        try:
            result = result.encode('ascii', 'ignore').decode('ascii')
        except (UnicodeDecodeError, UnicodeEncodeError):
            result = result.encode('ascii', 'replace').decode('ascii')

        return result or "Unknown"

    def generate_report(self, filename: str, summary: Dict, analysis: Dict,
                        geolocation: Dict, file_size: int = 0) -> io.BytesIO:
        
        summary = summary or {}
        analysis = analysis or {}
        geolocation = geolocation or {}

        doc = SimpleDocTemplate(
            self.buffer,
            pagesize=A4,
            rightMargin=self.margin,
            leftMargin=self.margin,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch
        )

        elements = []

        # ==================== TITLE PAGE ====================
        elements.append(Spacer(1, 1 * inch))

        elements.append(Paragraph("PCAP Network Analysis Report", self.styles['title']))
        elements.append(Spacer(1, 0.2 * inch))

        elements.append(Paragraph(
            "Comprehensive Analysis of Network Traffic Capture",
            self.styles['subtitle']
        ))

        elements.append(Spacer(1, 0.5 * inch))

        file_info_data = [
            ['Filename:', filename or 'Unknown'],
            ['File Size:', self._format_bytes(file_size)],
            ['Analysis Date:', datetime.now().strftime("%d %B %Y, %H:%M:%S")],
            ['Total Packets:', f"{summary.get('total_packets', 0):,}"],
            ['Capture Duration:', f"{summary.get('capture_duration', 0):.2f} seconds"],
        ]

        file_info_table = Table(file_info_data, colWidths=[1.5 * inch, 3 * inch])
        file_info_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (-1, -1), ReportColors.DARK_GRAY),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('BACKGROUND', (0, 0), (-1, -1), ReportColors.LIGHT_GRAY),
            ('BOX', (0, 0), (-1, -1), 1, ReportColors.PRIMARY),
        ]))
        elements.append(file_info_table)

        elements.append(Spacer(1, 0.5 * inch))

        traffic_summary = analysis.get('traffic', {}).get('summary', {})
        tcp_health = analysis.get('tcp', {}).get('health_score', {})

        quick_metrics = [
            {'value': f"{summary.get('total_packets', 0):,}", 'label': 'Total Packets', 'color': ReportColors.PRIMARY},
            {'value': self._format_bytes(summary.get('total_bytes', 0)), 'label': 'Total Data', 'color': ReportColors.SECONDARY},
            {'value': f"{traffic_summary.get('packets_per_sec', 0):.1f}", 'label': 'Packets/sec', 'color': ReportColors.ACCENT},
            {'value': str(tcp_health.get('grade', 'N/A')), 'label': 'Health Grade',
             'color': ReportColors.DANGER if tcp_health.get('grade') == 'F' else ReportColors.SUCCESS},
        ]
        elements.append(self._create_metrics_row(quick_metrics))

        elements.append(PageBreak())

        # ==================== TABLE OF CONTENTS ====================
        elements.extend(self._create_section_header("Table of Contents"))

        toc_items = [
            ("1. Executive Summary", "Overview of key findings"),
            ("2. Traffic Analysis", "Protocol distribution and traffic patterns"),
            ("3. Top Talkers", "Most active IP addresses"),
            ("4. Port Analysis", "Service and port usage"),
            ("5. TCP Health Assessment", "Connection quality and issues"),
            ("6. Geographic Analysis", "IP location distribution"),
            ("7. Observations", "Key insights and recommendations"),
        ]

        toc_data = [[Paragraph(f"<b>{item[0]}</b>", self.styles['body']),
                     Paragraph(item[1], self.styles['body'])] for item in toc_items]

        toc_table = Table(toc_data, colWidths=[2.8 * inch, 3.5 * inch])
        toc_table.setStyle(TableStyle([
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LINEBELOW', (0, 0), (-1, -2), 0.5, ReportColors.LIGHT_GRAY),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(toc_table)

        elements.append(PageBreak())

        # ==================== 1. EXECUTIVE SUMMARY ====================
        elements.extend(self._create_section_header("1. Executive Summary"))

        total_packets = summary.get('total_packets', 0)
        total_bytes = summary.get('total_bytes', 0)
        duration = summary.get('capture_duration', 0)
        protocols = summary.get('protocols_found', [])
        health_grade = tcp_health.get('grade', 'N/A')
        health_score = float(tcp_health.get('score', 0))

        grade_desc = 'excellent' if health_grade == 'A' else 'good' if health_grade == 'B' else 'moderate' if health_grade == 'C' else 'poor' if health_grade == 'D' else 'critical'

        protocols_str = ', '.join(str(p) for p in protocols[:5]) + ('...' if len(protocols) > 5 else '') if protocols else 'none'
        summary_text = f"""
        This report presents a comprehensive analysis of the network packet capture file
        <b>{filename or 'Unknown'}</b>. The capture contains <b>{total_packets:,} packets</b> totaling
        <b>{self._format_bytes(total_bytes)}</b> of data collected over <b>{duration:.2f} seconds</b>.

        The traffic analysis identified <b>{len(protocols)} distinct protocols</b> including
        {protocols_str}.

        The TCP health assessment resulted in a grade of <b>{health_grade}</b> with a score of
        <b>{health_score:.1f}/100</b>, indicating {grade_desc}
        network connection quality during the capture period.
        """
        elements.append(Paragraph(summary_text.strip(), self.styles['body']))

        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("<b>Key Metrics at a Glance</b>", self.styles['heading2']))

        geo_data = geolocation if geolocation.get('available') else {}

        key_metrics = [
            {'value': f"{total_packets:,}", 'label': 'Total Packets', 'color': ReportColors.PRIMARY},
            {'value': self._format_bytes(total_bytes), 'label': 'Total Bytes', 'color': ReportColors.SECONDARY},
            {'value': f"{duration:.1f}s", 'label': 'Duration', 'color': ReportColors.ACCENT},
            {'value': str(len(protocols)), 'label': 'Protocols', 'color': ReportColors.WARNING},
            {'value': str(geo_data.get('total_countries', 0)), 'label': 'Countries', 'color': colors.HexColor('#8b5cf6')},
        ]
        elements.append(self._create_metrics_row(key_metrics))

        elements.append(PageBreak())

        # ==================== 2. TRAFFIC ANALYSIS ====================
        elements.extend(self._create_section_header("2. Traffic Analysis"))

        traffic_data = analysis.get('traffic', {})
        protocol_dist = traffic_data.get('protocol_distribution', {})
        if isinstance(protocol_dist, dict) and protocol_dist.get('error'):
            protocol_dist = {}

        elements.append(Paragraph("<b>Traffic Overview</b>", self.styles['heading2']))

        traffic_metrics = [
            {'value': f"{traffic_summary.get('packets_per_sec', 0):.2f}", 'label': 'Packets/sec', 'color': ReportColors.PRIMARY},
            {'value': self._format_bytes(int(traffic_summary.get('bytes_per_sec', 0) or 0)), 'label': 'Throughput/sec', 'color': ReportColors.SECONDARY},
            {'value': str(summary.get('unique_src_ips', 0)), 'label': 'Source IPs', 'color': ReportColors.ACCENT},
            {'value': str(summary.get('unique_dst_ips', 0)), 'label': 'Dest IPs', 'color': ReportColors.WARNING},
        ]
        elements.append(self._create_metrics_row(traffic_metrics))

        elements.append(Spacer(1, 0.3 * inch))

        if protocol_dist:
            elements.append(Paragraph("<b>Protocol Distribution</b>", self.styles['heading2']))

            pie_chart = self._create_protocol_pie_chart(protocol_dist)
            if pie_chart:
                elements.append(pie_chart)
                elements.append(Paragraph("Figure 1: Distribution of protocols in the capture", self.styles['caption']))

            protocol_rows = []
            sorted_protocols = sorted(protocol_dist.items(), key=lambda x: (x[1].get('count', 0) if isinstance(x[1], dict) else 0), reverse=True)[:10]
            for protocol, data in sorted_protocols:
                if isinstance(data, dict):
                    protocol_rows.append([
                        str(protocol),
                        f"{data.get('count', 0):,}",
                        f"{data.get('percentage', 0):.2f}%"
                    ])

            if protocol_rows:
                elements.append(Spacer(1, 0.2 * inch))
                protocol_table = self._create_table(
                    ['Protocol', 'Packet Count', 'Percentage'],
                    protocol_rows,
                    [2 * inch, 2 * inch, 2 * inch]
                )
                elements.append(protocol_table)

        ip_dist = traffic_data.get('ip_version_distribution', {})
        if ip_dist and not ip_dist.get('error'):
            elements.append(Spacer(1, 0.3 * inch))
            elements.append(Paragraph("<b>IP Version Distribution</b>", self.styles['heading2']))

            ipv4 = ip_dist.get('IPv4', {}) or {}
            ipv6 = ip_dist.get('IPv6', {}) or {}

            ip_metrics = [
                {'value': f"{ipv4.get('count', 0):,}", 'label': f"IPv4 ({ipv4.get('percentage', 0):.1f}%)", 'color': ReportColors.PRIMARY},
                {'value': f"{ipv6.get('count', 0):,}", 'label': f"IPv6 ({ipv6.get('percentage', 0):.1f}%)", 'color': ReportColors.SECONDARY},
            ]
            elements.append(self._create_metrics_row(ip_metrics))

        elements.append(PageBreak())

        # ==================== 3. TOP TALKERS ====================
        elements.extend(self._create_section_header("3. Top Talkers"))

        top_talkers = traffic_data.get('top_talkers', {}) or {}
        if isinstance(top_talkers, dict) and top_talkers.get('error'):
            top_talkers = {}

        by_packets = top_talkers.get('by_packets', {}) or {}
        by_bytes = top_talkers.get('by_bytes', {}) or {}

        src_by_packets = by_packets.get('src', [])
        if src_by_packets:
            elements.append(Paragraph("<b>Top Source IPs by Packet Count</b>", self.styles['heading2']))
            src_rows = [[item[0], f"{item[1]:,}"] for item in src_by_packets[:10]]
            src_table = self._create_table(['Source IP Address', 'Packets'], src_rows, [4 * inch, 2 * inch])
            elements.append(src_table)

        elements.append(Spacer(1, 0.3 * inch))

        dst_by_packets = by_packets.get('dst', [])
        if dst_by_packets:
            elements.append(Paragraph("<b>Top Destination IPs by Packet Count</b>", self.styles['heading2']))
            dst_rows = [[item[0], f"{item[1]:,}"] for item in dst_by_packets[:10]]
            dst_table = self._create_table(['Destination IP Address', 'Packets'], dst_rows, [4 * inch, 2 * inch])
            elements.append(dst_table)

        elements.append(Spacer(1, 0.3 * inch))

        src_by_bytes = by_bytes.get('src', [])
        if src_by_bytes:
            elements.append(Paragraph("<b>Top Source IPs by Data Volume</b>", self.styles['heading2']))
            bytes_rows = [[item[0], self._format_bytes(item[1])] for item in src_by_bytes[:10]]
            bytes_table = self._create_table(['Source IP Address', 'Data Volume'], bytes_rows, [4 * inch, 2 * inch])
            elements.append(bytes_table)

        elements.append(PageBreak())

        # ==================== 4. PORT ANALYSIS ====================
        elements.extend(self._create_section_header("4. Port Analysis"))

        port_analysis = traffic_data.get('port_analysis', []) or []
        if isinstance(port_analysis, dict) and port_analysis.get('error'):
            port_analysis = []

        if port_analysis:
            elements.append(Paragraph(
                "The following table shows the most frequently used destination ports in the capture, "
                "along with their associated services.",
                self.styles['body']
            ))
            elements.append(Spacer(1, 0.2 * inch))

            port_rows = []
            for port_data in port_analysis[:15]:
                if isinstance(port_data, dict):
                    port_rows.append([
                        str(port_data.get('port', 'N/A')),
                        port_data.get('service', 'Unknown'),
                        f"{port_data.get('count', 0):,}"
                    ])

            if port_rows:
                port_table = self._create_table(
                    ['Port', 'Service', 'Packet Count'],
                    port_rows,
                    [1.5 * inch, 2.5 * inch, 2 * inch]
                )
                elements.append(port_table)

                elements.append(Spacer(1, 0.3 * inch))
                port_chart_data = [(f"{p['port']} ({p['service']})", p['count']) for p in port_analysis[:8] if isinstance(p, dict)]
                bar_chart = self._create_bar_chart(port_chart_data, "Top Ports", ReportColors.SECONDARY)
                if bar_chart:
                    elements.append(bar_chart)
                    elements.append(Paragraph("Figure 2: Top destination ports by packet count", self.styles['caption']))

        elements.append(PageBreak())

        # ==================== 5. TCP HEALTH ASSESSMENT ====================
        elements.extend(self._create_section_header("5. TCP Health Assessment"))

        tcp_data = analysis.get('tcp', {}) or {}
        health_score_data = tcp_data.get('health_score', {}) or {}
        if isinstance(health_score_data, dict) and health_score_data.get('error'):
            health_score_data = {}
        issues_summary = tcp_data.get('issues_summary', {}) or {}
        if isinstance(issues_summary, dict) and issues_summary.get('error'):
            issues_summary = {}
        issues = issues_summary.get('issues', {}) or {}

        elements.append(Paragraph("<b>Overall Health Score</b>", self.styles['heading2']))

        grade = health_score_data.get('grade', 'N/A')
        score = float(health_score_data.get('score', 0))

        grade_style = self._get_grade_style(grade)
        grade_table_data = [
            [Paragraph(str(grade), grade_style)],
            [Paragraph(f"Score: {score:.1f} / 100", self.styles['body_center'])]
        ]

        grade_table = Table(grade_table_data, colWidths=[2 * inch])
        grade_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 0), (-1, -1), ReportColors.LIGHT_GRAY),
            ('BOX', (0, 0), (-1, -1), 2, ReportColors.PRIMARY),
            ('TOPPADDING', (0, 0), (-1, -1), 15),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ]))
        elements.append(grade_table)

        elements.append(Spacer(1, 0.3 * inch))

        factors = health_score_data.get('factors', {}) or {}
        elements.append(Paragraph("<b>Health Factors</b>", self.styles['heading2']))

        factors_rows = [
            ['Retransmission Rate', f"{factors.get('retransmission_rate', 0) * 100:.2f}%"],
            ['Reset Rate', f"{factors.get('reset_rate', 0) * 100:.2f}%"],
            ['Failed Connection Rate', f"{factors.get('failed_connection_rate', 0) * 100:.2f}%"],
        ]

        factors_table = self._create_table(['Factor', 'Rate'], factors_rows, [3 * inch, 2 * inch])
        elements.append(factors_table)

        elements.append(Spacer(1, 0.3 * inch))

        if issues:
            elements.append(Paragraph("<b>Issue Breakdown</b>", self.styles['heading2']))

            issue_rows = []
            for issue_name, issue_data in issues.items():
                if isinstance(issue_data, dict):
                    severity = issue_data.get('severity', 'low')
                    count = issue_data.get('count', 0)
                    issue_rows.append([
                        str(issue_name).replace('_', ' ').title(),
                        f"{count:,}",
                        str(severity).upper()
                    ])

            if issue_rows:
                issues_table = self._create_table(
                    ['Issue Type', 'Count', 'Severity'],
                    issue_rows,
                    [2.5 * inch, 1.5 * inch, 2 * inch]
                )
                elements.append(issues_table)

        flags_summary = tcp_data.get('flags_summary', {}) or {}
        if isinstance(flags_summary, dict) and not flags_summary.get('error') and flags_summary:
            elements.append(Spacer(1, 0.3 * inch))
            elements.append(Paragraph("<b>TCP Flags Summary</b>", self.styles['heading2']))

            flags_rows = [[flag, f"{count:,}"] for flag, count in flags_summary.items() if count and int(count) > 0]
            if flags_rows:
                flags_table = self._create_table(['Flag', 'Count'], flags_rows, [2 * inch, 2 * inch])
                elements.append(flags_table)

        elements.append(PageBreak())

        # ==================== 6. GEOGRAPHIC ANALYSIS ====================
        elements.extend(self._create_section_header("6. Geographic Analysis"))

        if geolocation.get('available'):
            geo_metrics = [
                {'value': str(geolocation.get('total_unique_ips', 0)), 'label': 'Total IPs', 'color': ReportColors.PRIMARY},
                {'value': str(geolocation.get('public_ips', 0)), 'label': 'Public IPs', 'color': ReportColors.SECONDARY},
                {'value': str(geolocation.get('private_ips', 0)), 'label': 'Private IPs', 'color': ReportColors.DARK_GRAY},
                {'value': str(geolocation.get('total_countries', 0)), 'label': 'Countries', 'color': ReportColors.ACCENT},
                {'value': str(geolocation.get('total_cities', 0)), 'label': 'Cities', 'color': ReportColors.WARNING},
            ]
            elements.append(self._create_metrics_row(geo_metrics))

            elements.append(Spacer(1, 0.3 * inch))

            elements.append(Paragraph("<b>Geographic Distribution Map</b>", self.styles['heading2']))

            map_buffer = self._create_world_map(geolocation)
            if map_buffer:
                map_image = Image(map_buffer, width=6 * inch, height=3 * inch)
                elements.append(map_image)
                elements.append(Paragraph(
                    "Figure 3: World map showing source (blue) and destination (green) IP locations with connection lines",
                    self.styles['caption']
                ))
                elements.append(Paragraph(
                    "Note: For interactive map with detailed hover information, please refer to the Geolocation page in the web application.",
                    self.styles['note']
                ))

            elements.append(Spacer(1, 0.3 * inch))

            country_dist = geolocation.get('country_distribution', []) or []
            if country_dist:
                elements.append(Paragraph("<b>Traffic by Country</b>", self.styles['heading2']))

                country_rows = []
                for c in country_dist[:10]:
                    if isinstance(c, dict):
                        country_rows.append([
                            self._sanitize_text(c.get('country', 'Unknown')),
                            str(c.get('unique_ips', 0))
                        ])

                if country_rows:
                    country_table = self._create_table(['Country', 'Unique IPs'], country_rows, [3 * inch, 2 * inch])
                    elements.append(country_table)

            elements.append(Spacer(1, 0.3 * inch))

            connection_lines = geolocation.get('connection_lines', []) or []
            if connection_lines:
                elements.append(Paragraph("<b>Top Geographic Connections</b>", self.styles['heading2']))

                conn_rows = []
                for conn in connection_lines[:10]:
                    if isinstance(conn, dict):
                        src_city = self._sanitize_text(conn.get('src_city', 'Unknown'))
                        src_country = self._sanitize_text(conn.get('src_country', 'Unknown'))
                        dst_city = self._sanitize_text(conn.get('dst_city', 'Unknown'))
                        dst_country = self._sanitize_text(conn.get('dst_country', 'Unknown'))
                        src = f"{src_city}, {src_country}"
                        dst = f"{dst_city}, {dst_country}"
                        conn_rows.append([src[:30], dst[:30], f"{conn.get('packet_count', 0):,}"])

                if conn_rows:
                    conn_table = self._create_table(
                        ['Source Location', 'Destination Location', 'Packets'],
                        conn_rows,
                        [2.2 * inch, 2.2 * inch, 1.5 * inch]
                    )
                    elements.append(conn_table)
        else:
            elements.append(Paragraph(
                "Geolocation data is not available. Please ensure the GeoLite2 database is properly configured.",
                self.styles['body']
            ))

        elements.append(PageBreak())

        # ==================== 7. OBSERVATIONS & RECOMMENDATIONS ====================
        elements.extend(self._create_section_header("7. Observations & Recommendations"))

        observations = []

        if health_score_data.get('grade') == 'F':
            observations.append({
                'type': 'critical',
                'title': 'Critical: Poor TCP Health',
                'text': f"The TCP health score of {score:.1f}/100 indicates significant network issues. "
                       f"High retransmission rates ({factors.get('retransmission_rate', 0) * 100:.1f}%) suggest "
                       f"packet loss or network congestion."
            })
        elif health_score_data.get('grade') in ['D', 'C']:
            observations.append({
                'type': 'warning',
                'title': 'Warning: Moderate TCP Issues',
                'text': f"The TCP health score of {score:.1f}/100 indicates some network quality concerns. "
                       f"Consider investigating the cause of retransmissions and connection issues."
            })
        else:
            observations.append({
                'type': 'success',
                'title': 'Good: Healthy TCP Connections',
                'text': f"The TCP health score of {score:.1f}/100 indicates good network quality with minimal issues."
            })

        if protocol_dist:
            sorted_p = sorted(protocol_dist.items(), key=lambda x: (x[1].get('count', 0) if isinstance(x[1], dict) else 0), reverse=True)
            if sorted_p:
                top_protocol, top_data = sorted_p[0]
                pct = top_data.get('percentage', 0) if isinstance(top_data, dict) else 0
                traffic_type = 'web browsing' if str(top_protocol).upper() in ['QUIC', 'TLS', 'HTTP', 'HTTPS'] else 'network'
                observations.append({
                    'type': 'info',
                    'title': f'Primary Protocol: {top_protocol}',
                    'text': f"The dominant protocol is {top_protocol} accounting for {pct:.1f}% "
                           f"of all traffic. This is typical for {traffic_type} traffic."
                })

        if geolocation.get('available'):
            countries = geolocation.get('total_countries', 0)
            if countries > 10:
                observations.append({
                    'type': 'info',
                    'title': 'Diverse Geographic Distribution',
                    'text': f"Traffic originated from or was destined to {countries} different countries, "
                           f"indicating diverse international network activity."
                })

        for obs in observations:
            elements.append(Paragraph(f"<b>{obs['title']}</b>", self.styles['heading3']))
            elements.append(Paragraph(obs['text'], self.styles['body']))
            elements.append(Spacer(1, 0.15 * inch))

        elements.append(Spacer(1, 0.3 * inch))

        elements.append(Paragraph("<b>Recommendations</b>", self.styles['heading2']))

        recommendations = [
            "Review high-traffic IP addresses for any unexpected or unauthorized activity.",
            "Monitor TCP retransmission rates regularly to detect network degradation early.",
            "Investigate any unknown or suspicious geographic connections.",
            "Consider implementing traffic analysis as part of regular network monitoring.",
            "Keep network analysis tools and databases (e.g., GeoLite2) up to date.",
        ]

        for i, rec in enumerate(recommendations, 1):
            elements.append(Paragraph(f"{i}. {rec}", self.styles['body']))

        elements.append(Spacer(1, 0.5 * inch))

        elements.append(HRFlowable(width="100%", thickness=1, color=ReportColors.LIGHT_GRAY))
        elements.append(Spacer(1, 0.2 * inch))
        elements.append(Paragraph(
            f"Report generated by PCAP Analyzer on {datetime.now().strftime('%d %B %Y at %H:%M:%S')}",
            self.styles['footer']
        ))
        elements.append(Paragraph(
            "This report is automatically generated based on network packet analysis.",
            self.styles['footer']
        ))

        doc.build(elements, onFirstPage=self._header_footer, onLaterPages=self._header_footer)

        self.buffer.seek(0)
        return self.buffer


def generate_pdf_report(filename: str, summary: Dict, analysis: Dict,
                        geolocation: Dict, file_size: int = 0) -> io.BytesIO:
    generator = PCAPReportGenerator()
    return generator.generate_report(filename, summary, analysis, geolocation, file_size)
