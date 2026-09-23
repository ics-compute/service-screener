import xlsxwriter
from datetime import datetime, date

from utils.Config import Config, dashboard

class ExcelBuilder:
    # XLSX_FILENAME = 'adminlte/html/workItem.xlsx'
    XLSX_CREATOR = "Service Screener - AWS Malaysia"
    XLSX_TITLE = "Service Screener WorkList"
    SHEET_TRACKER = []
    SHEET_HEADER = [[
        'Region',
        'Check',
        'Type',
        'ResourceID',
        'Severity',
        'Status'
    ]]

    def __init__(self, accountId, ssParams):
        acctPath = Config.get('HTML_ACCOUNT_FOLDER_PATH')
        self.XLSX_FILENAME = acctPath + '/workItem.xlsx'

        self.obj = xlsxwriter.Workbook(self.XLSX_FILENAME)
        self.accountId = accountId
        self.ssParams = ssParams

        self.recommendations = {}
        self.xlsxFormat = {}
        self._setExcelInfo()

        self.buildListOfXlsxFormat()

        self.InfoSheet = self.obj.add_worksheet('Info')
        self.sheetIndex = 2


    def buildListOfXlsxFormat(self):
        self.xlsxFormat['bold'] = self.obj.add_format({'bold': True})
        self.xlsxFormat['wrapText'] = self.obj.add_format().set_text_wrap()
        self.xlsxFormat['border'] = self.obj.add_format({'border': 1})

    def generateWorkSheet(self, service, raw, suppressedRaw=None):
        service = service.upper()

        sh = self.obj.add_worksheet(service)

        data = self._formatReporterDataToArray(service, raw)

        # Add suppressed items if available
        if suppressedRaw:
            suppressedData = self._formatSuppressedReporterDataToArray(service, suppressedRaw)
            data.extend(suppressedData)

        self.writeRowsInArray(sh, self.SHEET_HEADER, 0, 0)
        self.writeRowsInArray(sh, data, 1, 0)

        sh.set_row(0, None, self.xlsxFormat['bold'])
        sh.data_validation('F2:F1048576', self._validation_status())
        self._setAutoSize(sh)

        self.sheetIndex += 1

    def writeRowsInArray(self, sh, data, startRow, startCol, cFormat=None):
        for _r, _d in enumerate(data):
            sh.write_row(startRow+_r, startCol, _d, cFormat)

    def generateRecommendationSheet(self):
        sh = self.obj.add_worksheet('Appendix')

        header = [[
            'Service',
            'Check',
            'Short Description',
            'Recommendation'
        ]]

        data = []
        for service, det in self.recommendations.items():
            for check, info in det.items():
                data.append([
                    service,
                    check,
                    info[0],
                    self._formatHyperlink(info[1])
                ])

        self.writeRowsInArray(sh, header, 0, 0)
        self.writeRowsInArray(sh, data, 1, 0)

        sh.set_row(0, None, self.xlsxFormat['bold'])
        sh.set_column("D:D", None, self.xlsxFormat['wrapText'])
        self._setAutoSize(sh)

        self.sheetIndex += 1

    def buildSummaryPage(self, summary):
        ## <TODO>
        # sh = self.obj.getSheet(0)
        # sh.setTitle("Info")
        sh = self.InfoSheet

        info = [
            ['AccountId', "'" + self.accountId],
            ['Generated on', datetime.today().strftime('%Y/%m/%d %H:%M:%S')],
            ['Parameters', self.ssParams]
        ]

        ##Append Software Info
        info.append(['...Product Info', '...................'])
        softwareInfo = Config.ADVISOR
        for key, val in softwareInfo.items():
            info.append([key, val])

        ##Append number of resources scanned, rules executed and timespent
        info.append(['...Execution Summary', '...................'])
        for key, val in summary.items():
            info.append([key, val])

        # sh.fromArray(info, None, 'A1')

        self.writeRowsInArray(sh, info, 0, 0)

        ## Enhance MAP
        darr = []
        arr = []
        total = 0
        types = dashboard['MAP']

        # S, O, C, P, R, Total
        arr.append(['', 'S', 'O', 'C', 'P', 'R', 'Total'])
        darr.append(['', 'S', 'O', 'C', 'P', 'R', '-', 'H', 'M', 'L', 'I', '-', 'Total'])
        for service, v in types.items():
            _ = v['_']
            sum = _['S'] + _['O'] + _['C'] + _['P'] + _['R']
            dsum = v['H'] + v['M'] + v['L'] + v['I']
            arr.append([service, _['S'], _['O'], _['C'], _['P'], _['R'], sum])
            darr.append([service, v['S'], v['O'], v['C'], v['P'], v['R'], '-', v['H'], v['M'], v['L'], v['I'], '-', dsum])

        totalServ = len(types)
        endRow = totalServ + 2

        sp = endRow + 2
        sp1 = sp+1
        dEndRow = totalServ + sp + 1

        # Build HIGH FINDING REPORT
        sh.write('D1', 'Type')
        sh.merge_range('E1:J1', 'High Criticality Findings')

        # sh.from_array(arr, None, 'D2', True)
        self.writeRowsInArray(sh, arr, 1, 3, self.xlsxFormat['border'])

        # Build DETAIL FINDING REPORT
        sh.write('D' + str(sp), 'Type')
        sh.merge_range("E" + str(sp) + ':' + "P" + str(sp), 'Finding Reports')

        self.writeRowsInArray(sh, darr, sp, 3, self.xlsxFormat['border'])

        self._setAutoSize(sh)

    def _setExcelInfo(self):
        self.obj.set_properties({
            'title': self.XLSX_TITLE,
            'subject': self.XLSX_TITLE,
            'comments': self._getXLSXDescription((self.ssParams)),
            'author': self.XLSX_CREATOR,
            'keywords': 'Screener, AWS, github, Malaysia',
            'created': datetime.now()
        })

    def _setAutoSize(self, sh):
        sh.autofit()

    def _getXLSXDescription(self, ssParams):
        now = datetime.now()
        return now.strftime('%Y/%m/%d %H:%M:%S') + " | " + ssParams

    def _validation_status(self):
        valDict = {
            'validate': 'list',
            'source': ['New', 'Suppressed', 'Resolved'],
            'ignore_blank': False,
            'error_type': 'stop'
        }

        return valDict

    ## <TODO>
    ## <ACCID><SS><VERS><YYMMDD_His>.xlsx
    def _getFileName(self, folderPath):
        return folderPath + self.XLSX_FILENAME

    def _formatReporterDataToArray(self, service, cardSummary):
        arr = []
        for check, detail in cardSummary.items():
            if not detail.get('__links'):
                detail['__links'] = ''

            if not service in self.recommendations:
                self.recommendations[service] = {}

            self.recommendations[service][check] = [detail['shortDesc'], detail['__links']]
            for region, resources in detail['__affectedResources'].items():
                for resource in resources:
                    arr.append([
                        region,
                        check,
                        self._getPillarName(detail['__categoryMain']),
                        resource,
                        self._getCriticallyName(detail['criticality']),
                        'New'
                    ])
        return arr

    def _formatSuppressedReporterDataToArray(self, service, suppressedCardSummary):
        """Format suppressed findings for Excel with 'Suppressed' status"""
        arr = []
        for check, detail in suppressedCardSummary.items():
            if not detail.get('__links'):
                detail['__links'] = ''

            if not service in self.recommendations:
                self.recommendations[service] = {}

            # Add to recommendations if not already there
            if check not in self.recommendations[service]:
                self.recommendations[service][check] = [detail['shortDesc'], detail['__links']]

            for region, resources in detail['__affectedResources'].items():
                for resource in resources:
                    arr.append([
                        region,
                        check,
                        self._getPillarName(detail['__categoryMain']),
                        resource,
                        self._getCriticallyName(detail['criticality']),
                        'Suppressed'  # Set status to Suppressed
                    ])
        return arr

    def _save(self, folderPath=''):
        if bool(self.recommendations):
            self.generateRecommendationSheet()

        self.obj.close()
        return

    def generateWAFPillarsExcel(self, allCardSummaries):
        """Generate an actionable workbook with one sheet per WAF pillar.

        Category ``T`` findings are deliberately excluded because they are not
        mapped to a Well-Architected pillar. Each exported row carries a short
        Notes cell built by ``_buildWAFPillarNotes``.
        """
        waf_pillars = {
            'O': 'Operational Excellence',
            'S': 'Security',
            'R': 'Reliability',
            'P': 'Performance Efficiency',
            'C': 'Cost Optimization',
        }

        account_path = Config.get('HTML_ACCOUNT_FOLDER_PATH')
        filename = account_path + '/waf-pillars.xlsx'
        workbook = xlsxwriter.Workbook(filename)
        workbook.set_properties({
            'title': 'AWS Well-Architected Framework Findings',
            'author': self.XLSX_CREATOR,
            'created': datetime.now(),
        })

        header_format = workbook.add_format({
            'bold': True,
            'font_color': '#FFFFFF',
            'bg_color': '#1976D2',
            'border': 1,
            'border_color': '#000000',
            'align': 'center',
            'valign': 'vcenter',
        })
        table_format = workbook.add_format({
            'border': 1,
            'border_color': '#000000',
            'valign': 'top',
        })
        notes_format = workbook.add_format({
            'text_wrap': True,
            'valign': 'top',
            'border': 1,
            'border_color': '#000000',
        })
        header = [
            'Service', 'Region', 'Check', 'ResourceID', 'Severity', 'Status',
            'Notes',
        ]
        pillar_rows = {pillar: [] for pillar in waf_pillars}

        for service, card_summary in allCardSummaries.items():
            for check, detail in card_summary.items():
                pillar = detail.get('__categoryMain')
                if pillar not in pillar_rows:
                    # T is non-WAF/general content; unknown categories are also
                    # excluded rather than being misclassified into a pillar.
                    continue

                for region, resources in detail.get('__affectedResources', {}).items():
                    for resource in resources:
                        notes = self._buildWAFPillarNotes(
                            service, check, detail, region, resource
                        )
                        pillar_rows[pillar].append({
                            'values': [
                                service.upper(),
                                region,
                                check,
                                resource,
                                self._getCriticallyName(detail.get('criticality', 'I')),
                                'New',
                            ],
                            'notes': notes,
                        })

        for code, name in waf_pillars.items():
            worksheet = workbook.add_worksheet(name)
            worksheet.write_row(0, 0, header, header_format)

            for row_index, row in enumerate(pillar_rows[code], start=1):
                worksheet.write_row(row_index, 0, row['values'], table_format)
                worksheet.write(row_index, 6, row['notes'], notes_format)

            worksheet.autofilter(0, 0, len(pillar_rows[code]), len(header) - 1)
            worksheet.freeze_panes(1, 0)
            worksheet.autofit()
            worksheet.set_column(6, 6, 80)

        workbook.close()
        return filename

    # Reporter impact flags (1 = yes, -1 = depends) rendered in the Notes column.
    _IMPACT_LABELS = (
        ('downtime', 'downtime'),
        ('slowness', 'performance impact'),
        ('additionalCost', 'extra cost'),
        ('needFullTest', 'regression test'),
    )

    def _buildWAFPillarNotes(self, service, check, detail, region, resource):
        """Build the short Notes text for one WAF workbook row.

        Line 1: what to do (the finding's shortDesc plus a specific hint when
                the catalog or the description has one).
        Line 2: "Why:" the consequence of leaving it, taken from the reporter
                description when it adds information.
        Line 3: "Fix impact:" downtime/performance/cost/testing flags, only
                when the reporter sets any.
        Line 4: the reviewed CLI command resolved for this resource, or the
                template with the placeholders still to be filled in.
        """
        from utils.RemediationCatalog import RemediationCatalog

        guidance = RemediationCatalog.get_guidance(service, check, detail)
        lines = [' '.join(filter(None, (
            self._asSentence(guidance['summary']),
            self._asSentence(guidance['instruction']),
        )))]

        if guidance.get('context'):
            lines.append(f"Why: {guidance['context']}")

        impact = self._describeImpact(detail)
        if impact:
            lines.append(f'Fix impact: {impact}.')

        resource_remediation = (
            detail.get('__remediationByResource', {})
            .get(region, {})
            .get(resource, {})
        )
        command = ' '.join(str(resource_remediation.get('command', '')).split())
        unresolved = [str(field) for field in resource_remediation.get('unresolved', [])]
        if command and unresolved:
            lines.append(f"CLI template (fill {', '.join(unresolved)}): {command}")
        elif command:
            risk = detail.get('remediation_risk')
            label = f'CLI ({risk} risk)' if risk else 'CLI'
            lines.append(f'{label}: {command}')

        return '\n'.join(lines)

    def _describeImpact(self, detail):
        parts = []
        for key, label in self._IMPACT_LABELS:
            value = detail.get(key)
            if value == 1:
                parts.append(label)
            elif value == -1:
                parts.append(f'possible {label}')
        return ', '.join(parts)

    @staticmethod
    def _asSentence(text):
        text = ' '.join(str(text or '').split()).rstrip('.')
        if not text:
            return ''
        return text[0].upper() + text[1:] + '.'

    def _getPillarName(self, category):
        mapped = {
            'T': 'Text',
            'O': 'Operation Excellence',
            'P': 'Performance Efficiency',
            'S': 'Security',
            'R': 'Reliability',
            'C': 'Cost Optimization'
        }
        return mapped[category]

    def _getCriticallyName(self, criticality):
        mapped = {
            'H': 'High',
            'M': 'Medium',
            'L': 'Low',
            'I': 'Informational'
        }

        return mapped[criticality]

    def _formatHyperlink(self, arr):
        if not arr:
            return ''

        recomm = []
        for p in arr:
            o = p.find("href='")
            e = p.find("'>")
            r = p[o+6:e-6]
            w = p[e+2:-4]
            recomm.append(f"{w}, {r}")
        return '\n'.join(recomm)