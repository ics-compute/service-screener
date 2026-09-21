from services.Evaluator import Evaluator


class CodebuildReportGroup(Evaluator):
    """
    Per-report-group CodeBuild checks (1 of the 15).

      cbReportGroupExportNotEncrypted  -- FSBP CodeBuild.7

    A report group is a separate resource type from a build project, so it gets
    its own driver rather than being folded into CodebuildProject.

    Input:
      group -- a batch_get_report_groups entry plus '_region'.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO.
    """

    def __init__(self, group, cbClient):
        super().__init__()
        self.group = group
        self.cbClient = cbClient

        self.name = group.get('name', 'unknown')
        self._resourceName = self.name

        self.exportConfig = group.get('exportConfig') or {}

        self.addII('reportGroupName', self.name)
        self.addII('region', group.get('_region', 'N/A'))
        self.addII('type', group.get('type', 'N/A'))
        self.addII('status', group.get('status', 'N/A'))
        self.addII('exportConfigType',
                   self.exportConfig.get('exportConfigType', 'N/A'))

    # ------------------------------------------------------------------ #
    # 1. Report group export not encrypted  (FSBP CodeBuild.7)
    # ------------------------------------------------------------------ #
    def _checkCbReportGroupExportNotEncrypted(self):
        """
        Only S3-exporting report groups can be misconfigured this way. When
        exportConfigType is NO_EXPORT the reports stay inside CodeBuild and there
        is nothing to encrypt, so that is INFO rather than a pass or a failure.
        """
        exportType = self.exportConfig.get('exportConfigType')

        if exportType != 'S3':
            self.results['cbReportGroupExportNotEncrypted'] = [
                0,
                f"Report group '{self.name}' has exportConfigType="
                f"{exportType or 'not set'} — nothing is exported to S3"
            ]
            return

        s3 = self.exportConfig.get('s3Destination') or {}
        if s3.get('encryptionDisabled') is True:
            self.results['cbReportGroupExportNotEncrypted'] = [
                -1,
                "Report group '{}' exports to s3://{} with encryption disabled — "
                "test and coverage reports reveal internal code structure, test "
                "data and failure detail".format(
                    self.name, s3.get('bucket', 'unknown'))
            ]
        else:
            key = s3.get('encryptionKey')
            self.results['cbReportGroupExportNotEncrypted'] = [
                1,
                "Report group '{}' encrypts its S3 export{}".format(
                    self.name, f" with {key}" if key else "")
            ]
