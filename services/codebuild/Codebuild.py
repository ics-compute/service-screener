import botocore

from utils.Tools import _pi
from utils.Config import Config
from services.Service import Service

from services.codebuild.drivers.CodebuildProject import CodebuildProject
from services.codebuild.drivers.CodebuildReportGroup import CodebuildReportGroup


class Codebuild(Service):
    """
    AWS CodeBuild service scanner.

    Two check subjects, so two drivers:
      CodebuildProject     -- per build project (credentials, isolation, logging)
      CodebuildReportGroup -- per report group (export encryption)

    Hydration calls (all read-only):
      - list_projects              (paginated)
      - batch_get_projects         (batched, 100 names per call)
      - list_report_groups         (paginated)
      - batch_get_report_groups    (batched, 100 ARNs per call)

    NOTE ON SECRETS: two checks in CodebuildProject look for credentials in
    project configuration. They report the LOCATION of the problem (variable name,
    which field) and never the credential itself, so a scan report cannot become a
    second copy of the leak. See the comments on those checks.
    """

    ACCESS_DENIED_CODES = (
        'AccessDenied', 'AccessDeniedException', 'AuthorizationError',
        'UnrecognizedClientException',
    )

    ## batch_get_projects and batch_get_report_groups both cap at 100 per call.
    BATCH_SIZE = 100

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.cbClient = ssBoto.client('codebuild', config=self.bConfig)

    # ------------------------------------------------------------------ #
    # Discovery
    # ------------------------------------------------------------------ #
    def getResources(self):
        names = self._listProjectNames()
        if not names:
            return []

        projects = []
        for i in range(0, len(names), self.BATCH_SIZE):
            batch = names[i:i + self.BATCH_SIZE]
            try:
                resp = self.cbClient.batch_get_projects(names=batch)
            except botocore.exceptions.ClientError as e:
                self._logClientError('batch_get_projects', e)
                continue

            for project in resp.get('projects', []) or []:
                if not project.get('name'):
                    continue

                ## Optional --filters tag filtering. CodeBuild returns tags as
                ## [{'key':..,'value':..}] with LOWERCASE keys, unlike most
                ## services' [{'Key':..,'Value':..}], so normalise before the
                ## shared helper sees them.
                tags = self._normaliseTags(project.get('tags') or [])
                if self.tags and not self.resourceHasTags(tags):
                    continue

                project['_tags'] = tags
                project['_region'] = self.region
                _pi('Codebuild', f"Project: {project['name']}")
                projects.append(project)

        return projects

    def _listProjectNames(self):
        names = []
        try:
            paginator = self.cbClient.get_paginator('list_projects')
            for page in paginator.paginate():
                names += page.get('projects', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_projects', e)
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"CodeBuild not available in region {self.region}: {e}")
        except botocore.exceptions.OperationNotPageableError:
            try:
                names = self.cbClient.list_projects().get('projects', []) or []
            except botocore.exceptions.ClientError as e:
                self._logClientError('list_projects', e)
        return names

    def _getReportGroups(self):
        arns = []
        try:
            paginator = self.cbClient.get_paginator('list_report_groups')
            for page in paginator.paginate():
                arns += page.get('reportGroups', []) or []
        except botocore.exceptions.ClientError as e:
            self._logClientError('list_report_groups', e)
            return []
        except botocore.exceptions.EndpointConnectionError:
            return []
        except botocore.exceptions.OperationNotPageableError:
            try:
                arns = self.cbClient.list_report_groups().get(
                    'reportGroups', []) or []
            except botocore.exceptions.ClientError as e:
                self._logClientError('list_report_groups', e)
                return []

        if not arns:
            return []

        groups = []
        for i in range(0, len(arns), self.BATCH_SIZE):
            batch = arns[i:i + self.BATCH_SIZE]
            try:
                resp = self.cbClient.batch_get_report_groups(
                    reportGroupArns=batch)
            except botocore.exceptions.ClientError as e:
                self._logClientError('batch_get_report_groups', e)
                continue
            for group in resp.get('reportGroups', []) or []:
                if group.get('name'):
                    group['_region'] = self.region
                    groups.append(group)
        return groups

    def _normaliseTags(self, tags):
        """CodeBuild uses lowercase tag keys; convert to the Key/Value form."""
        normalised = []
        for tag in tags:
            if not isinstance(tag, dict):
                continue
            normalised.append({
                'Key': tag.get('key', tag.get('Key', '')),
                'Value': tag.get('value', tag.get('Value', '')),
            })
        return normalised

    # ------------------------------------------------------------------ #
    # Advise
    # ------------------------------------------------------------------ #
    def advise(self):
        objs = {}

        for project in self.getResources():
            name = project.get('name', 'unknown')
            try:
                _pi('Codebuild', f"Analyzing project: {name}")
                obj = CodebuildProject(project, self.cbClient)
                obj.run(self.__class__)
                objs[f"CodeBuild Project::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing CodeBuild project {name}: {e}")

        for group in self._getReportGroups():
            name = group.get('name', 'unknown')
            try:
                _pi('Codebuild', f"Analyzing report group: {name}")
                obj = CodebuildReportGroup(group, self.cbClient)
                obj.run(self.__class__)
                objs[f"CodeBuild Report Group::{name}"] = obj.getInfo()
                del obj
            except Exception as e:
                print(f"Error processing CodeBuild report group {name}: {e}")

        return objs

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _logClientError(self, where, error):
        code = error.response.get('Error', {}).get('Code', 'Unknown')
        if code in self.ACCESS_DENIED_CODES:
            return
        msg = error.response.get('Error', {}).get('Message', str(error))
        print(f"Codebuild {where}: {code} - {msg}")
