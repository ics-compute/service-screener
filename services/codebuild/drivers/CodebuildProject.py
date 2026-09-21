import re

from services.Evaluator import Evaluator


class CodebuildProject(Evaluator):
    """
    Per-project CodeBuild checks (14 of the 15).

    Input:
      project -- a batch_get_projects entry plus '_tags' (normalised to
                 Key/Value) and '_region', from services/codebuild/Codebuild.py.

    Status contract (services/Evaluator.py): -1 = FAIL, 1 = PASS, 0 = INFO /
    not applicable. Only -1 surfaces as a finding.

    SECRET HANDLING: _checkCbPlaintextCredentialsInEnvVars and
    _checkCbSourceUrlCredentials both detect credentials in project config. They
    report only WHERE the credential is (the variable name, or which source
    field), never the value. A scan report must not become a second copy of the
    leak, and reports get pasted into tickets and chat.
    """

    ## Environment variable names that indicate a credential when stored as
    ## PLAINTEXT. AWS key names are matched exactly because they are
    ## unambiguous; the rest are substring fragments.
    EXACT_CREDENTIAL_NAMES = frozenset([
        'aws_access_key_id',
        'aws_secret_access_key',
        'aws_session_token',
    ])

    CREDENTIAL_NAME_FRAGMENTS = (
        'secret', 'password', 'passwd', 'token', 'credential', 'privatekey',
        'private_key', 'apikey', 'api_key', 'accesskey', 'access_key',
        'auth', 'cert',
    )

    ## Environment variable types that resolve at build time from a secure
    ## store rather than embedding the value in the project definition.
    SECURE_ENV_TYPES = frozenset(['PARAMETER_STORE', 'SECRETS_MANAGER'])

    ## Source types whose location is a URL that could carry inline credentials.
    URL_SOURCE_TYPES = frozenset(['GITHUB', 'GITHUB_ENTERPRISE', 'BITBUCKET',
                                  'CODECOMMIT', 'S3'])

    ## https://user:password@host — the form FSBP CodeBuild.1 looks for. The
    ## userinfo segment must contain a colon, otherwise it is just a username,
    ## which is not a credential.
    URL_CREDENTIAL_PATTERN = re.compile(r'://[^/\s:@]+:[^/\s@]+@')

    ## CodeBuild curated images that AWS has retired or that pin an end-of-life
    ## toolchain. Matched as substrings against environment.image, which has the
    ## form 'aws/codebuild/standard:5.0' (verified live) -- NOT the
    ## 'ubuntu:standard:5.0' short form. standard:5.0 and earlier are Ubuntu
    ## images past EOL; standard:6.0/7.0 are current.
    DEPRECATED_IMAGE_FRAGMENTS = (
        'aws/codebuild/standard:1.0', 'aws/codebuild/standard:2.0',
        'aws/codebuild/standard:3.0', 'aws/codebuild/standard:4.0',
        'aws/codebuild/standard:5.0',
        'aws/codebuild/amazonlinux2-x86_64-standard:1.0',
        'aws/codebuild/amazonlinux2-x86_64-standard:2.0',
        'aws/codebuild/amazonlinux2-x86_64-standard:3.0',
        'aws/codebuild/windows-base:1.0', 'aws/codebuild/windows-base:2.0',
    )

    MAX_NAMES_IN_MESSAGE = 5

    def __init__(self, project, cbClient):
        super().__init__()
        self.project = project
        self.cbClient = cbClient

        self.name = project.get('name', 'unknown')
        self._resourceName = self.name

        self.environment = project.get('environment') or {}
        self.source = project.get('source') or {}
        self.secondarySources = project.get('secondarySources') or []
        self.artifacts = project.get('artifacts') or {}
        self.logsConfig = project.get('logsConfig') or {}
        self.tags = project.get('_tags') or []

        self.addII('projectName', self.name)
        self.addII('region', project.get('_region', 'N/A'))
        self.addII('sourceType', self.source.get('type', 'N/A'))
        self.addII('environmentType', self.environment.get('type', 'N/A'))
        self.addII('image', self.environment.get('image', 'N/A'))
        self.addII('privilegedMode',
                   str(self.environment.get('privilegedMode', False)))
        self.addII('projectVisibility',
                   project.get('projectVisibility', 'N/A'))
        self.addII('serviceRole', project.get('serviceRole', 'N/A'))
        self.addII('vpcConfigured', str(bool(project.get('vpcConfig'))))
        self.addII('envVarCount',
                   str(len(self.environment.get('environmentVariables') or [])))
        self.addII('tagCount', str(len(self.tags)))

    # ------------------------------------------------------------------ #
    # 1. Plaintext credentials in environment variables  (FSBP CodeBuild.2)
    # ------------------------------------------------------------------ #
    def _checkCbPlaintextCredentialsInEnvVars(self):
        """
        Reports the variable NAME only. The value is deliberately never read
        into the finding: a build project's env vars are visible to anyone with
        codebuild:BatchGetProjects, and a scan report should not widen that.
        """
        envVars = self.environment.get('environmentVariables') or []
        if not envVars:
            self.results['cbPlaintextCredentialsInEnvVars'] = [
                0, f"Project '{self.name}' defines no environment variables"
            ]
            return

        offending = []
        for var in envVars:
            name = var.get('name') or ''
            varType = var.get('type') or 'PLAINTEXT'
            if varType in self.SECURE_ENV_TYPES:
                continue
            if self._nameLooksLikeCredential(name):
                offending.append(name)

        if offending:
            self.results['cbPlaintextCredentialsInEnvVars'] = [
                -1,
                "{} of {} environment variable(s) on project '{}' hold "
                "credential-shaped names as PLAINTEXT: {} — the values are "
                "readable by anyone with codebuild:BatchGetProjects and appear "
                "in build logs".format(
                    len(offending), len(envVars), self.name,
                    self._joinNames(offending))
            ]
        else:
            self.results['cbPlaintextCredentialsInEnvVars'] = [
                1,
                f"No credential-shaped PLAINTEXT environment variable on project "
                f"'{self.name}' ({len(envVars)} variable(s) checked)"
            ]

    # ------------------------------------------------------------------ #
    # 2. Credentials embedded in a source URL  (FSBP CodeBuild.1)
    # ------------------------------------------------------------------ #
    def _checkCbSourceUrlCredentials(self):
        """
        Reports WHICH source carries an inline credential, never the matched
        text. The regex looks for the userinfo form https://user:pass@host.
        """
        offending = []

        primary = self.source.get('location') or ''
        if self.URL_CREDENTIAL_PATTERN.search(primary):
            offending.append('primary source')

        for index, secondary in enumerate(self.secondarySources):
            location = (secondary or {}).get('location') or ''
            if self.URL_CREDENTIAL_PATTERN.search(location):
                identifier = (secondary or {}).get(
                    'sourceIdentifier') or f'secondary source {index}'
                offending.append(identifier)

        if offending:
            self.results['cbSourceUrlCredentials'] = [
                -1,
                "Project '{}' embeds credentials in the source URL of: {} — the "
                "credential is stored in the project definition in clear text "
                "and is logged on every clone".format(
                    self.name, self._joinNames(offending))
            ]
        else:
            self.results['cbSourceUrlCredentials'] = [
                1, f"No credentials embedded in any source URL of '{self.name}'"
            ]

    # ------------------------------------------------------------------ #
    # 3. Privileged mode
    # ------------------------------------------------------------------ #
    def _checkCbPrivilegedMode(self):
        """
        AWS retired the equivalent Security Hub control (CodeBuild.5) but
        privileged mode is still a genuine container-escape risk: it grants the
        build container full Docker daemon access, so a compromised dependency
        can reach the host and the instance credentials.
        """
        if self.environment.get('privilegedMode') is True:
            self.results['cbPrivilegedMode'] = [
                -1,
                f"Project '{self.name}' runs with privilegedMode=true — the "
                "build container has full Docker daemon access, so anything it "
                "executes can escape to the host and reach its credentials"
            ]
        else:
            self.results['cbPrivilegedMode'] = [
                1, f"Project '{self.name}' does not use privileged mode"
            ]

    # ------------------------------------------------------------------ #
    # 4. Public project visibility
    # ------------------------------------------------------------------ #
    def _checkCbProjectVisibilityPublic(self):
        ## The API enum is PUBLIC_READ / PRIVATE — not 'PUBLIC'.
        visibility = self.project.get('projectVisibility')
        if visibility == 'PUBLIC_READ':
            self.results['cbProjectVisibilityPublic'] = [
                -1,
                f"Project '{self.name}' has projectVisibility=PUBLIC_READ — its "
                "build logs, including any secret echoed during a build, are "
                "readable by anyone on the internet without authentication"
            ]
        elif visibility:
            self.results['cbProjectVisibilityPublic'] = [
                1, f"Project '{self.name}' visibility is {visibility}"
            ]
        else:
            self.results['cbProjectVisibilityPublic'] = [
                0, f"Project '{self.name}' does not report a visibility setting"
            ]

    # ------------------------------------------------------------------ #
    # 5. Artifact encryption disabled
    # ------------------------------------------------------------------ #
    def _checkCbNoArtifactEncryption(self):
        if not self.artifacts or self.artifacts.get('type') == 'NO_ARTIFACTS':
            self.results['cbNoArtifactEncryption'] = [
                0, f"Project '{self.name}' produces no artifacts"
            ]
            return

        if self.artifacts.get('encryptionDisabled') is True:
            self.results['cbNoArtifactEncryption'] = [
                -1,
                f"Project '{self.name}' has artifacts.encryptionDisabled=true — "
                "build output is written to S3 unencrypted, and build artifacts "
                "routinely contain source code and embedded configuration"
            ]
        else:
            self.results['cbNoArtifactEncryption'] = [
                1, f"Project '{self.name}' encrypts its build artifacts"
            ]

    # ------------------------------------------------------------------ #
    # 6. Default (AWS-managed) KMS key
    # ------------------------------------------------------------------ #
    def _checkCbEncryptionDefaultKey(self):
        """
        CodeBuild does not leave encryptionKey null when none is specified — it
        populates it with the AWS-managed alias/aws/s3 key. So the check is
        whether the key IS that default, not whether it is absent. Verified live:
        a project created with no --encryption-key reports
        arn:aws:kms:...:alias/aws/s3.
        """
        key = self.project.get('encryptionKey') or ''
        if not key:
            self.results['cbEncryptionDefaultKey'] = [
                0, f"Project '{self.name}' reports no encryption key"
            ]
        elif key.endswith('alias/aws/s3'):
            self.results['cbEncryptionDefaultKey'] = [
                -1,
                f"Project '{self.name}' encrypts build output with the AWS-managed "
                "key alias/aws/s3, whose policy the account cannot restrict, "
                "rotate or revoke — use a customer managed key"
            ]
        else:
            self.results['cbEncryptionDefaultKey'] = [
                1, f"Project '{self.name}' encrypts with the customer key {key}"
            ]

    # ------------------------------------------------------------------ #
    # 7. Insecure SSL on the source
    # ------------------------------------------------------------------ #
    def _checkCbInsecureSSL(self):
        if self.source.get('insecureSsl') is True:
            self.results['cbInsecureSSL'] = [
                -1,
                f"Project '{self.name}' has source.insecureSsl=true — TLS "
                "certificate validation is disabled when cloning, so the source "
                "can be substituted by anyone able to intercept the connection"
            ]
        else:
            self.results['cbInsecureSSL'] = [
                1, f"Project '{self.name}' validates TLS on source checkout"
            ]

    # ------------------------------------------------------------------ #
    # 8. No VPC configuration
    # ------------------------------------------------------------------ #
    def _checkCbNoVpcConfig(self):
        """
        INFO rather than FAIL. A build outside a VPC is the AWS default and is
        correct for most public-dependency builds; it only matters when the build
        needs private-subnet isolation or must reach private resources.
        """
        vpcConfig = self.project.get('vpcConfig') or {}
        if vpcConfig.get('vpcId'):
            self.results['cbNoVpcConfig'] = [
                1,
                f"Project '{self.name}' runs inside VPC {vpcConfig['vpcId']}"
            ]
        else:
            self.results['cbNoVpcConfig'] = [
                0,
                f"Project '{self.name}' is not attached to a VPC — builds have "
                "direct internet egress. Acceptable for public-dependency builds; "
                "review if the build handles sensitive data"
            ]

    # ------------------------------------------------------------------ #
    # 9. No build logging at all
    # ------------------------------------------------------------------ #
    def _checkCbLogsDisabled(self):
        cw = (self.logsConfig.get('cloudWatchLogs') or {})
        s3 = (self.logsConfig.get('s3Logs') or {})

        ## CodeBuild defaults CloudWatch logging to ENABLED, so an absent status
        ## is not 'off'. Only an explicit DISABLED counts.
        cwOff = cw.get('status') == 'DISABLED'
        s3Off = s3.get('status', 'DISABLED') == 'DISABLED'

        if cwOff and s3Off:
            self.results['cbLogsDisabled'] = [
                -1,
                f"Project '{self.name}' has both CloudWatch and S3 build logging "
                "disabled — there is no record of what any build did, so a "
                "compromised build cannot be investigated after the fact"
            ]
        else:
            destinations = []
            if not cwOff:
                destinations.append('CloudWatch Logs')
            if not s3Off:
                destinations.append('S3')
            self.results['cbLogsDisabled'] = [
                1,
                f"Project '{self.name}' logs builds to "
                + ' and '.join(destinations)
            ]

    # ------------------------------------------------------------------ #
    # 10. S3 build logs not encrypted
    # ------------------------------------------------------------------ #
    def _checkCbS3LogsNotEncrypted(self):
        s3 = self.logsConfig.get('s3Logs') or {}
        if s3.get('status') != 'ENABLED':
            self.results['cbS3LogsNotEncrypted'] = [
                0, f"Project '{self.name}' does not write build logs to S3"
            ]
            return

        if s3.get('encryptionDisabled') is True:
            self.results['cbS3LogsNotEncrypted'] = [
                -1,
                f"Project '{self.name}' writes S3 build logs with encryption "
                "disabled — build logs frequently contain resolved secrets, "
                "connection strings and internal hostnames"
            ]
        else:
            self.results['cbS3LogsNotEncrypted'] = [
                1, f"Project '{self.name}' encrypts its S3 build logs"
            ]

    # ------------------------------------------------------------------ #
    # 11. Unauthenticated public source
    # ------------------------------------------------------------------ #
    def _checkCbSourceCredentialsInsecure(self):
        sourceType = self.source.get('type')
        if sourceType not in ('GITHUB', 'GITHUB_ENTERPRISE', 'BITBUCKET'):
            self.results['cbSourceCredentialsInsecure'] = [
                0,
                f"Project '{self.name}' source type is {sourceType or 'unknown'} "
                "— third-party source authentication does not apply"
            ]
            return

        ## CodeBuild stores the OAuth/PAT token at the account level rather than
        ## per project, so an absent source.auth does NOT prove the source is
        ## unauthenticated. Report INFO and say why.
        if (self.source.get('auth') or {}).get('type'):
            self.results['cbSourceCredentialsInsecure'] = [
                1,
                f"Project '{self.name}' declares source authentication of type "
                + str(self.source['auth'].get('type'))
            ]
        else:
            self.results['cbSourceCredentialsInsecure'] = [
                0,
                f"Project '{self.name}' declares no per-project source auth. "
                "CodeBuild resolves credentials from the account-level source "
                "credential for the provider, so this is not conclusive — verify "
                "with list_source_credentials"
            ]

    # ------------------------------------------------------------------ #
    # 12. Deprecated build image
    # ------------------------------------------------------------------ #
    def _checkCbImageOutdated(self):
        image = self.environment.get('image') or ''
        if not image:
            self.results['cbImageOutdated'] = [
                0, f"Project '{self.name}' reports no build image"
            ]
            return

        lowered = image.lower()
        matched = [f for f in self.DEPRECATED_IMAGE_FRAGMENTS if f in lowered]
        if matched:
            self.results['cbImageOutdated'] = [
                -1,
                f"Project '{self.name}' builds on {image}, a retired CodeBuild "
                "image — its toolchain and OS packages no longer receive "
                "security updates"
            ]
        else:
            self.results['cbImageOutdated'] = [
                1, f"Project '{self.name}' uses build image {image}"
            ]

    # ------------------------------------------------------------------ #
    # 13. No concurrent build limit
    # ------------------------------------------------------------------ #
    def _checkCbConcurrentBuildLimitNotSet(self):
        limit = self.project.get('concurrentBuildLimit')
        if limit:
            self.results['cbConcurrentBuildLimitNotSet'] = [
                1, f"Project '{self.name}' caps concurrent builds at {limit}"
            ]
        else:
            self.results['cbConcurrentBuildLimitNotSet'] = [
                -1,
                f"Project '{self.name}' has no concurrentBuildLimit — a webhook "
                "loop or a push storm can start unbounded parallel builds, "
                "consuming the account's build minutes without a ceiling"
            ]

    # ------------------------------------------------------------------ #
    # 14. No tags
    # ------------------------------------------------------------------ #
    def _checkCbNoTags(self):
        if self.tags:
            keys = [t.get('Key', '?') for t in self.tags]
            self.results['cbNoTags'] = [
                1, f"{len(self.tags)} tag(s): " + self._joinNames(keys)
            ]
        else:
            self.results['cbNoTags'] = [
                -1,
                f"Project '{self.name}' has no tags — it cannot be attributed to "
                "an owning team, and CI/CD projects accumulate faster than any "
                "other resource type"
            ]

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _nameLooksLikeCredential(self, name):
        lowered = (name or '').lower()
        if lowered in self.EXACT_CREDENTIAL_NAMES:
            return True
        return any(f in lowered for f in self.CREDENTIAL_NAME_FRAGMENTS)

    def _joinNames(self, names):
        shown = ', '.join(str(n) for n in names[:self.MAX_NAMES_IN_MESSAGE])
        extra = len(names) - self.MAX_NAMES_IN_MESSAGE
        if extra > 0:
            shown += f" (+{extra} more)"
        return shown
