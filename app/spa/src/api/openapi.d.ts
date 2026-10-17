// GENERATED from app/openapi.yaml by docs-api/scripts/openapi-check.mjs. Do not edit; run `npm run openapi:types`.
export interface paths {
    "/admin": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Decoy (every method). Mounted before authentication; never reads a body. */
        get: operations["decoyAdmin"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/admin/{rest}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                rest: string;
            };
            cookie?: never;
        };
        /** Decoy (every method). Mounted before authentication; never reads a body. */
        get: operations["decoyAdminRest"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/agreements": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listAgreements"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/agreements/{agreementId}/{version}/text": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                agreementId: components["parameters"]["AgreementId"];
                version: components["schemas"]["AgreementVersion"];
            };
            cookie?: never;
        };
        get: operations["getAgreementText"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/agreements/{agreementId}/accept": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                agreementId: components["parameters"]["AgreementId"];
            };
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["acceptAgreement"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/agreements/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getAgreementStatus"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/audit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listTenantAudit"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/documents": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listDocuments"];
        put?: never;
        post: operations["createDocument"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/documents/{docId}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                docId: components["parameters"]["DocId"];
            };
            cookie?: never;
        };
        get: operations["getDocument"];
        put?: never;
        post?: never;
        delete: operations["deleteDocument"];
        options?: never;
        head?: never;
        patch: operations["patchDocument"];
        trace?: never;
    };
    "/documents/{docId}/content": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                docId: components["parameters"]["DocId"];
            };
            cookie?: never;
        };
        get?: never;
        /** @description Raw body; Content-Type must equal the declared type. The server recomputes SHA-256 and sniffs magic bytes. */
        put: operations["uploadDocumentContent"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/documents/{docId}/download": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                docId: components["parameters"]["DocId"];
            };
            cookie?: never;
        };
        get: operations["getDownloadUrl"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/grc/assessment": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getGrcAssessment"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/grc/profile": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getGrcProfile"];
        put: operations["putGrcProfile"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/grc/responsibility-matrix": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getResponsibilityMatrix"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/grc/ruleset": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getRuleset"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/healthz": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getHealth"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/me": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getMe"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/soc/audit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listPlatformAudit"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/soc/incidents": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["listIncidents"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/soc/incidents/{incidentId}": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                incidentId: components["parameters"]["IncidentId"];
            };
            cookie?: never;
        };
        get: operations["getIncident"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/soc/incidents/{incidentId}/evidence": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                incidentId: components["parameters"]["IncidentId"];
            };
            cookie?: never;
        };
        get: operations["verifyIncidentEvidence"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/soc/incidents/{incidentId}/report": {
        parameters: {
            query?: never;
            header?: never;
            path: {
                incidentId: components["parameters"]["IncidentId"];
            };
            cookie?: never;
        };
        get: operations["getIncidentReport"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/soc/metrics": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getSocMetrics"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/soc/overview": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getSocOverview"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/soc/posture": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["getPosture"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        Acceptance: {
            /** Format: date-time */
            acceptedAt: string;
            acceptedBy: {
                groups: string[];
                sub: string;
            };
            agreementId: components["schemas"]["AgreementId"];
            /** @constant */
            authorityConfirmed: true;
            /** @constant */
            method: "click-through";
            requestId: string;
            /** @constant */
            schemaVersion: "1";
            sourceIp: string | null;
            sourceIpTrusted: boolean;
            tenantId: components["schemas"]["TenantId"];
            /** @constant */
            textMediaType: "text/plain; charset=utf-8";
            textSha256: components["schemas"]["Sha256Hex"];
            userAgent: string | null;
            version: components["schemas"]["AgreementVersion"];
        };
        AcceptanceRequest: {
            /** @constant */
            authorityConfirmed: true;
            sha256: components["schemas"]["Sha256Hex"];
            version: components["schemas"]["AgreementVersion"];
        };
        Agreement: {
            agreementId: components["schemas"]["AgreementId"];
            /** Format: date */
            effectiveDate: string;
            required: boolean;
            sha256: components["schemas"]["Sha256Hex"];
            title: string;
            version: components["schemas"]["AgreementVersion"];
        };
        AgreementId: string;
        AgreementStatus: {
            accepted: components["schemas"]["Acceptance"][];
            complete: boolean;
            pending: components["schemas"]["Agreement"][];
        };
        AgreementVersion: string;
        /** @enum {string} */
        AuditAction: "DOCUMENT_CREATED" | "DOCUMENT_UPLOADED" | "DOCUMENT_UPDATED" | "DOCUMENT_DELETED" | "DOCUMENT_DOWNLOAD_URL_ISSUED" | "AGREEMENT_ACCEPTED" | "GRC_PROFILE_UPDATED" | "ACCESS_DENIED" | "DECOY_ROUTE_HIT" | "SOC_EVIDENCE_VERIFIED" | "SOC_REPORT_EXPORTED";
        AuditEvent: {
            action: components["schemas"]["AuditAction"];
            actor: {
                groups?: string[];
                sub?: string;
                tenantId?: string;
                tokenPresent?: boolean;
                /** @enum {string} */
                type: "user" | "anonymous";
            };
            /** Format: date-time */
            at: string;
            details: {
                [key: string]: string | number | boolean | null;
            };
            eventId: string;
            eventKey: string;
            /** @enum {string} */
            outcome: "SUCCESS" | "DENIED";
            requestId: string;
            resource: {
                id?: string;
                type: string;
            };
            /** @constant */
            schemaVersion: "1";
            sourceIp: string | null;
            sourceIpTrusted: boolean;
            userAgent: string | null;
        };
        AuditPage: {
            items: components["schemas"]["AuditEvent"][];
            nextCursor?: string;
        };
        Citation: {
            article?: string;
            source: string;
            status: components["schemas"]["CitationStatus"];
            url?: string;
        };
        /** @enum {string} */
        CitationStatus: "doc" | "verify";
        /** @enum {string} */
        Classification: "public" | "internal" | "confidential" | "restricted";
        /** @enum {string} */
        ContentType: "application/pdf" | "text/plain" | "image/png" | "image/jpeg" | "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
        DocId: string;
        DocumentCreate: {
            classification: components["schemas"]["Classification"];
            contentType: components["schemas"]["ContentType"];
            description?: string;
            sha256: components["schemas"]["Sha256Hex"];
            sizeBytes: number;
            tags?: components["schemas"]["Tags"];
            title: string;
        };
        DocumentMeta: {
            classification: components["schemas"]["Classification"];
            contentType: components["schemas"]["ContentType"];
            /** Format: date-time */
            createdAt: string;
            description?: string;
            docId: components["schemas"]["DocId"];
            ownerSub: string;
            sha256: components["schemas"]["Sha256Hex"];
            sizeBytes: number;
            status: components["schemas"]["DocumentStatus"];
            tags: components["schemas"]["Tags"];
            title: string;
            /** Format: date-time */
            updatedAt: string;
            version: number;
        };
        DocumentPage: {
            items: components["schemas"]["DocumentMeta"][];
            nextCursor?: string;
        };
        DocumentPatch: {
            classification?: components["schemas"]["Classification"];
            description?: string;
            tags?: components["schemas"]["Tags"];
            title?: string;
        };
        /** @enum {string} */
        DocumentStatus: "PENDING_UPLOAD" | "AVAILABLE";
        DownloadUrl: {
            /** Format: date-time */
            expiresAt: string;
            url: string;
        };
        EvidenceCheck: {
            actualSha256: components["schemas"]["NullableString"];
            error: components["schemas"]["NullableString"];
            key: string;
            legalHold: boolean | null;
            ok: boolean;
            recordedSha256: components["schemas"]["NullableString"];
            retention: {
                mode: components["schemas"]["NullableString"];
                retainUntil: components["schemas"]["NullableString"];
            } | null;
            versionId: components["schemas"]["NullableString"];
        };
        EvidenceRecord: {
            bucket?: components["schemas"]["NullableString"];
            key: string;
            sha256: components["schemas"]["NullableString"];
            sha256Base64?: components["schemas"]["NullableString"];
            versionId: components["schemas"]["NullableString"];
        };
        EvidenceVerification: {
            chainOfCustodyOk: boolean | null;
            checks: components["schemas"]["EvidenceCheck"][];
            incidentId: string;
            label: string;
            objectLock: {
                days: components["schemas"]["NullableNumber"];
                enabled: boolean | null;
                mode: components["schemas"]["NullableString"];
            };
            truncated: boolean;
            /** Format: date-time */
            verifiedAt: string;
        };
        Framework: {
            citation: string;
            citationStatus: components["schemas"]["CitationStatus"];
            id: string;
            notes?: string;
            regulator: string;
            title: string;
        };
        /** @enum {string} */
        GateOutcome: "success" | "failure" | "skipped" | "unknown";
        GrcAssessment: {
            disclaimer: string;
            findings: components["schemas"]["GrcFinding"][];
            /** Format: date-time */
            generatedAt: string;
            platformFacts: {
                [key: string]: string | number | boolean | string[];
            };
            profileVersion: number;
            rulesetSha256: components["schemas"]["Sha256Hex"];
            rulesetVersion: string;
            summary: {
                CUSTOMER_ACTION: number;
                GAP: number;
                INFO: number;
                MET: number;
                NOT_APPLICABLE: number;
                PARTIAL: number;
            };
        };
        GrcFinding: {
            citations: components["schemas"]["Citation"][];
            citationStatus: components["schemas"]["CitationStatus"];
            controls: string[];
            framework: string;
            obligation: string;
            parameters?: {
                [key: string]: string | number | boolean;
            };
            rationale: string;
            ruleId: string;
            status: components["schemas"]["GrcFindingStatus"];
            topic: string;
        };
        /** @enum {string} */
        GrcFindingStatus: "MET" | "PARTIAL" | "GAP" | "CUSTOMER_ACTION" | "NOT_APPLICABLE" | "INFO";
        GrcProfile: {
            cbeRegulated: boolean;
            dataSubjectRegions: ("EG" | "EU" | "SA" | "OTHER")[];
            governmentData: boolean;
            jurisdictions: ("EG" | "EU" | "SA")[];
            processesPersonalData: boolean;
            processesSensitiveData: boolean;
            /** @enum {string} */
            sector: "general" | "financial" | "health" | "government" | "critical-infrastructure";
        };
        GrcProfileRecord: {
            profile: components["schemas"]["GrcProfile"];
            /** Format: date-time */
            updatedAt: string;
            updatedBy: string;
            version: number;
        };
        /** @enum {string} */
        Group: "admin" | "member" | "auditor" | "secops-analyst";
        Health: {
            /** @constant */
            status: "ok";
        };
        IncidentDetail: {
            actions: components["schemas"]["ProjectedAction"][];
            attempts: components["schemas"]["NullableNumber"];
            block: {
                blockedCidr: components["schemas"]["NullableString"];
                blockExpiresAt: components["schemas"]["NullableString"];
                blockState: components["schemas"]["NullableString"];
            } | null;
            containedAt: components["schemas"]["NullableString"];
            displayStatus: string;
            eventTime: components["schemas"]["NullableString"];
            evidenceRecords: components["schemas"]["EvidenceRecord"][];
            executionArn: components["schemas"]["NullableString"];
            failure: components["schemas"]["NullableString"];
            findingCreatedAt: components["schemas"]["NullableString"];
            findingType: components["schemas"]["NullableString"];
            firstEventTime: components["schemas"]["NullableString"];
            guardReason: components["schemas"]["NullableString"];
            incidentId: string;
            mttcSeconds: components["schemas"]["NullableNumber"];
            notifyOnly: boolean;
            relatedAudit: components["schemas"]["AuditEvent"][];
            resourceType: components["schemas"]["NullableString"];
            severity: components["schemas"]["NullableNumber"];
            sfnStartedAt: components["schemas"]["NullableString"];
            status: string;
            timeline: components["schemas"]["TimelineEntry"][];
            triage: components["schemas"]["Triage"];
            wouldContainAt: components["schemas"]["NullableString"];
        };
        IncidentPage: {
            items: components["schemas"]["IncidentSummary"][];
            nextCursor?: string;
        };
        /** @enum {string} */
        IncidentStatus: "DETECTED" | "CONTAINED" | "WOULD_CONTAIN_DRY_RUN" | "BLOCKED_BY_GUARD" | "NO_PLAYBOOK_ANALYST_REVIEW" | "FAILED";
        IncidentSummary: {
            containedAt: components["schemas"]["NullableString"];
            displayStatus: string;
            eventTime: components["schemas"]["NullableString"];
            findingType: components["schemas"]["NullableString"];
            incidentId: string;
            mttcSeconds: components["schemas"]["NullableNumber"];
            scenario: string;
            severity: components["schemas"]["NullableNumber"];
            status: string;
            tactic: string;
        };
        IrEvidence: {
            actual_sha256: components["schemas"]["NullableString"];
            error: components["schemas"]["NullableString"];
            key: string;
            ok: boolean;
            recorded_sha256: components["schemas"]["NullableString"];
            version_id: components["schemas"]["NullableString"];
        };
        IrReport: {
            actions: components["schemas"]["ProjectedAction"][];
            authoritative: string;
            chain_of_custody_ok: boolean | null;
            contained_at: components["schemas"]["NullableString"];
            containment_verified: boolean | null;
            detection_latency_seconds: components["schemas"]["NullableNumber"];
            event_time: components["schemas"]["NullableString"];
            evidence: components["schemas"]["IrEvidence"][];
            execution_arn: components["schemas"]["NullableString"];
            executive_summary: {
                attack_techniques: string[];
                eradication: string[];
                impact: string;
                mttc_verdict: string;
                recovery: string[];
                references: string[];
                scenario: string;
                status: string;
                tactic: string;
            };
            failure: components["schemas"]["NullableString"];
            finding_created_at: components["schemas"]["NullableString"];
            finding_type: components["schemas"]["NullableString"];
            generated_by: string;
            guard_reason: components["schemas"]["NullableString"];
            incident_id: string;
            mttc_seconds: components["schemas"]["NullableNumber"];
            mttc_target_met: boolean | null;
            resource_type: components["schemas"]["NullableString"];
            severity: components["schemas"]["NullableNumber"];
            status: string;
        };
        Jurisdiction: {
            frameworks: string[];
            /** @enum {string} */
            id: "EG" | "EU" | "SA";
            name: string;
        };
        MatrixCell: {
            notes: string;
            /** @enum {string} */
            responsibility: "provider" | "shared" | "customer";
            service: string;
            /** @enum {string} */
            status: "built" | "mapped";
            verify: boolean;
        };
        Me: {
            email?: string;
            groups: components["schemas"]["Group"][];
            permissions: components["schemas"]["Permission"][];
            sub: string;
            tenantId: components["schemas"]["TenantId"];
        };
        MttcStats: {
            last: components["schemas"]["NullableNumber"];
            max: components["schemas"]["NullableNumber"];
            p50: components["schemas"]["NullableNumber"];
            p90: components["schemas"]["NullableNumber"];
            samples: number;
            targetSeconds: number;
        };
        NullableNumber: number | null;
        NullableString: string | null;
        /** @enum {string} */
        Permission: "doc:read" | "doc:write" | "doc:delete" | "audit:read" | "agreement:read" | "agreement:accept" | "grc:read" | "grc:assess" | "grc:profile:write" | "soc:read" | "soc:evidence" | "posture:read";
        Posture: {
            build: {
                builtAt: components["schemas"]["NullableString"];
                ciRunId: components["schemas"]["NullableString"];
                commit: string;
                gates: {
                    app: components["schemas"]["GateOutcome"];
                    sast: components["schemas"]["GateOutcome"];
                    sca: components["schemas"]["GateOutcome"];
                    secrets: components["schemas"]["GateOutcome"];
                };
                gatesEnforced: boolean;
                local: boolean;
            };
            containment: {
                dryRun: boolean | null;
                failedLast24h: number | null;
                lastMttcSeconds: components["schemas"]["NullableNumber"];
                playbooksEnabled: boolean;
                targetSeconds: number;
            };
            /** Format: date-time */
            generatedAt: string;
            image: {
                ecrScan: {
                    completedAt: components["schemas"]["NullableString"];
                    critical: number | null;
                    high: number | null;
                    low: number | null;
                    medium: number | null;
                    status: string;
                } | null;
                reference: components["schemas"]["NullableString"];
            };
            imagePolicy: string;
        };
        Problem: {
            /** @enum {string} */
            code: "UNAUTHENTICATED" | "TENANT_INVALID" | "FORBIDDEN" | "AGREEMENT_REQUIRED" | "NOT_FOUND" | "VALIDATION_FAILED" | "CONFLICT" | "PRECONDITION_FAILED" | "PAYLOAD_TOO_LARGE" | "UNSUPPORTED_MEDIA_TYPE" | "INTEGRITY_MISMATCH" | "RATE_LIMITED" | "SERVICE_UNAVAILABLE" | "INTERNAL";
            detail?: string;
            errors?: {
                message: string;
                path: string;
            }[];
            requestId: string;
            status: number;
            title: string;
            type: string;
        };
        ProjectedAction: {
            at: components["schemas"]["NullableString"];
            details?: string;
            playbook: components["schemas"]["NullableString"];
            step: components["schemas"]["NullableString"];
        };
        ResponsibilityMatrix: {
            controls: {
                cells: {
                    aws: components["schemas"]["MatrixCell"];
                    azure: components["schemas"]["MatrixCell"];
                    gcp: components["schemas"]["MatrixCell"];
                };
                control: string;
                id: string;
                layer: string;
            }[];
            disclaimer: string;
            /** Format: date */
            lastReviewed: string;
            layers: {
                layer: string;
                notes: string;
                owner: string;
            }[];
            providers: ("aws" | "azure" | "gcp")[];
            version: string;
        };
        RulesetSummary: {
            disclaimer: string;
            frameworks: components["schemas"]["Framework"][];
            jurisdictions: components["schemas"]["Jurisdiction"][];
            /** Format: date */
            lastReviewed: string;
            ruleCount: number;
            sha256: components["schemas"]["Sha256Hex"];
            version: string;
        };
        Sha256Hex: string;
        SocMetrics: {
            byStatus: {
                BLOCKED_BY_GUARD: number;
                CONTAINED: number;
                DETECTED: number;
                FAILED: number;
                NO_PLAYBOOK_ANALYST_REVIEW: number;
                WOULD_CONTAIN_DRY_RUN: number;
            };
            byTactic: {
                count: number;
                tactic: string;
                techniques: string[];
            }[];
            mttc: components["schemas"]["MttcStats"];
            /** Format: date-time */
            since: string;
            truncated: boolean;
            /** @enum {string} */
            window: "24h" | "7d" | "30d";
        };
        SocOverview: {
            /** Format: date-time */
            generatedAt: string;
            incidents: components["schemas"]["IncidentSummary"][];
            metrics: components["schemas"]["SocMetrics"];
        };
        Tags: string[];
        TenantId: string;
        TimelineEntry: {
            at: components["schemas"]["NullableString"];
            detail?: string;
            /** @enum {string} */
            kind: "DETECTED" | "GUARD" | "ACTION" | "CONTAINED" | "WOULD_CONTAIN" | "FAILED" | "EVIDENCE" | "ANALYST";
            label: string;
        };
        Triage: {
            eradication: string[];
            impact: string;
            recovery: string[];
            references: string[];
            scenario: string;
            tactic: string;
            techniques: string[];
        };
    };
    responses: {
        /** @description RFC 9457 problem. */
        Problem: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/problem+json": components["schemas"]["Problem"];
            };
        };
    };
    parameters: {
        AgreementId: components["schemas"]["AgreementId"];
        Cursor: string;
        DocId: components["schemas"]["DocId"];
        From: string;
        IncidentId: string;
        Limit: number;
        To: string;
    };
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    decoyAdmin: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Identical in shape to any RBAC denial. */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    decoyAdminRest: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                rest: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Identical in shape to any RBAC denial. */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    listAgreements: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The agreement catalogue with server-computed text hashes. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Agreement"][];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getAgreementText: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                agreementId: components["parameters"]["AgreementId"];
                version: components["schemas"]["AgreementVersion"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The agreement text (render as plain text only). */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "text/plain": string;
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    acceptAgreement: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                agreementId: components["parameters"]["AgreementId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AcceptanceRequest"];
            };
        };
        responses: {
            /** @description Already accepted; the existing record (idempotent). */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Acceptance"];
                };
            };
            /** @description Acceptance recorded (click-through, not an e-signature). */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Acceptance"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getAgreementStatus: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Acceptance status for the caller's tenant. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AgreementStatus"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    listTenantAudit: {
        parameters: {
            query?: {
                cursor?: components["parameters"]["Cursor"];
                from?: components["parameters"]["From"];
                limit?: components["parameters"]["Limit"];
                to?: components["parameters"]["To"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The caller's tenant audit trail, newest first. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AuditPage"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    listDocuments: {
        parameters: {
            query?: {
                cursor?: components["parameters"]["Cursor"];
                limit?: components["parameters"]["Limit"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Newest first; tombstones are excluded. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DocumentPage"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    createDocument: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["DocumentCreate"];
            };
        };
        responses: {
            /** @description Metadata recorded; status PENDING_UPLOAD. */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DocumentMeta"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getDocument: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                docId: components["parameters"]["DocId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Document metadata. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DocumentMeta"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    deleteDocument: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                docId: components["parameters"]["DocId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Tombstoned; the S3 object gets a delete marker (erasure completes when non-current versions expire, 30 days). */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            default: components["responses"]["Problem"];
        };
    };
    patchDocument: {
        parameters: {
            query?: never;
            header?: {
                "If-Match"?: string;
            };
            path: {
                docId: components["parameters"]["DocId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["DocumentPatch"];
            };
        };
        responses: {
            /** @description Updated metadata. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DocumentMeta"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    uploadDocumentContent: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                docId: components["parameters"]["DocId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/pdf": string;
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document": string;
                "image/jpeg": string;
                "image/png": string;
                "text/plain": string;
            };
        };
        responses: {
            /** @description Content stored; status AVAILABLE. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DocumentMeta"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getDownloadUrl: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                docId: components["parameters"]["DocId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A version-pinned pre-signed GET (navigation, not fetch). */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DownloadUrl"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getGrcAssessment: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Deterministic rule evaluation over the tenant profile and platform facts. Not legal advice. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["GrcAssessment"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getGrcProfile: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The tenant's GRC profile. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["GrcProfileRecord"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    putGrcProfile: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["GrcProfile"];
            };
        };
        responses: {
            /** @description Stored profile. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["GrcProfileRecord"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getResponsibilityMatrix: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Shared-responsibility matrix (AWS built; Azure/GCP mapped). */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResponsibilityMatrix"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getRuleset: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Ruleset identity, disclaimer and frameworks. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RulesetSummary"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getHealth: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Liveness only (no version, no dependency checks). */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Health"];
                };
            };
        };
    };
    getMe: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The verified principal. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Me"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    listPlatformAudit: {
        parameters: {
            query?: {
                cursor?: components["parameters"]["Cursor"];
                from?: components["parameters"]["From"];
                limit?: components["parameters"]["Limit"];
                to?: components["parameters"]["To"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The platform-scoped (`_platform`) audit trail. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AuditPage"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    listIncidents: {
        parameters: {
            query: {
                cursor?: components["parameters"]["Cursor"];
                limit?: components["parameters"]["Limit"];
                status: components["schemas"]["IncidentStatus"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Incidents in one status, newest first. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IncidentPage"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getIncident: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                incidentId: components["parameters"]["IncidentId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Allow-listed projection of the incident row. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IncidentDetail"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    verifyIncidentEvidence: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                incidentId: components["parameters"]["IncidentId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description SHA-256 recomputed from S3 for every evidence record (live verification view). */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EvidenceVerification"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getIncidentReport: {
        parameters: {
            query?: {
                format?: "json" | "md";
            };
            header?: never;
            path: {
                incidentId: components["parameters"]["IncidentId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description IR report (JSON) or a Markdown attachment (download only, never rendered). */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IrReport"];
                    "text/markdown": string;
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getSocMetrics: {
        parameters: {
            query?: {
                window?: "24h" | "7d" | "30d";
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description MTTC, status counts and ATT&CK breakdown for the window. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SocMetrics"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getSocOverview: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Latest incidents (≤ 50) and 24 h metrics in one call (polled every 15 s). */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SocOverview"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
    getPosture: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Build gates, image policy, live ECR scan and containment health. */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Posture"];
                };
            };
            default: components["responses"]["Problem"];
        };
    };
}
