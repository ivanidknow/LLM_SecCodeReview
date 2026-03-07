
# Discovery

### Architecture.

%% Насколько прочна конструкция, в которой это живет? %%
##### Component Topology.
* Layered Analysis (layered_analysis.protocol)
* Идентификация Statefull и Stateless компонентов (state_analysis.protocol)
* Coupling & Cohesion (coupling_cohesion.protocol)
* Third-party Surface (third_party_surface.protocol)
* Critical Paths (critical_paths.protocol)
* Shared Resources & Side-Channels (shared_resources_sidechannel.protocol)
* Fail-Safe Defaults & Resilience (resilience_failsafe.protocol)
##### Trust Boundaries.
* Segmentation (segmentation.protocol)
* Entry Points Analysis (entry_points.protocol)
* Validation Chokepoints (validation_chokepoints.protocol)
* Идентификация Privilege Transitions (privilege_transitions.protocol)
* Анализ Outbound Trust (outbound_trust.protocol)
##### Interface Mapping.
* Protocol Discovery (protocol_discovery.protocol)
* Payload Analysis (payload_analysis.protocol)
* Security Controls (security_controls.protocol)
* Error Verbosity (error_verbosity.protocol)
* Dependency & Shadow Interfaces (shadow_interfaces.protocol)
##### IAM & Authorization.
* Identity Model (identity_model.protocol)
* Authentication Strategy (authentication_strategy.protocol)
* Authorization Model (authorization_model.protocol)
* Depth of AuthZ (depth_of_authz.protocol)
* Lifecycle & Revocation (lifecycle_revocation.protocol)
##### Data at Rest & in Transit.
* Data Inventory (data_inventory.protocol)
* Исследование Data at Rest (data_at_rest.protocol)
* Исследование Data in Transit (data_in_transit.protocol)
* Secrets Management (secrets_management.protocol)
* Data Retention (data_retention.protocol)
##### Negative Constraints.
* Structural Antipatterns (structural_logic_smells.protocol)
* Connectivity & Coupling (connectivity_coupling.protocol)
* State & Memory (state_memory_leaks.protocol)
* Logic & Enforcement (logic_enforcement_smells.protocol)
* Error & Feedback (error_feedback_smells.protocol)
* Resource & Lifecycle (resource_lifecycle_smells.protocol)
* External & Supply Chain Constraints (external_supply_chain.protocol)


---

### Бизнес-процессы. 

%% Понимание того, как приложение превращает код в деньги и ценность %%

##### Value Chain Mapping 
* Monetization Points Identification (monetization_points.protocol)
* Asset Lifecycle Trace (asset_lifecycle_trace.protocol)
* Business-Critical Dependency Tree (business_critical_dependencies.protocol)
* Throughput & Bottleneck Analysis (throughput_bottleneck.protocol)
* Compliance & Regulatory Anchors (compliance_anchors.protocol)
##### Transaction Integrity & Non-Repudiation
* Atomic Business Operations (atomic_business_operations.protocol)
* Idempotency & Duplicate Protection (idempotency_protection.protocol)
* Immutable Audit Trail (immutable_audit_trail.protocol)
* Intent & Origin Proof (intent_origin_proof.protocol)
* Data Consistency & Checksums (data_consistency_checksums.protocol)
* Temporal Integrity (temporal_integrity.protocol)
##### Business Logic Abuse
* Incentive & Reward Manipulation (incentive_reward_manipulation.protocol)
* Multi-Step Flow Bypassing (multi_step_flow_bypassing.protocol)
* Rate & Threshold Abuse (rate_threshold_abuse.protocol)
* Input-Driven Price & Quantity Tampering (price_quantity_tampering.protocol)
* Competitive Intelligence & Scraping (competitive_scraping.protocol)
* Inventory & Resource Exhaustion (inventory_exhaustion.protocol)
##### BIA: Business Impact Analysis
* Critical Path Interruption Cost (critical_path_cost.protocol)
* Recovery Time Objective (RTO) & Recovery Point Objective (RPO) (rto_rpo_analysis.protocol)
* Cascading Failure Financial Impact (cascading_failure_impact.protocol)
* Data Breach Financial & Legal Liability (data_breach_liability.protocol)
* Reputation & Trust Loss Modeling (reputation_trust_loss.protocol)
* Dependency & Third-Party Outage Risk (third_party_outage.protocol)
##### Automated Fraud Scenarios
* Account Takeover (ATO) & Credential Stuffing (ato_credential_stuffing.protocol)
* Multi-Accounting & Sybil Attacks (multi_accounting_sybil.protocol)
* Inventory Hoarding & Scalping (inventory_hoarding.protocol)
* Promotion & Coupon Abuse (promotion_abuse.protoco)
* Carding & Payment Testing (carding_payment_testing.protocol)
* Fake Engagement & Reputation Manipulation (fake_engagement.protocol)
##### Reconciliation & Anti-Tampering
* External State Sync (external_state_sync.protocol)
* Double-Entry Bookkeeping Integrity (double_entry_integrity.protocol)
* Aggregate Invariant Checks (aggregate_invariant_checks.protocol)
* Integrity Checksumming for Records (record_integrity_checksumming.protocol)
* Log-to-State Cross-Verification (log_state_cross_verification.protocol)
* Alerting on Reconciliation Mismatch (reconciliation_alerting.protocol)
##### Administrative & Governance Logic
* Privileged Action Governance (four_eyes_principle.protocol)
* Admin Panel Exposure & Logic Abuse (admin_logic_security.protocol)
* Access Recertification & Orphaned Accounts (access_governance.protocol)
* Sensitive Configuration Tampering (config_integrity.protocol)
* Shadow API & Feature Flag Abuse (feature_flag_governance.protocol)


---

### License Compliance

%% Идентификация юридических и операционных рисков, связанных с использованием стороннего кода. %%

##### License Inventory & Taxonomy
* Direct Dependency Identification (direct_dependency.protocol)
* Transitive Dependency Chain (transitive_chain.protocol)
* Dual-License Detection (dual_license.protocol)
* Permissive vs Copyleft Classification (license_classification.protocol)
##### Legal Compatibility Analysis
* Copyleft Contamination Audit (copyleft_contamination.protocol)
* Incompatible License Mixing (license_mixing_conflicts.protocol)
* SaaS/Network Trigger Analysis (saas_network_trigger.protocol)
* Linking Method Evaluation (linking_method.protocol)
##### Business & Monetization Impact
* Commercial Use Prohibition (commercial_prohibition.protocol)
* White-Label & Redistribution Constraints (redistribution_constraints.protocol)
* Patent Grant & Liability (patent_grant_liability.protocol)
* Attribution & Trademark Compliance (attribution_trademark.protocol)
##### Supply Chain & Provenance
* Provenance Verification (provenance_verification.protocol)
* License Evolution Tracking (license_evolution.protocol)
* SBOM (Software Bill of Materials) Quality (sbom_quality.protocol)
* Abandoned/Unmaintained Component Risk (abandoned_risk.protocol)


---

# Modeling

### DFD (Data Flow Diagram)

%% Инвентаризация и чертеж системы: кто с кем общается, где лежат данные и где заканчивается «своё» и начинается «чужое». %%

##### Entity & Process Mapping
* External Interactors Identification (external_interactors.protocol)
* Automated Agents & Bots (automated_agents.protocol)
* Process Decomposition (process_decomposition.protocol)
* Inter-Process Communication (IPC) Identification (ipc_identification.protocol)
##### Data Store Inventory
* Persistent Storage (persistent_storage.protocol)
* Volatile & Cache Storage (volatile_storage.protocol)
* Side-Channel & Hidden Storage (side_channel.protocol)
* Metadata & Indexes (metadata_indexes.protocol)
##### Flow Path Tracing
* Synchronous Request-Response Paths (sync_request_response.protocol)
* Asynchronous & Event-Driven Flows (async_event_driven.protocol)
* Outbound & Third-Party Integration Paths (outbound_integration.protocol)
* Administrative & Management Flows (admin_management.protocol)
##### Trust Boundary Crossing
* External-to-Internal Transitions (external_internal.protocol)
* Network & Infrastructure Boundaries (network_infra.protocol)
* Privilege & Logical Boundaries (privilege_logical.protocol)
* Integrity & Validation Chokepoints (validation_chokepoints.protocol)


---

### Threat Modeling

%% Поиск дыр и план работ: размышление, как хакер может сломать чертеж, выбор самых опасных угроз и принятие решений по ограничению. %%

##### STRIDE Assessment
* Spoofing (stride_spoofing.protocol)
* Tampering (stride_tampering.protocol)
* Repudiation (stride_repudiation.protocol)
* Information Disclosure (stride_info_disclosure.protocol)
* Denial of Service (stride_dos.protocol)
* Elevation of Privilege (stride_eop.protocol)
##### Attack Trees & Scenarios
* Lateral Movement Scenarios (lateral_movement.protocol)
* Supply Chain Attack Modeling (supply_chain.protocol)
* Business Logic Abuse Scenarios (business_logic_abuse.protocol)
* Data Exfiltration Scenarios (data_exfiltration.protocol)
##### Threat Ranking & Prioritization
* DREAD Scoring Model (dread_scoring.protocol)
* BIA-driven Risk Mapping (bia_risk_mapping.protocol)
* Likelihood vs. Impact Matrix (likelihood_impact_matrix.protocol)
* Remediation Cost-Benefit Analysis (cost_benefit_analysis.protocol)
##### Countermeasure Mapping
* Mitigation Strategy Selection (mitigation_strategy.protocol)
* Technical Control Specification (technical_controls.protocol)
* Security-by-Design Patterns (design_patterns.protocol)
* Verification & Testing Requirements (verification_testing.protocol)

---

# Deep Scan

### Discovery-Driven Static Analysis

%% Проведение контекстного статического анализа кода с использованием данных инвентаризации для выявления жестко заданных секретов (Secrets) и небезопасного использования функций в критических узлах системы. %%

##### Context-Aware Secret Scanning
* Provider-Specific Entropy Analysis (provider_entropy_analysis.protocol)
* Identity-Linked Variable Correlation (identity_variable_correlation.protocol)
* Config-to-Source Leak Detection (config_to_source_leak.protocol)
* Semantic Log & Exception Leak Analysis (semantic_log_exception_leak.protocol)
* Post-Exploitation Secret Discovery (post_exploitation_secrets.protocol)
##### Sensitive Sink Mapping
* Command & Code Execution Sinks (command_code_execution_sinks.protocol)
* Database & Query Sinks (database_query_sinks.protocol)
* Data Rendering & Output Sinks (data_rendering_output_sinks.protocol)
* File System & Stream Sinks (file_system_stream_sinks.protocol)
* Integrity & Validation Bypass Sinks (integrity_validation_bypass_sinks.protocol)
##### Dependency Vulnerability Contextualization
* Function-Level Reachability Analysis (function_reachability.protocol)
* Transitive Dependency Risk Mapping (transitive_dependency_risk.protocol)
* Environmental & Runtime Vulnerability Match (environmental_runtime_match.protocol)
* Automated Exploit Maturity Check (exploit_maturity_check.protocol)
* Mitigation-Specific Patch Analysis (mitigation_patch_analysis.protocol)
##### Security Header & Config Validation
* HTTP Security Headers Audit (http_headers_audit.protocol)
* Session & Cookie Security Hardening (session_cookie_security.protocol)
* Environment-Specific Hardening (env_specific_hardening.protocol)
* Framework Security Features Enforcement (framework_security_enforcement.protocol)
* Server Metadata & Information Leakage (server_metadata_leak.protocol)


---

### Taint Analysis & Data Flow Tracking

%% Анализ путей прохождения данных от точек входа (Sources) до чувствительных функций исполнения (Sinks) с целью проверки корректности их фильтрации и преобразования. %%

##### Untrusted Source Identification
* HTTP Request Surface Mapping (http_request_surface_mapping.protocol)
* External API & Webhook Ingestion (external_api_webhook_ingestion.protocol)
* Message Queue & Event Stream Sourcing (message_queue_stream_sourcing.protocol)
* File & Upload Stream Analysis (file_upload_stream_analysis.protocol)
* Persistence-to-Memory Tainting (persistence_to_memory_tainting.protocol)
##### Propagation Path Tracing
* Direct Assignment & Variable Aliasing (direct_assignment_aliasing.protocol)
* String Manipulation & Transformation (string_manipulation_transformation.protocol)
* Inter-Procedural Data Flow (inter_procedural_data_flow.protocol)
* Asynchronous & Callback Propagation (asynchronous_callback_propagation.protocol)
* Object & Property Tainting (object_property_tainting.protocol)
##### Sanitization & Validation Verification
* Schema-Based Validation Audit (schema_based_validation_audit.protocol)
* Context-Specific Sanitizer Matching (context_specific_sanitizer_matching.protocol)
* Custom Validation Logic Analysis (custom_validation_logic_analysis.protocol)
* Canonicalization & Encoding Integrity (canonicalization_encoding_integrity.protocol)
* Validation Bypass & Conditional Logic (validation_bypass_conditional_logic.protocol)
##### Sink-to-Source Correlation (The Exploit Path)
* Full Path Verification (full_path_verification.protocol)
* Reachability & Execution Context Analysis (reachability_execution_context.protocol)
* Exploit Payload Feasibility (exploit_payload_feasibility.protocol)
* Impact Surface Mapping (impact_surface_mapping.protocol)
* Evidence Generation (evidence_generation.protocol)
##### Contextual Escape Analysis
* Output Context Identification (output_context_identification.protocol)
* Multi-Stage Encoding Validation (multi_stage_encoding_validation.protocol)
* Encoding Bypass & Double-Decoding Probe (encoding_bypass_double_decoding.protocol)
* Template Engine Auto-Escaping Audit (template_engine_auto_escaping.protocol)
* Behavioral Inconsistency Detection (parser_mismatch_detection.protocol)


---

### Manual Logic Review

%% Исследование программной логики на предмет архитектурных и функциональных дефектов, которые невозможно выявить автоматическими средствами, включая обход этапов бизнес-процессов и нарушения модели разграничения доступа. %%

##### AuthN/AuthZ Logic Audit
* Insecure Direct Object Reference (IDOR) Detection (idor_detection.protocol)
* Administrative Interface & Endpoint Exposure (admin_endpoint_exposure.protocol)
* Authentication Mechanism Hardening (auth_mechanism_hardening.protocol)
* Broken Level Access Control (broken_access_control.protocol)
* Session Management & Termination Logic (session_management_termination.protocol)
* Default/Guest Account & Backdoor Check (backdoor_check.protocol)
##### Workflow & State Machine Integrity
* Step Skipping & Out-of-Order Execution (step_skipping_logic.protocol)
* Unauthorized State Transitions (unauthorized_state_transitions.protocol)
* Parameter Pollution in Multi-Step Flows (parameter_pollution_multistep.protocol)
* Post-Action Replay & Lifecycle Re-entry (post_action_replay.protocol)
* Forced Browsing & Hidden Flow Discovery (forced_browsing_hidden_flow.protocol)
##### Financial & Numeric Logic Probe
* Negative & Zero Value Injection (negative_zero_injection.protocol)
* Precision & Rounding Attacks (precision_rounding_attacks.protocol)
* Integer Overflow & Underflow (integer_overflow_underflow.protocol)
* Currency & Unit Mismatch (currency_unit_mismatch.protocol)
* Inventory & Resource Exhaustion (inventory_resource_exhaustion.protocol)
##### Incentive System & Rate Limit Abuse  
* Referral & Sign-up Bonus Farming (referral_bonus_farming.protocol)
* Coupon & Promo Code Brute-forcing (coupon_brute_forcing.protocol)
* Rate Limit Bypass via Header Manipulation (rate_limit_bypass_headers.protocol)
* Competitive Resource Exhaustion (competitive_resource_exhaustion.protocol)
* Cumulative Discount & Stackable Offers Logic (cumulative_discount_stacking.protocol)
##### Race Condition & Concurrency Analysis
* TOCTOU (Time-of-Check to Time-of-Use) Analysis (toctou_analysis.protocol)
* Atomic Operation & Transaction Integrity (atomic_transaction_integrity.protocol)
* Distributed Lock & Race Condition in Microservices (distributed_lock_race.protocol)
* Singleton & Global State Thread Safety (singleton_global_state.protocol)
* Async Event Loop Blocking & Race (async_loop_race.protocol)


---

### Infrastructure-as-Code (IaC) Audit

%% Аудит конфигурационных файлов инфраструктуры (Docker, Kubernetes, Terraform) для обеспечения соответствия принципам защищенного развертывания и минимизации привилегий окружения. %%

##### Container Image & Dockerfile Hardening
* Least Privilege User Enforcement (least_privilege_user.protocol)
* Base Image Provenance & Vulnerability Scanning (base_image_provenance.protocol)
* Attack Surface Reduction (attack_surface_reduction.protocol)
* Multi-Stage Build Optimization (multi_stage_optimization.protocol)
* Sensitive Data & Secret Leakage in Layers (sensitive_data_leakage.protocol)
* Filesystem & Execution Security (filesystem_execution_security.protocol)
##### Orchestration & Kubernetes Manifest Security
* Pod Security Context & Privilege Escalation (pod_security_context.protocol)
* Network Policy & Microsegmentation (network_policy_segmentation.protocol)
* RBAC (Role-Based Access Control) Principle of Least Privilege (rbac_least_privilege.protocol)
* Resource Quotas & Limits (resource_quotas_limits.protocol)
* Secrets & ConfigMap Management (secrets_configmap_management.protocol)
* Admission Control & Image Provenance (admission_control_provenance.protocol)
##### Cloud Infrastructure & Terraform Audit
* Public Exposure & Network Perimeter Control (public_exposure_perimeter.protocol)
* IAM Least Privilege & Resource Access (iam_least_privilege.protocol)
* Encryption at Rest & In-Transit (encryption_rest_transit.protocol)
* Audit Logging & Monitoring Configuration (audit_logging_monitoring.protocol)
* Terraform State & Backend Security (terraform_state_security.protocol)
* Orphaned & Shadow Resources Detection (orphaned_shadow_resources.protocol)
##### Secret Management & Vault Integration
* Secret Injection Method Audit (secret_injection_audit.protocol)
* Vault Access Policy (vault_access_policy.protocol)
* Dynamic Secrets Implementation (dynamic_secrets_implementation.protocol)
* Authentication Method Security (auth_method_security.protocol)
* Secret Sprawl & Plaintext Detection (secret_sprawl_detection.protocol)
* Transit Encryption & Data Unsealing (transit_unsealing.protocol)
##### CI/CD Pipeline Security (Supply Chain)
* Pipeline Definition & Workflow Integrity (pipeline_definition_integrity.protocol)
* Secret & Token Management in CI (ci_secret_token_management.protocol)
* Third-Party Action & Plugin Pinning (third_party_pinning.protocol)
* Build Environment Isolation (build_environment_isolation.protocol)
* Software Bill of Materials (SBOM) & Artifact Integrity (sbom_artifact_integrity.protocol)
* Post-Build Security Testing Gate (post_build_testing_gate.protocol)


---

# Validation & Finalization
##### Vulnerability Validation & Exploitability Audit
* Анализ достижимости и путей атаки (contextual_reachability.protocol)
* Доказательная верификация (poc_development.protocol)
* Итоговая оценка риска (refined_severity.protocol)
##### Consolidated Reporting & Executive Synthesis
* Агрегация и приоритизация (finding_aggregation.protocol)
* Стратегия устранения (remediation_roadmap.protocol)
* Финальный синтез (executive_synthesis.protocol)