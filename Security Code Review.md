
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

