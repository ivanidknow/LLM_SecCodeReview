'use client';
// @ts-nocheck
import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  ConfigProvider, theme, Layout, Card, Checkbox, Button, Input,
  Typography, Tag, Flex, Select, Modal, Popover
} from 'antd';
import {
  FolderOpenOutlined, ThunderboltOutlined, CodeOutlined,
  SearchOutlined, RocketOutlined, ExperimentOutlined,
  SendOutlined, WarningOutlined, ApiOutlined,
  SettingOutlined
} from '@ant-design/icons';
import axios from 'axios';

const { Text } = Typography;
const { Header, Content } = Layout;

/* ============================================================
   METHODOLOGY
   ============================================================ */
interface Module { id: string; label: string; mandatory?: boolean; }
interface Section { id: string; label: string; mandatory?: boolean; modules: Module[]; }

const METHODOLOGY: Section[] = [
  { id: 'discovery', label: 'Discovery', modules: [
    { id: 'architecture', label: 'Architecture', mandatory: true },
    { id: 'business_processes', label: 'Бизнес-процессы' },
    { id: 'license_compliance', label: 'License Compliance' },
  ]},
  { id: 'modeling', label: 'Modeling', modules: [
    { id: 'dfd', label: 'DFD' },
    { id: 'threat_modeling', label: 'Threat Modeling' },
  ]},
  { id: 'deep_scan', label: 'Deep Scan', modules: [
    { id: 'static_analysis', label: 'Discovery-Driven SAST' },
    { id: 'taint_analysis', label: 'Taint Analysis & Data Flow' },
    { id: 'manual_logic_review', label: 'Manual Logic Review' },
    { id: 'iac_audit', label: 'IaC Audit (Docker/K8s/Terraform)' },
  ]},
  { id: 'validating_and_reporting', label: 'Validation & Finalization', mandatory: true, modules: [] },
];

const MANDATORY_IDS = new Set<string>();
METHODOLOGY.forEach(s => { if (s.mandatory) MANDATORY_IDS.add(s.id); s.modules.forEach(m => { if (m.mandatory) MANDATORY_IDS.add(m.id); }); });
const ALL_IDS = METHODOLOGY.flatMap(s => [s.id, ...s.modules.map(m => m.id)]);

const API_SYNC     = 'http://localhost:8000/api/projects/sync-cursor';
const API_CHAT     = 'http://localhost:8000/api/analysis/chat';
const API_STATUS   = 'http://localhost:8000/api/analysis/status';
const API_MODELS   = 'http://localhost:8000/api/analysis/models';
const API_OPTIMIZE = 'http://localhost:8000/api/analysis/optimize';
const API_REPORT  = 'http://localhost:8000/api/analysis/report';

/* ---- Metadata options ---- */
const PROJECT_TYPES = [
  { value: '', label: 'Auto-detect' },
  { value: 'web', label: 'Web Application' },
  { value: 'api', label: 'API / Backend' },
  { value: 'cli', label: 'CLI Tool' },
  { value: 'mobile', label: 'Mobile App' },
  { value: 'microservice', label: 'Microservice' },
  { value: 'library', label: 'Library / SDK' },
];
const TECH_STACKS = [
  { value: '', label: 'Auto-detect' },
  { value: 'python', label: 'Python' },
  { value: 'node', label: 'Node.js / TypeScript' },
  { value: 'react', label: 'React / Next.js' },
  { value: 'go', label: 'Go' },
  { value: 'java', label: 'Java / Spring' },
  { value: 'dotnet', label: '.NET / C#' },
  { value: 'rust', label: 'Rust' },
  { value: 'ruby', label: 'Ruby / Rails' },
];
const RISK_LEVELS = [
  { value: 'low', label: '🟢 Low' },
  { value: 'medium', label: '🟡 Medium' },
  { value: 'high', label: '🔴 High' },
];

/* ---- Commands ---- */
const COMMANDS = [
  { cmd: '/scan discovery', desc: 'Run Discovery phase' },
  { cmd: '/scan full',      desc: 'Full Scan (all modules)' },
  { cmd: '/sync',           desc: 'Sync to .cursorrules' },
  { cmd: '/optimize',       desc: 'Apply AI optimization' },
  { cmd: '/report',         desc: 'Show Gold Standard report' },
  { cmd: '/status',         desc: 'Show context + status' },
  { cmd: '/clear',          desc: 'Clear terminal' },
  { cmd: '/help',           desc: 'List commands' },
];

/* ============================================================
   APP
   ============================================================ */
export default function SecurityOrchestrator() {
  return (
    <ConfigProvider theme={{ algorithm: theme.darkAlgorithm, token: { colorBgContainer: '#0a0a0a', colorBgElevated: '#111', colorBgLayout: '#000', colorBorder: '#1f1f1f', colorPrimary: '#3b82f6', borderRadius: 8 } }}>
      <Dashboard />
    </ConfigProvider>
  );
}

/* ---- Optimization Warning ---- */
interface OptWarn { show: boolean; message: string; technologies: string[]; archType: string; recommended: { id: string; reason: string }[]; redundant: { id: string; reason: string }[]; fullScanWarning?: string; }
const EMPTY_OPT: OptWarn = { show: false, message: '', technologies: [], archType: '', recommended: [], redundant: [] };

function Dashboard() {
  /* ---- State ---- */
  const [projectPath, setProjectPath] = useState('');
  const [selected, setSelected] = useState<string[]>(() => [...MANDATORY_IDS]);
  const [isSyncing, setIsSyncing] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [discoveryDone, setDiscoveryDone] = useState(false);

  /* Metadata */
  const [projectType, setProjectType] = useState('');
  const [techStack, setTechStack] = useState('');
  const [riskLevel, setRiskLevel] = useState('medium');

  /* Terminal */
  const [logs, setLogs] = useState<string[]>(['[SYSTEM] Hexstrike Sentinel v3.0', '[INFO] Type /help for commands.']);
  const logEnd = useRef<HTMLDivElement>(null);
  useEffect(() => { logEnd.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs]);

  /* CLI */
  const [cmdInput, setCmdInput] = useState('');
  const [showAC, setShowAC] = useState(false);
  const [acIdx, setAcIdx] = useState(0);
  const inputRef = useRef<any>(null);

  /* LLM */
  const [isStreaming, setIsStreaming] = useState(false);
  const [ollamaStatus, setOllamaStatus] = useState<'online' | 'offline' | 'unknown'>('unknown');
  const [models, setModels] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState('llama3');

  /* Optimization */
  const [optWarn, setOptWarn] = useState<OptWarn>(EMPTY_OPT);
  const [isOptimizing, setIsOptimizing] = useState(false);
  const [pendingOpt, setPendingOpt] = useState<any>(null);

  /* Init */
  useEffect(() => {
    axios.get(API_STATUS).then(r => { setOllamaStatus(r.data.ollama); setLogs(p => [...p, `[INFO] Ollama: ${r.data.ollama}`]); }).catch(() => setOllamaStatus('offline'));
    axios.get(API_MODELS).then(r => { const l = r.data.models || []; setModels(l); if (l.length) { const pref = l.find((m: string) => m.startsWith('llama3')) || l[0]; setSelectedModel(pref); } }).catch(() => {});
  }, []);

  /* ---- Build project_context for API ---- */
  const buildContext = () => {
    const ctx: any = {};
    if (projectType) ctx.project_type = projectType;
    if (techStack) ctx.tech_stack = techStack;
    ctx.risk_level = riskLevel;
    return ctx;
  };

  /* ============================================================
     COMMANDS
     ============================================================ */
  const filteredCmds = cmdInput.startsWith('/') ? COMMANDS.filter(c => c.cmd.startsWith(cmdInput.toLowerCase())) : [];

  const executeCommand = async (raw: string) => {
    const input = raw.trim();
    if (!input) return;
    setCmdInput('');
    setShowAC(false);

    if (input.startsWith('/')) {
      const parts = input.toLowerCase().split(/\s+/);
      setLogs(p => [...p, `[CMD] > ${input}`]);
      switch (parts[0]) {
        case '/scan':
          if (parts[1] === 'discovery') return runDiscovery();
          if (parts[1] === 'full') return runFullScan();
          return setLogs(p => [...p, '[ERROR] Usage: /scan discovery | /scan full']);
        case '/sync': return runSync();
        case '/optimize': return applyPendingOpt();
        case '/report': return fetchReport();
        case '/status':
          return setLogs(p => [...p,
            `[CTX] Project: ${projectPath || '(not set)'}`,
            `[CTX] Type: ${projectType || 'auto'}  Stack: ${techStack || 'auto'}  Risk: ${riskLevel}`,
            `[CTX] Selected: ${selected.length} modules  Discovery: ${discoveryDone ? 'DONE' : 'NOT RUN'}`,
            `[CTX] Ollama: ${ollamaStatus} (${selectedModel})`,
          ]);
        case '/clear': return setLogs(['[SYSTEM] Cleared.']);
        case '/help':
          return setLogs(p => [...p, '[HELP] ─── Commands ───', ...COMMANDS.map(c => `[HELP]   ${c.cmd.padEnd(20)} ${c.desc}`), '[HELP] ─── Or type a question for the Sentinel ───']);
        default: return setLogs(p => [...p, `[ERROR] Unknown: ${parts[0]}. Type /help`]);
      }
    }
    await chatWithSentinel(input);
  };

  /* ---- Fetch Report ---- */
  const fetchReport = async () => {
    setLogs(p => [...p, '[CMD] Fetching Gold Standard report...']);
    try {
      const res = await axios.get(API_REPORT);
      const lines: string[] = res.data.lines || [];
      if (!lines.length) {
        setLogs(p => [...p, '[WARN] No report available. Run: python generate_test_report.py --api-push']);
        return;
      }
      setLogs(p => [...p, ...lines.map((l: string) => {
        if (l.startsWith('[ALERT]')) return `[SENTINEL REPORT] 🚨 ${l.slice(8)}`;
        if (l.startsWith('[SECTION]')) return `[SENTINEL REPORT] ═══ ${l.slice(10)} ═══`;
        if (l.startsWith('[SUBSEC]')) return `[SENTINEL REPORT] ── ${l.slice(9)} ──`;
        if (l.startsWith('[FIX]')) return `[SENTINEL REPORT] 🔧 ${l.slice(6)}`;
        if (l.startsWith('[EVIDENCE]')) return `[SENTINEL REPORT] 📋 Evidence:`;
        if (l.startsWith('[SENTINEL')) return l;
        return `[SENTINEL REPORT] ${l}`;
      })]);
    } catch (e: any) {
      setLogs(p => [...p, `[FAIL] ${e.message}`]);
    }
  };

  /* ---- Folder ---- */
  const pickFolder = async () => {
    try {
      const h = await (window as any).showDirectoryPicker();
      // Resolve full path via the handle
      const entries: string[] = [];
      for await (const [name] of h.entries()) { entries.push(name); break; }
      // showDirectoryPicker only gives the folder name, not the absolute path.
      // User must verify or type the full absolute path.
      setProjectPath(h.name);
      setLogs(p => [...p, `[INFO] Folder selected: ${h.name}`, '[INFO] If sync fails, type the full absolute path (e.g., C:\\\\Users\\\\...\\\\project).']);
    } catch {
      const inp = document.createElement('input');
      inp.type = 'file'; (inp as any).webkitdirectory = true;
      inp.onchange = () => {
        const f = inp.files?.[0];
        if (f) {
          const rel = (f as any).webkitRelativePath || '';
          // Try to extract folder name from the relative path
          const folder = rel.split('/')[0] || f.name;
          setProjectPath(folder);
          setLogs(p => [...p, `[INFO] Folder: ${folder}`, '[INFO] If sync fails, type the full absolute path.']);
        }
      };
      inp.click();
    }
  };

  const verifyPath = async (path: string): Promise<boolean> => {
    try {
      // Quick sync dry-run: send minimal request to check if path is valid
      await axios.post(API_SYNC, { project_path: path, selected_ids: ['architecture'] });
      return true;
    } catch (e: any) {
      const detail = e.response?.data?.detail || e.message;
      if (detail.includes('Directory not found')) {
        setLogs(p => [...p, `[FAIL] Path not reachable: ${detail}`, '[INFO] Please type the full absolute path to your project.']);
        return false;
      }
      // Other errors (e.g., missing protocols) mean path is valid
      return true;
    }
  };

  /* ---- Selection ---- */
  const toggleModule = (id: string) => { if (!MANDATORY_IDS.has(id)) setSelected(p => p.includes(id) ? p.filter(i => i !== id) : [...p, id]); };
  const toggleSection = (sec: Section) => {
    if (sec.mandatory) return;
    const ids = sec.modules.filter(m => !m.mandatory).map(m => m.id);
    if (!ids.length) return;
    setSelected(p => ids.every(id => p.includes(id)) ? p.filter(id => !ids.includes(id)) : [...new Set([...p, ...ids])]);
  };
  const sectionState = (sec: Section) => {
    if (sec.mandatory) return { checked: true, indeterminate: false };
    if (!sec.modules.length) return { checked: false, indeterminate: false };
    const ids = sec.modules.map(m => m.id);
    const n = ids.filter(id => selected.includes(id)).length;
    return { checked: n === ids.length, indeterminate: n > 0 && n < ids.length };
  };
  const buildSelectedIds = (sids: string[]): string[] => {
    const ids: string[] = [];
    for (const sec of METHODOLOGY) {
      if (sids.includes(sec.id)) { if (!sec.modules.length || sec.modules.every(m => sids.includes(m.id) || m.mandatory)) ids.push(sec.id); else sec.modules.forEach(m => { if (sids.includes(m.id)) ids.push(m.id); }); }
      else sec.modules.forEach(m => { if (sids.includes(m.id)) ids.push(m.id); });
    }
    return [...new Set(ids)];
  };

  /* ---- Sync ---- */
  const syncToBackend = async (ids: string[], label: string) => {
    if (!projectPath) { setLogs(p => [...p, '[ERROR] Set a project path first.']); return; }

    // Verify path is reachable before full sync
    setLogs(p => [...p, `[INFO] Verifying path: ${projectPath}`]);
    const valid = await verifyPath(projectPath);
    if (!valid) { return; }

    setIsSyncing(true);
    const payload = buildSelectedIds(ids);
    setLogs(p => [...p, `[SYNC] ${label} → ${projectPath} (${payload.length} IDs)`]);
    try {
      const res = await axios.post(API_SYNC, { project_path: projectPath, selected_ids: payload, project_context: buildContext() });
      const { synced_count, synced_ids, target, categories_expanded, warnings } = res.data;
      setLogs(p => [...p, `[OK] Synced ${synced_count} → ${target}`]);
      if (categories_expanded?.length) setLogs(p => [...p, `[INFO] Expanded: ${categories_expanded.join(', ')}`]);
      if (warnings?.length) for (const w of warnings) setLogs(p => [...p, `[WARN] ${w}`]);
    } catch (e: any) { setLogs(p => [...p, `[FAIL] ${e.response?.data?.detail || e.message}`]); }
    finally { setIsSyncing(false); }
  };

  const runSync = () => syncToBackend(selected, 'Sync Cursor');

  /* ---- Full Scan (with smart check) ---- */
  const runFullScan = () => {
    if (!discoveryDone) {
      setLogs(p => [...p, '[WARN] ⚡ Recommendation: Run Discovery first for a more precise Full Scan.', '[INFO] Proceeding with Full Scan...']);
    }
    const allIds = [...new Set(ALL_IDS)];
    setSelected(allIds);
    setLogs(p => [...p, '[CMD] Executing FULL SCAN...']);
    syncToBackend(allIds, 'FULL SCAN').then(() => {
      if (ollamaStatus === 'online') triggerOptimization(true);
    });
  };

  /* ---- Discovery ---- */
  const runDiscovery = async () => {
    if (!projectPath) { setLogs(p => [...p, '[ERROR] Set a project path first.']); return; }
    setIsSyncing(true);
    setLogs(p => [...p, '[CMD] Executing DISCOVERY scan...']);
    try {
      const res = await axios.post(API_SYNC, { project_path: projectPath, selected_ids: ['discovery', 'validating_and_reporting'], project_context: buildContext() });
      const { synced_count, target } = res.data;
      setDiscoveryDone(true);
      setLogs(p => [...p, `[OK] Discovery: ${synced_count} protocols → ${target}`, '[INFO] Discovery COMPLETE.']);
      if (ollamaStatus === 'online') await triggerOptimization(false);
    } catch (e: any) { setLogs(p => [...p, `[FAIL] ${e.response?.data?.detail || e.message}`]); }
    finally { setIsSyncing(false); }
  };

  /* ---- Optimization ---- */
  const triggerOptimization = async (isFullScan: boolean) => {
    if (isOptimizing) return;
    setIsOptimizing(true);
    setLogs(p => [...p, '[OPTIMIZE] Analyzing with AI...']);
    try {
      const res = await axios.post(API_OPTIMIZE, { discovery_log: logs.join('\n'), current_selected_ids: selected, model: selectedModel, is_full_scan: isFullScan });
      const d = res.data;
      setLogs(p => [...p, `[OPTIMIZE] Tech: ${d.detected_technologies?.join(', ') || 'none'}`, `[OPTIMIZE] Arch: ${d.architecture_type}`]);

      // Auto-update metadata from AI if not manually set
      if (d.architecture_type && d.architecture_type !== 'unknown' && !projectType) {
        const typeMap: Record<string, string> = { monolith: 'web', microservices: 'microservice', serverless: 'api', hybrid: 'api' };
        const mapped = typeMap[d.architecture_type] || '';
        if (mapped) { setProjectType(mapped); setLogs(p => [...p, `[CTX] Auto-set Project Type: ${mapped}`]); }
      }
      if (d.detected_technologies?.length && !techStack) {
        const techMap: Record<string, string> = { python: 'python', django: 'python', fastapi: 'python', flask: 'python', node: 'node', express: 'node', react: 'react', nextjs: 'react', go: 'go', golang: 'go', java: 'java', spring: 'java', rust: 'rust' };
        for (const t of d.detected_technologies) {
          const key = t.toLowerCase();
          if (techMap[key]) { setTechStack(techMap[key]); setLogs(p => [...p, `[CTX] Auto-set Stack: ${techMap[key]}`]); break; }
        }
      }

      if (!d.is_optimized) {
        const reasoning = d.reasoning || {};
        const missing = (d.recommended_ids || []).filter((i: string) => !selected.includes(i));
        const unnecessary = (d.redundant_ids || []).filter((i: string) => selected.includes(i));
        setPendingOpt({ recommended: missing, redundant: unnecessary, reasoning });

        if (isFullScan && d.full_scan_warning) {
          setLogs(p => [...p, `[WARN] ${d.full_scan_warning}`, '[INFO] Type /optimize to apply.']);
        } else {
          setLogs(p => [...p, '[OPTIMIZE] Plan not optimal.',
            ...(missing.length ? [`[OPTIMIZE] ➕ Add: ${missing.join(', ')}`] : []),
            ...(unnecessary.length ? [`[OPTIMIZE] ➖ Remove: ${unnecessary.join(', ')}`] : []),
            '[INFO] Type /optimize to apply, or ignore.']);
        }
        setOptWarn({
          show: true, message: d.full_scan_warning || 'Discovery finished. Scan plan is not optimal.',
          technologies: d.detected_technologies || [], archType: d.architecture_type || 'unknown',
          recommended: missing.map((i: string) => ({ id: i, reason: reasoning[i] || '' })),
          redundant: unnecessary.map((i: string) => ({ id: i, reason: reasoning[i] || '' })),
          fullScanWarning: d.full_scan_warning,
        });
      } else {
        setLogs(p => [...p, '[OPTIMIZE] ✓ Selection is optimal.']);
      }
    } catch (e: any) { setLogs(p => [...p, `[WARN] Optimization unavailable: ${e.response?.data?.detail || e.message}`]); }
    finally { setIsOptimizing(false); }
  };

  const applyPendingOpt = () => {
    if (!pendingOpt) { setLogs(p => [...p, '[INFO] No pending optimization.']); return; }
    const toAdd: string[] = pendingOpt.recommended || [];
    const toRm = new Set<string>(pendingOpt.redundant || []);
    setSelected(prev => [...new Set([...prev.filter(id => !toRm.has(id)), ...toAdd])]);
    setLogs(p => [...p, `[OPTIMIZE] Applied: +${toAdd.length} -${toRm.size}`]);
    setPendingOpt(null);
    setOptWarn(EMPTY_OPT);
  };

  /* ---- Chat ---- */
  const chatWithSentinel = async (query: string) => {
    if (!projectPath) { setLogs(p => [...p, '[ERROR] Set project path and sync first.']); return; }
    setIsStreaming(true);
    setLogs(p => [...p, `[YOU] ${query}`, '[SENTINEL] ...']);
    try {
      const r = await fetch(API_CHAT, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ project_path: projectPath, user_query: query, model: selectedModel }) });
      if (!r.ok) { const e = await r.json().catch(() => ({ detail: r.statusText })); setLogs(p => { const c = [...p]; c[c.length - 1] = `[FAIL] ${e.detail}`; return c; }); setIsStreaming(false); return; }
      const reader = r.body?.getReader(); const dec = new TextDecoder(); let acc = '';
      if (reader) { while (true) { const { done, value } = await reader.read(); if (done) break; acc += dec.decode(value, { stream: true }); setLogs(p => { const c = [...p]; c[c.length - 1] = `[SENTINEL] ${acc}`; return c; }); } }
      if (!acc) setLogs(p => { const c = [...p]; c[c.length - 1] = '[SENTINEL] (no response)'; return c; });
    } catch (e: any) { setLogs(p => { const c = [...p]; c[c.length - 1] = `[FAIL] ${e.message}`; return c; }); }
    finally { setIsStreaming(false); }
  };

  /* ---- Keyboard ---- */
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (showAC && filteredCmds.length > 0) {
      if (e.key === 'ArrowDown') { e.preventDefault(); setAcIdx(i => Math.min(i + 1, filteredCmds.length - 1)); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); setAcIdx(i => Math.max(i - 1, 0)); return; }
      if (e.key === 'Tab') { e.preventDefault(); setCmdInput(filteredCmds[acIdx].cmd + ' '); setShowAC(false); return; }
    }
    if (e.key === 'Enter') { e.preventDefault(); executeCommand(cmdInput); }
  };
  useEffect(() => { if (cmdInput.startsWith('/') && cmdInput.length > 0) { setShowAC(true); setAcIdx(0); } else setShowAC(false); }, [cmdInput]);

  /* ---- Colors ---- */
  const logColor = (l: string) => {
    if (l.startsWith('[ERROR]') || l.startsWith('[FAIL]')) return '#f87171';
    if (l.startsWith('[OK]')) return '#4ade80';
    if (l.startsWith('[SYNC]') || l.startsWith('[SCAN]')) return '#60a5fa';
    if (l.startsWith('[WARN]')) return '#fb923c';
    if (l.startsWith('[OPTIMIZE]')) return '#c084fc';
    if (l.startsWith('[SYSTEM]')) return '#a78bfa';
    if (l.startsWith('[SENTINEL REPORT]')) return '#fbbf24';
    if (l.startsWith('[SENTINEL]')) return '#4af626';
    if (l.startsWith('[YOU]')) return '#e879f9';
    if (l.startsWith('[CMD]')) return '#38bdf8';
    if (l.startsWith('[CTX]')) return '#2dd4bf';
    if (l.startsWith('[HELP]')) return '#94a3b8';
    return '#22d3ee';
  };

  /* ---- Metadata Popover content ---- */
  const MetadataPanel = (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, width: 260, fontFamily: 'monospace' }}>
      <Text style={{ fontSize: 10, color: '#666', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Project Specs</Text>
      <div>
        <Text style={{ fontSize: 11, color: '#888', display: 'block', marginBottom: 4 }}>Type</Text>
        <Select value={projectType} onChange={setProjectType} options={PROJECT_TYPES} style={{ width: '100%' }} size="small" popupMatchSelectWidth styles={{ popup: { root: { background: '#111' } } }} />
      </div>
      <div>
        <Text style={{ fontSize: 11, color: '#888', display: 'block', marginBottom: 4 }}>Stack</Text>
        <Select value={techStack} onChange={setTechStack} options={TECH_STACKS} style={{ width: '100%' }} size="small" popupMatchSelectWidth styles={{ popup: { root: { background: '#111' } } }} />
      </div>
      <div>
        <Text style={{ fontSize: 11, color: '#888', display: 'block', marginBottom: 4 }}>Risk Level</Text>
        <Select value={riskLevel} onChange={setRiskLevel} options={RISK_LEVELS} style={{ width: '100%' }} size="small" popupMatchSelectWidth styles={{ popup: { root: { background: '#111' } } }} />
      </div>
    </div>
  );

  return (
    <Layout style={{ height: '100vh', overflow: 'hidden', background: '#000' }} suppressHydrationWarning>

      {/* ===== OPT MODAL ===== */}
      <Modal open={optWarn.show}
        title={<Flex align="center" gap={8}><WarningOutlined style={{ color: '#fbbf24', fontSize: 18 }} /><span style={{ color: '#fbbf24' }}>Scan Optimization</span></Flex>}
        onOk={applyPendingOpt} onCancel={() => setOptWarn(EMPTY_OPT)} okText="Apply" cancelText="Ignore"
        okButtonProps={{ style: { background: '#3b82f6', fontWeight: 700 } }}
        styles={{ body: { background: '#0a0a0a' }, header: { background: '#0a0a0a' }, footer: { background: '#0a0a0a' }, content: { background: '#0a0a0a', border: '1px solid #1f1f1f' } }}
      >
        <div style={{ fontFamily: 'monospace', fontSize: 13, lineHeight: 1.8 }}>
          <p style={{ color: '#fbbf24' }}>{optWarn.message}</p>
          {optWarn.technologies.length > 0 && <div style={{ margin: '8px 0' }}>{optWarn.technologies.map(t => <Tag key={t} color="blue" style={{ fontSize: 11, margin: '2px 4px 2px 0' }}>{t}</Tag>)}</div>}
          <Tag color="purple" style={{ fontSize: 11 }}>{optWarn.archType}</Tag>
          {optWarn.recommended.length > 0 && <div style={{ marginTop: 10 }}><Text style={{ color: '#4ade80', fontSize: 11 }}>➕ ADD:</Text>{optWarn.recommended.map(r => <div key={r.id} style={{ color: '#4ade80', paddingLeft: 16, fontSize: 12 }}><code>{r.id}</code> {r.reason && <span style={{ color: '#666' }}>— {r.reason}</span>}</div>)}</div>}
          {optWarn.redundant.length > 0 && <div style={{ marginTop: 10 }}><Text style={{ color: '#f87171', fontSize: 11 }}>➖ REMOVE:</Text>{optWarn.redundant.map(r => <div key={r.id} style={{ color: '#f87171', paddingLeft: 16, fontSize: 12 }}><code>{r.id}</code> {r.reason && <span style={{ color: '#666' }}>— {r.reason}</span>}</div>)}</div>}
          {optWarn.fullScanWarning && <div style={{ marginTop: 12, padding: 8, background: '#1a1200', border: '1px solid #fbbf2440', borderRadius: 6 }}><Text style={{ color: '#fbbf24', fontSize: 12 }}>⚠ {optWarn.fullScanWarning}</Text></div>}
        </div>
      </Modal>

      {/* ===== HEADER ===== */}
      <Header style={{ height: 60, lineHeight: '60px', background: '#080808', borderBottom: '1px solid #1f1f1f', padding: '0 20px', display: 'flex', alignItems: 'center', gap: 8 }}>
        <Button type="text" icon={<FolderOpenOutlined />} onClick={pickFolder} style={{ color: '#888' }} />
        <Input value={projectPath} onChange={e => setProjectPath(e.target.value)} placeholder="Path to repository..." variant="borderless" prefix={<SearchOutlined style={{ color: '#444' }} />} style={{ flex: 1, fontFamily: 'monospace', fontSize: 14 }} />

        {/* Context tags */}
        {projectType && <Tag color="cyan" style={{ margin: 0, fontSize: 9 }}>{projectType}</Tag>}
        {techStack && <Tag color="geekblue" style={{ margin: 0, fontSize: 9 }}>{techStack}</Tag>}
        <Tag color={riskLevel === 'high' ? 'red' : riskLevel === 'low' ? 'green' : 'gold'} style={{ margin: 0, fontSize: 9 }}>{riskLevel}</Tag>
        <Tag color="blue" style={{ margin: 0, fontFamily: 'monospace', fontSize: 10, fontWeight: 700 }}>{selected.length}</Tag>
        <Tag color={ollamaStatus === 'online' ? 'green' : 'red'} style={{ margin: 0, fontSize: 9, fontWeight: 700 }}>LLM</Tag>
        {discoveryDone && <Tag color="purple" style={{ margin: 0, fontSize: 9 }}>DISCOVERED</Tag>}

        {/* Project Specs popover */}
        <Popover content={MetadataPanel} trigger="click" placement="bottomRight" styles={{ root: { background: '#0a0a0a', border: '1px solid #1f1f1f' } }}>
          <Button type="text" icon={<SettingOutlined />} style={{ color: '#666' }} />
        </Popover>

        <Button icon={<ExperimentOutlined />} onClick={runDiscovery} disabled={isSyncing || isOptimizing} style={{ fontWeight: 700, fontSize: 11 }}>DISCOVERY</Button>
        <Button icon={<RocketOutlined />} onClick={runFullScan} disabled={isSyncing || isOptimizing} danger style={{ fontWeight: 700, fontSize: 11 }}>FULL SCAN</Button>
        <Button type="primary" icon={<ThunderboltOutlined />} loading={isSyncing} onClick={runSync} style={{ fontWeight: 700, letterSpacing: '0.05em' }}>SYNC CURSOR</Button>
      </Header>

      {/* ===== CONTENT ===== */}
      <Content style={{ overflow: 'auto', padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 16 }}>
          {METHODOLOGY.map(sec => {
            const { checked, indeterminate } = sectionState(sec);
            const isOpen = expanded[sec.id] !== false;
            return (<div key={sec.id}><Card size="small" styles={{ header: { borderBottom: '1px solid #1a1a1a', padding: '12px 16px' }, body: { padding: (isOpen && sec.modules.length) ? '8px 12px' : 0 } }} style={{ background: '#0a0a0a', borderColor: '#1a1a1a' }}
              title={<Flex align="center" gap={10}>
                <Checkbox checked={checked || sec.mandatory} indeterminate={indeterminate} disabled={sec.mandatory} onChange={() => toggleSection(sec)} />
                <span onClick={() => sec.modules.length > 0 && setExpanded(p => ({ ...p, [sec.id]: !isOpen }))} style={{ cursor: sec.modules.length ? 'pointer' : 'default', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: sec.mandatory ? '#3b82f6' : '#999', flex: 1 }}>
                  {sec.label}{sec.mandatory && <Tag color="blue" style={{ marginLeft: 8, fontSize: 9 }}>REQ</Tag>}
                </span>
                {sec.modules.length > 0 && <Text type="secondary" style={{ fontSize: 10, fontFamily: 'monospace' }}>{sec.modules.length}</Text>}
              </Flex>}
            >
              {isOpen && sec.modules.map(mod => {
                const isOn = selected.includes(mod.id);
                return (<Flex key={mod.id} align="center" gap={8} onClick={() => toggleModule(mod.id)} style={{ padding: '8px 10px', borderRadius: 6, cursor: mod.mandatory ? 'default' : 'pointer', marginBottom: 2, background: isOn ? 'rgba(59,130,246,0.08)' : 'transparent' }}>
                  <Checkbox checked={isOn || mod.mandatory} disabled={mod.mandatory} style={{ pointerEvents: 'none' }} />
                  <Text style={{ fontSize: 13, fontFamily: 'monospace', color: isOn ? '#93c5fd' : '#888' }}>{mod.label}</Text>
                  {mod.mandatory && <Tag color="green" style={{ marginLeft: 'auto', fontSize: 9 }}>REQ</Tag>}
                </Flex>);
              })}
            </Card></div>);
          })}
        </div>

        {/* ===== TERMINAL ===== */}
        <div style={{ flex: 1, minHeight: 300, background: '#050505', border: '1px solid #1a1a1a', borderRadius: 8, overflow: 'hidden', display: 'flex', flexDirection: 'column', position: 'relative' }}>
          <Flex align="center" gap={8} style={{ padding: '8px 16px', borderBottom: '1px solid #1a1a1a', background: '#080808', flexShrink: 0 }}>
            <CodeOutlined style={{ color: '#555', fontSize: 12 }} />
            <Text style={{ fontSize: 10, fontFamily: 'monospace', color: '#555', textTransform: 'uppercase', letterSpacing: '0.1em', flex: 1 }}>Command Console</Text>
            {isStreaming && <Tag color="green" style={{ fontSize: 9, margin: 0 }}>STREAM</Tag>}
            {isOptimizing && <Tag color="purple" style={{ fontSize: 9, margin: 0 }}>AI</Tag>}
            <Select value={selectedModel} onChange={(v: string) => { setSelectedModel(v); setLogs(p => [...p, `[INFO] Model: ${v}`]); }} size="small" variant="borderless" disabled={isStreaming || !models.length} style={{ minWidth: 140, fontFamily: 'monospace', fontSize: 11 }} popupMatchSelectWidth={false} styles={{ popup: { root: { background: '#111', border: '1px solid #2a2a2a' } } }}
              options={models.length ? models.map(m => ({ value: m, label: m })) : [{ value: 'llama3', label: 'llama3' }]} />
          </Flex>
          <div style={{ padding: 16, fontFamily: 'monospace', fontSize: 13, lineHeight: 1.8, flex: 1, overflowY: 'auto' }}>
            {logs.map((l, i) => <div key={i} style={{ color: logColor(l), whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{l}</div>)}
            <div ref={logEnd} />
          </div>
          {/* Autocomplete */}
          {showAC && filteredCmds.length > 0 && (
            <div style={{ position: 'absolute', bottom: 48, left: 12, right: 12, background: '#111', border: '1px solid #2a2a2a', borderRadius: 6, padding: 4, zIndex: 10 }}>
              {filteredCmds.map((c, i) => (
                <div key={c.cmd} onClick={() => { setCmdInput(c.cmd + ' '); setShowAC(false); inputRef.current?.focus(); }}
                  style={{ padding: '5px 10px', cursor: 'pointer', borderRadius: 4, fontSize: 12, fontFamily: 'monospace', display: 'flex', gap: 12, background: i === acIdx ? 'rgba(59,130,246,0.15)' : 'transparent' }}>
                  <span style={{ color: '#60a5fa', minWidth: 130 }}>{c.cmd}</span><span style={{ color: '#666' }}>{c.desc}</span>
                </div>
              ))}
            </div>
          )}
          {/* Input */}
          <Flex align="center" gap={8} style={{ padding: '8px 12px', borderTop: '1px solid #1a1a1a', background: '#080808', flexShrink: 0 }}>
            <ApiOutlined style={{ color: '#38bdf8', fontSize: 14 }} />
            <Input ref={inputRef} value={cmdInput} onChange={e => setCmdInput(e.target.value)} onKeyDown={handleKeyDown}
              placeholder="Type / for commands, or ask the Sentinel..."
              disabled={isStreaming} variant="borderless"
              style={{ flex: 1, fontFamily: 'monospace', fontSize: 13, color: cmdInput.startsWith('/') ? '#38bdf8' : '#4af626' }} />
            <Button type="text" icon={<SendOutlined />} onClick={() => executeCommand(cmdInput)} disabled={isStreaming || !cmdInput.trim()} style={{ color: '#4af626' }} />
          </Flex>
        </div>
      </Content>
    </Layout>
  );
}