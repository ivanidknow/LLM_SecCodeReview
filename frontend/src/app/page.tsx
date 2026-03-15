'use client';
// @ts-nocheck
import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  ConfigProvider, theme, Layout, Card, Checkbox, Button, Input,
  Typography, Tag, Flex, Select, Modal, Popover
} from 'antd';
import { useRouter } from 'next/navigation';
import {
  FolderOpenOutlined, ThunderboltOutlined, CodeOutlined,
  SearchOutlined, RocketOutlined, ExperimentOutlined,
  SendOutlined, WarningOutlined, ApiOutlined,
  SettingOutlined, ReloadOutlined
} from '@ant-design/icons';
import axios from 'axios';

const { Text, Title } = Typography;
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
const API_OPTIMIZE  = 'http://localhost:8000/api/analysis/optimize';
const API_REPORT    = 'http://localhost:8000/api/analysis/report';
const API_DISCOVERY = 'http://localhost:8000/api/analysis/discovery';
const API_MODELING  = 'http://localhost:8000/api/analysis/modeling';
const API_DEEP_SCAN = 'http://localhost:8000/api/analysis/deep_scan';
const API_FINAL_REPORT = 'http://localhost:8000/api/analysis/final_report';
const API_SESSION   = 'http://localhost:8000/api/analysis/session';
const API_SESSION_LOAD = 'http://localhost:8000/api/analysis/session/load';

/* ---- Workflow Steps ---- */
type Phase = 'discovery' | 'modeling' | 'deep_scan' | 'report';
const WORKFLOW_ORDER: Phase[] = ['discovery', 'modeling', 'deep_scan', 'report'];
const WORKFLOW_LABELS: Record<string, string> = { discovery: 'Discovery', modeling: 'Modeling', deep_scan: 'Deep Scan', report: 'Final Report' };
const STEP_MODULES: Record<string, string[]> = {
  modeling: ['modeling', 'dfd', 'threat_modeling'],
  deep_scan: ['deep_scan', 'static_analysis', 'taint_analysis', 'manual_logic_review', 'iac_audit'],
  report: ['validating_and_reporting'],
};

const NEXT_STEP_MAP: Record<Phase, { label: string; next: Phase }> = {
  discovery: { label: "START MODELING", next: "modeling" },
  modeling: { label: "PROCEED TO DEEP SCAN", next: "deep_scan" },
  deep_scan: { label: "GENERATE FINAL REPORT", next: "report" },
  report: { label: "START NEW AUDIT", next: "discovery" }
};

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
  { cmd: '/proceed',        desc: 'Advance to next workflow step' },
  { cmd: '/report',         desc: 'Show Gold Standard report' },
  { cmd: '/status',         desc: 'Show context + status' },
  { cmd: '/clear',          desc: 'Clear terminal' },
  { cmd: '/rescan <file>',  desc: 'Focused Deep Scan on a single file' },
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
  const router = useRouter();

  /* ---- State ---- */
  const [projectPath, setProjectPath] = useState('');
  const [projectName, setProjectName] = useState('Security Sentinel');
  const [selected, setSelected] = useState<string[]>(() => [...MANDATORY_IDS]);
  const [isSyncing, setIsSyncing] = useState(false);
  const [loadedProtocolsCount, setLoadedProtocolsCount] = useState<number>(0);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [discoveryDone, setDiscoveryDone] = useState(false);

  /* Metadata */
  const [projectType, setProjectType] = useState('');
  const [techStack, setTechStack] = useState('');
  const [riskLevel, setRiskLevel] = useState('medium');

  /* Terminal */
  const [logs, setLogs] = useState<string[]>(['[SYSTEM] SecCodeReview Engine v3.5', '[INFO] Type /help for commands.']);
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

  /* Workflow */
  const [currentPhase, setCurrentPhase] = useState<Phase>('discovery');
  const [completedSteps, setCompletedSteps] = useState<Set<Phase>>(new Set());
  const [showProceedBtn, setShowProceedBtn] = useState(false);

  /* Init */
  useEffect(() => {
    const localProj = localStorage.getItem('activeProject');
    if (!localProj) {
      router.push('/projects');
      return;
    }
    let p: any;
    try {
      p = JSON.parse(localProj);
      setProjectPath(p.absolute_path || '');
      setProjectName(p.name || 'Security Sentinel');
    } catch(e) { return; }

    const storedStep_m = localStorage.getItem('activeStep');
    if (storedStep_m && WORKFLOW_ORDER.includes(storedStep_m as Phase)) {
        setCurrentPhase(storedStep_m as Phase);
    }

    if (p.absolute_path) {
      axios.get(`http://localhost:8000/api/history/projects/by-path?path=${encodeURIComponent(p.absolute_path)}`)
        .then(res => {
          const project = res.data.project;
          const stage = project.current_stage;
          if (stage && WORKFLOW_ORDER.includes(stage as Phase)) {
            setCurrentPhase(stage as Phase);
            localStorage.setItem('activeStep', stage);
            const c_idx = WORKFLOW_ORDER.indexOf(stage as Phase);
            if (c_idx > 0) {
              setDiscoveryDone(true);
              const newSet = new Set<Phase>();
              for(let i=0; i<=c_idx; i++) newSet.add(WORKFLOW_ORDER[i]);
              setCompletedSteps(newSet);
            }
          }
          return axios.get(`http://localhost:8000/api/history/projects/${project.id}/last-session`);
        })
        .then(res => {
          const sessionLogs = res.data.logs;
          if (sessionLogs && sessionLogs.length > 0) {
            const rawText = sessionLogs.map((l: any) => l.message).join('');
            const lines = rawText.split('\n');
            const strLogs: string[] = [];
            for (const line of lines) {
              if (!line.trim()) { strLogs.push(''); continue; }
              if (line.startsWith('[DEEP_SCAN]') || line.startsWith('[MODELING]') || line.startsWith('[DISCOVERY]') || line.startsWith('[REPORT]') || line.startsWith('---') || line.startsWith('[INFO]') || line.startsWith('[ERROR]') || line.startsWith('[FAIL]') || line.startsWith('[WARN]') || line.startsWith('[TIMEOUT]')) {
                strLogs.push(line);
              } else if (line.startsWith('[TRUST]') || line.startsWith('[DATAFLOW]')) {
                strLogs.push(`[AI] 🛡 ${line}`);
              } else if (line.startsWith('[THREAT]') || line.startsWith('[AUTH]') || line.startsWith('[AUTHZ]')) {
                strLogs.push(`[AI] ⚠ ${line}`);
              } else if (line.startsWith('[RECOMMEND]')) {
                strLogs.push(`[OPTIMIZE] ${line}`);
              } else if (line.startsWith('[SUMMARY]')) {
                strLogs.push(`[AI] ═══ ${line} ═══`);
              } else if (line.startsWith('[VULN]')) {
                strLogs.push(`[AI] 🚨 ${line}`);
              } else if (line.startsWith('[FIX]')) {
                strLogs.push(`[AI] 🔧 ${line}`);
              } else if (line.startsWith('[SYSTEM]') || line.startsWith('[SENTINEL REPORT]')) {
                strLogs.push(line);
              } else if (line.startsWith('#') || line.startsWith('*') || line.startsWith('```')) {
                strLogs.push(`[SENTINEL REPORT] ${line}`);
              } else {
                strLogs.push(`[AI] ${line}`);
              }
            }
            
            // Filter empty lines specifically created from rapid chunking 
            const finalLogs = strLogs.filter((l, i) => l !== '' || (i > 0 && strLogs[i-1] !== ''));
            setLogs(prev => [...prev.filter((l: string) => l.includes('v3.0') || l.includes('/help') || l.includes('[INFO] Ollama')), ...finalLogs]);
            if (finalLogs.some((l: string) => l.includes('COMPLETE') || l.includes('[SENTINEL REPORT]'))) {
              setShowProceedBtn(true);
            }
          }
        })
        .catch(() => {});
    }

    axios.get(API_STATUS).then(r => { setOllamaStatus(r.data.ollama); setLogs(p => [...p, `[INFO] Ollama: ${r.data.ollama}`]); }).catch(() => setOllamaStatus('offline'));
    axios.get(API_MODELS).then(r => { const l = r.data.models || []; setModels(l); if (l.length) { const pref = l.find((m: string) => m.startsWith('llama3')) || l[0]; setSelectedModel(pref); } }).catch(() => {});
  }, [router]);

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
          if (parts[1] === 'discovery') { setLogs(p => [...p, `[CTX] Resolved path: ${projectPath || '(not set)'}`]); return runDiscovery(); }
          if (parts[1] === 'full') { setLogs(p => [...p, `[CTX] Resolved path: ${projectPath || '(not set)'}`]); return runFullScan(); }
          return setLogs(p => [...p, '[ERROR] Usage: /scan discovery | /scan full']);
        case '/sync': setLogs(p => [...p, `[CTX] Resolved path: ${projectPath || '(not set)'}`]); return runSync();
        case '/rescan':
          if (!parts[1]) return setLogs(p => [...p, '[ERROR] Usage: /rescan <filename>']);
          return handleRescanCommand(parts[1]);
        case '/optimize': return applyPendingOpt();
        case '/proceed': return proceedToNextStep();
        case '/report': return fetchReport();
        case '/status':
          return setLogs(p => [...p,
            `[CTX] Project path: ${projectPath || '(not set)'}`,
            `[CTX] Resolved to: ${projectPath ? `(backend resolves to absolute path)` : 'N/A'}`,
            `[CTX] Type: ${projectType || 'auto'}  Stack: ${techStack || 'auto'}  Risk: ${riskLevel}`,
            `[CTX] Selected: ${selected.length} modules  Discovery: ${discoveryDone ? 'DONE' : 'NOT RUN'}`,
            `[CTX] Ollama: ${ollamaStatus} (${selectedModel})`,
          ]);
        case '/clear': return handleResetSession();
        case '/help':
          return setLogs(p => [...p, '[HELP] ─── Commands ───', ...COMMANDS.map(c => `[HELP]   ${c.cmd.padEnd(20)} ${c.desc}`), '[HELP] ─── Or type a question for the Sentinel ───']);
        default: return setLogs(p => [...p, `[ERROR] Unknown: ${parts[0]}. Type /help`]);
      }
    }
    await chatWithSentinel(input);
  };

  /* ---- Session Reset ---- */
  const handleResetSession = async () => {
    try {
      if (projectPath) {
          const pUrl = `http://localhost:8000/api/history/projects/by-path?path=${encodeURIComponent(projectPath)}`;
          const res = await axios.get(pUrl);
          const pid = res.data.project.id;
          await axios.delete(`http://localhost:8000/api/history/projects/${pid}/logs`);
      }
    } catch (e) {}
    setLogs(['[SYSTEM] Session and logs cleared.']);
    setCurrentPhase('discovery');
    setCompletedSteps(new Set());
    setDiscoveryDone(false);
    setShowProceedBtn(false);
    localStorage.removeItem('activeStep');
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

  /* ---- Rescan file ---- */
  const handleRescanCommand = async (filename: string) => {
    if (!projectPath) { setLogs(p => [...p, '[ERROR] Set a project path first.']); return; }
    if (ollamaStatus !== 'online') { setLogs(p => [...p, '[ERROR] Ollama is offline.']); return; }
    setIsSyncing(true);
    setLogs(p => [...p, `[CMD] Initiating Focused Rescan on ${filename}...`]);
    
    try {
      const resp = await fetch('http://localhost:8000/api/analysis/rescan_file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_path: projectPath, target_file: filename, model: selectedModel }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        setLogs(p => [...p, `[FAIL] ${err.detail || 'Rescan failed'}`]);
        return;
      }
      const reader = resp.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';
          for (const line of lines) {
            if (!line.trim()) continue;
            setLogs(p => [...p, line]);
          }
        }
        if (buffer.trim()) {
           setLogs(p => [...p, buffer]);
        }
      }
    } catch (e: any) {
      setLogs(p => [...p, `[FAIL] ${e.message}`]);
    } finally {
      setIsSyncing(false);
    }
  };

  /* ---- Folder ---- */
  const pickFolder = async () => {
    try {
      const h = await (window as any).showDirectoryPicker();
      setProjectPath(h.name);
      setLogs(p => [...p,
        `[INFO] Folder selected: ${h.name}`,
        '[INFO] Tip: Backend auto-resolves relative paths (project root, Desktop, CWD).',
        '[INFO] For full control, type the absolute path (e.g., C:\\Users\\...\\project).',
      ]);
    } catch {
      const inp = document.createElement('input');
      inp.type = 'file'; (inp as any).webkitdirectory = true;
      inp.onchange = () => {
        const f = inp.files?.[0];
        if (f) {
          const rel = (f as any).webkitRelativePath || '';
          const folder = rel.split('/')[0] || f.name;
          setProjectPath(folder);
          setLogs(p => [...p,
            `[INFO] Folder: ${folder}`,
            '[INFO] Backend will resolve this to an absolute path automatically.',
          ]);
        }
      };
      inp.click();
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
    if (!projectPath) { setLogs(p => [...p, '[ERROR] Set a project path first. Click 📁 or type a path.']); return; }
    setIsSyncing(true);
    const payload = buildSelectedIds(ids);
    setLogs(p => [...p, `[SYNC] ${label} → ${projectPath} (${payload.length} IDs)`]);
    try {
      const res = await axios.post(API_SYNC, { project_path: projectPath, selected_ids: payload, project_context: buildContext() });
      const { synced_count, synced_ids, target, categories_expanded, warnings } = res.data;
      setLoadedProtocolsCount(synced_count);
      setLogs(p => [...p, `[OK] Loaded Protocols: ${synced_count} (${target})`]);
      setLogs(p => [...p, `[OK] Active Rules: ${synced_ids.join(', ')}`]);
      if (categories_expanded?.length) setLogs(p => [...p, `[INFO] Expanded: ${categories_expanded.join(', ')}`]);
      if (warnings?.length) for (const w of warnings) setLogs(p => [...p, `[WARN] ${w}`]);
    } catch (e: any) {
      const detail = e.response?.data?.detail || e.message;
      setLogs(p => [...p, `[FAIL] ${detail}`]);
      // If it's a path error, print the tip
      if (detail.includes('Directory not found') || detail.includes('Tried:')) {
        setLogs(p => [...p, '[INFO] Tip: Type the full absolute path or use a folder name relative to the project root.']);
      }
    }
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

  /* ---- Discovery (AI Analysis — does NOT write .cursorrules) ---- */
  const runDiscovery = async () => {
    if (!projectPath) { setLogs(p => [...p, '[ERROR] Set a project path first. Click 📁 or type a path.']); return; }
    if (ollamaStatus !== 'online') { setLogs(p => [...p, '[ERROR] Ollama is offline. Start it with: ollama serve']); return; }
    setIsSyncing(true);
    setLogs(p => [...p, '[DISCOVERY] ═══ Starting AI-powered project analysis... ═══', `[DISCOVERY] Target: ${projectPath}`, `[DISCOVERY] Model: ${selectedModel}`]);
    try {
      const resp = await fetch(API_DISCOVERY, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_path: projectPath, model: selectedModel }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        setLogs(p => [...p, `[FAIL] ${err.detail || 'Discovery failed'}`]);
        return;
      }
      const reader = resp.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      const discoveryLines: string[] = [];

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          // Process complete lines
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';
          for (const line of lines) {
            if (!line.trim()) continue;
            discoveryLines.push(line);
            // Color-code by prefix
            if (line.startsWith('[DISCOVERY]') || line.startsWith('---')) {
              setLogs(p => [...p, line]);
            } else if (line.startsWith('[STACK]') || line.startsWith('[ENTRY]') || line.startsWith('[ARCH]') || line.startsWith('[INFRA]') || line.startsWith('[DEPS]')) {
              setLogs(p => [...p, `[AI] ${line}`]);
            } else if (line.startsWith('[WARN]') || line.startsWith('[SECRET]') || line.startsWith('[VULN]')) {
              setLogs(p => [...p, `[AI] ⚠ ${line}`]);
            } else if (line.startsWith('[SUMMARY]')) {
              setLogs(p => [...p, `[AI] ═══ ${line} ═══`]);
            } else {
              setLogs(p => [...p, `[AI] ${line}`]);
            }
          }
        }
        // Flush remaining buffer
        if (buffer.trim()) {
          discoveryLines.push(buffer);
          setLogs(p => [...p, `[AI] ${buffer}`]);
        }
      }

      setDiscoveryDone(true);
      setLogs(p => [...p, '[DISCOVERY] ═══ Analysis COMPLETE ═══']);

      // Auto-detect tech stack and project type from AI output
      const fullLog = discoveryLines.join('\n');
      const stackMatch = fullLog.match(/\[STACK\].*?:\s*(.+)/i);
      if (stackMatch && !techStack) {
        const detected = stackMatch[1].toLowerCase();
        const stackMap: Record<string, string> = { python: 'python', fastapi: 'python', django: 'python', flask: 'python', node: 'node', express: 'node', react: 'react', next: 'react', go: 'go', rust: 'rust', java: 'java', '.net': 'dotnet', ruby: 'ruby' };
        for (const [key, val] of Object.entries(stackMap)) {
          if (detected.includes(key)) { setTechStack(val); setLogs(p => [...p, `[CTX] Auto-set Tech Stack: ${val}`]); break; }
        }
      }
      const archMatch = fullLog.match(/\[ARCH\].*?:\s*(.+)/i);
      if (archMatch && !projectType) {
        const arch = archMatch[1].toLowerCase();
        if (arch.includes('api') || arch.includes('rest')) setProjectType('api');
        else if (arch.includes('web') || arch.includes('frontend')) setProjectType('web');
        else if (arch.includes('cli')) setProjectType('cli');
        else if (arch.includes('micro')) setProjectType('microservice');
      }

      // Trigger optimization with discovery findings
      if (ollamaStatus === 'online') await triggerOptimization(false);

      // Save session to backend
      const techs = discoveryLines.filter(l => l.match(/\[STACK\]/)).map(l => l.replace(/.*:\s*/, '').trim());
      const entries = discoveryLines.filter(l => l.match(/\[ENTRY\]/)).map(l => l.replace(/.*:\s*/, '').trim());
      const warns = discoveryLines.filter(l => l.match(/\[WARN\]|\[SECRET\]|\[VULN\]/)).map(l => l.replace(/.*:\s*/, '').trim());
      const detectedArch = archMatch ? archMatch[1] : '';
      const detectedStack = stackMatch ? stackMatch[1] : '';

      axios.post(API_SESSION, {
        project_path: projectPath,
        discovery_data: { tech_stack: detectedStack, project_type: projectType, architecture: detectedArch, technologies: techs, entry_points: entries, warnings: warns, raw_log: fullLog },
        workflow_step: 'modeling',
      }).catch(() => {});

      // Update workflow state
      setCompletedSteps(prev => new Set([...prev, 'discovery']));
      setShowProceedBtn(true);
      setLogs(p => [...p,
        `[SYSTEM] Next logical step: Threat Modeling based on discovered ${detectedArch || techStack || 'project'} architecture.`,
        `[SYSTEM] Click 'PROCEED' or type /proceed to begin Modeling & Deep Scan.`
      ]);
    } catch (e: any) {
      setLogs(p => [...p, `[FAIL] ${e.message}`]);
    } finally {
      setIsSyncing(false);
    }
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
    setShowProceedBtn(true);
  };

  /* ---- Workflow PROCEED ---- */
  const proceedToNextStep = async () => {
    const nextPhase = NEXT_STEP_MAP[currentPhase].next;
    const modules = STEP_MODULES[nextPhase] || [];
    setShowProceedBtn(false);

    // If restarting audit
    if (nextPhase === 'discovery') {
       setCurrentPhase('discovery');
       setCompletedSteps(new Set());
       setLogs(p => [...p, '[SYSTEM] ═══ STARTING NEW AUDIT ═══']);
       return;
    }

    // === MODELING: Stream AI analysis instead of just syncing ===
    if (nextPhase === 'modeling') {
      const prevPhase = currentPhase;
      setCurrentPhase('modeling');
      setSelected(prev => [...new Set([...prev, ...modules])]);
      setLogs(p => [...p, `[SYSTEM] ═══ PROCEEDING TO: MODELING ═══`]);
      axios.post(API_SESSION, { project_path: projectPath, workflow_step: 'modeling' }).catch(() => {});
      const success = await runModeling();
      if (!success) {
        setCurrentPhase(prevPhase); // Revert phase on failure
      }
      return;
    }

    // === DEEP SCAN: Stream AI analysis ===
    if (nextPhase === 'deep_scan') {
      const prevPhase = currentPhase;
      setCurrentPhase('deep_scan');
      const newSelected = [...new Set([...selected, ...modules])];
      setSelected(newSelected);
      setLogs(p => [...p, `[SYSTEM] ═══ PROCEEDING TO: DEEP SCAN ═══`]);
      axios.post(API_SESSION, { project_path: projectPath, workflow_step: 'deep_scan' }).catch(() => {});
      
      // SYNC BEFORE SCAN to validate loaded rules and active targets logging
      await syncToBackend(newSelected, 'DEEP SCAN SYNC');

      const success = await runDeepScan();
      if (!success) {
        setCurrentPhase(prevPhase);
      }
      return;
    }

    // === REPORT: Stream Final AI Report ===
    if (nextPhase === 'report') {
      const prevPhase = currentPhase;
      setCurrentPhase('report');
      setSelected(prev => [...new Set([...prev, ...modules])]);
      setLogs(p => [...p, `[SYSTEM] ═══ PROCEEDING TO: FINAL REPORT ═══`]);
      axios.post(API_SESSION, { project_path: projectPath, workflow_step: 'report' }).catch(() => {});
      const success = await runFinalReport();
      if (!success) {
        setCurrentPhase(prevPhase);
      }
      return;
    }

    // === Other phases: auto-select + sync ===
    if (!modules.length) {
      setLogs(p => [...p, `[WARN] No modules mapped for ${nextPhase}.`]);
      return;
    }
    setSelected(prev => [...new Set([...prev, ...modules])]);
    setCurrentPhase(nextPhase);
    setLogs(p => [...p,
      `[SYSTEM] ═══ PROCEEDING TO: ${WORKFLOW_LABELS[nextPhase]?.toUpperCase()} ═══`,
      `[SYNC] Auto-selecting ${modules.length} modules: ${modules.join(', ')}`,
    ]);
    
    // Send phase change ping to backend to update session context
    axios.post(API_SESSION, { project_path: projectPath, workflow_step: nextPhase }).catch(() => {});
    
    await syncToBackend([...selected, ...modules], `WORKFLOW → ${WORKFLOW_LABELS[nextPhase]}`);

    setCompletedSteps(prev => {
      const next = new Set(prev);
      if (currentPhase !== 'report') next.add(currentPhase);
      return next;
    });

    if (nextPhase === 'report') {
      setCompletedSteps(prev => new Set([...prev, 'report']));
      setLogs(p => [...p, '[SYSTEM] ═══ WORKFLOW COMPLETE ═══', '[INFO] All protocols synced. Use the AI Sentinel for analysis or type /report.']);
      setShowProceedBtn(true);
    } else {
      setShowProceedBtn(true);
      // @ts-ignore
      setLogs(p => [...p, `[SYSTEM] Next step: ${WORKFLOW_LABELS[NEXT_STEP_MAP[nextPhase].next]}. Click 'PROCEED' when ready.`]);
    }
  };

  const handleRerun = (phase: Phase) => {
    setCurrentPhase(phase);
    if (phase === 'discovery') runDiscovery();
    else if (phase === 'modeling') runModeling(true);
    else if (phase === 'deep_scan') runDeepScan(true);
    else if (phase === 'report') {
      try {
        // Assume runFinalReport exists and is available
        // @ts-ignore
        runFinalReport();
      } catch (e) {}
    }
  };

  /* ---- Modeling (AI Streaming) ---- */
  const runModeling = async (rerun: boolean = false) => {
    if (!projectPath) { setLogs(p => [...p, '[ERROR] Set a project path first.']); return; }
    if (ollamaStatus !== 'online') { setLogs(p => [...p, '[ERROR] Ollama is offline. Start with: ollama serve']); return; }
    setIsSyncing(true);
    setLogs(p => [...p, '[MODELING] ═══ Starting Threat Modeling analysis... ═══', `[MODELING] Model: ${selectedModel}`]);
    try {
      const discoveryLog = logs.filter(l => l.startsWith('[AI]') || l.startsWith('[DISCOVERY]')).join('\n');
      const resp = await fetch(API_MODELING, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_path: projectPath, discovery_log: discoveryLog, model: selectedModel, use_persistent_context: rerun }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        setLogs(p => [...p, `[FAIL] ${err.detail || 'Modeling failed'}`]);
        return;
      }
      const reader = resp.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      const modelingLines: string[] = [];
      let threatCount = 0;

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';
          for (const line of lines) {
            if (!line.trim()) continue;
            modelingLines.push(line);
            if (line.startsWith('[THREAT]')) threatCount++;
            if (line.startsWith('[MODELING]') || line.startsWith('---')) {
              setLogs(p => [...p, line]);
            } else if (line.startsWith('[TRUST]') || line.startsWith('[DATAFLOW]')) {
              setLogs(p => [...p, `[AI] 🛡 ${line}`]);
            } else if (line.startsWith('[THREAT]') || line.startsWith('[AUTH]') || line.startsWith('[AUTHZ]')) {
              setLogs(p => [...p, `[AI] ⚠ ${line}`]);
            } else if (line.startsWith('[RECOMMEND]')) {
              setLogs(p => [...p, `[OPTIMIZE] ${line}`]);
            } else if (line.startsWith('[SUMMARY]')) {
              setLogs(p => [...p, `[AI] ═══ ${line} ═══`]);
            } else {
              setLogs(p => [...p, `[AI] ${line}`]);
            }
          }
        }
        if (buffer.trim()) {
          modelingLines.push(buffer);
          setLogs(p => [...p, `[AI] ${buffer}`]);
        }
      }
      
      const isTimeout = modelingLines.some(l => l.includes('[TIMEOUT]'));
      if (isTimeout) {
        setLogs(p => [...p, `[ERROR] AI Timeout. Please 'Retry' or change the model.`]);
        setShowProceedBtn(true);
        return false;
      }

      // Sync modeling protocols to .cursorrules
      const modelingModules = STEP_MODULES['modeling'] || [];
      await syncToBackend([...selected, ...modelingModules], 'MODELING SYNC');

      setCompletedSteps(prev => new Set([...prev, 'modeling']));
      
      // Send phase change ping for Deep Scan (it will become the active phase after modeling logic finishes)
      // wait, proceedToNextStep triggers the next phase. Here we just unlock the button for Deep Scan.
      // So currentPhase REMAINS 'modeling', but modeling is done. The user clicks "PROCEED" to enter deep_scan.

      // Extract [RECOMMEND] lines for Deep Scan suggestion
      const recommendations = modelingLines.filter(l => l.startsWith('[RECOMMEND]')).map(l => l.replace('[RECOMMEND]', '').trim());
      setLogs(p => [...p,
        `[MODELING] Logic analysis complete. ${threatCount} architectural threat${threatCount !== 1 ? 's' : ''} found.`,
      ]);
      if (recommendations.length > 0) {
        setLogs(p => [...p,
          `[OPTIMIZE] Based on Modeling, I recommend adding for Deep Scan:`,
          ...recommendations.map(r => `[OPTIMIZE]   → ${r}`),
        ]);
      }
      setShowProceedBtn(true);
      setLogs(p => [...p, `[SYSTEM] Click 'PROCEED TO DEEP SCAN' to continue.`]);
      return true;
    } catch (e: any) {
      setLogs(p => [...p, `[FAIL] ${e.message}`]);
      setShowProceedBtn(true);
      return false;
    } finally {
      setIsSyncing(false);
    }
  };

  /* ---- Deep Scan (AI Streaming) ---- */
  const runDeepScan = async (rerun: boolean = false) => {
    if (!projectPath) { setLogs(p => [...p, '[ERROR] Set a project path first.']); return false; }
    if (ollamaStatus !== 'online') { setLogs(p => [...p, '[ERROR] Ollama is offline. Start with: ollama serve']); return false; }
    setIsSyncing(true);
    setLogs(p => [...p, '[DEEP_SCAN] ═══ Starting Deep Scan analysis... ═══', `[DEEP_SCAN] Model: ${selectedModel}`]);
    try {
      const modelingLog = logs.filter(l => l.startsWith('[AI] 🛡') || l.startsWith('[AI] ⚠') || l.startsWith('[MODELING]')).join('\n');
      const resp = await fetch(API_DEEP_SCAN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_path: projectPath, modeling_log: modelingLog, model: selectedModel, use_persistent_context: rerun }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        setLogs(p => [...p, `[FAIL] ${err.detail || 'Deep Scan failed'}`]);
        return false;
      }
      const reader = resp.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      const scanLines: string[] = [];
      let vulnCount = 0;

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';
          for (const line of lines) {
            if (!line.trim()) continue;
            scanLines.push(line);
            
            // Handle specific structured tags
            if (line.startsWith('[DEEP_SCAN]') || line.startsWith('---')) {
              setLogs(p => [...p, line]);
            } else if (line.startsWith('[SENTINEL_REFUSAL]')) {
              setLogs(p => [...p, `[SENTINEL_REFUSAL] AI model is being cautious. Retrying with aggressive mode...`]);
            } else if (line.startsWith('[VALIDATION FAILED]')) {
              setLogs(p => [...p, `[ERROR] 🔥 ${line}`]);
            } else if (line.startsWith('[VULN]')) {
              vulnCount++;
              setLogs(p => [...p, `[AI] 🚨 ${line}`]);
            } else if (line.startsWith('[SUMMARY]')) {
              setLogs(p => [...p, `[AI] ═══ ${line} ═══`]);
            } else if (line.startsWith('[FIX]')) {
              setLogs(p => [...p, `[AI] 🔧 ${line}`]);
            } else if (line.startsWith('[AI] Testing')) {
              setLogs(p => [...p, line]);
            } else {
              // Pass pure Markdown directly
              setLogs(p => [...p, `[AI] ${line}`]);
            }
          }
        }
        if (buffer.trim()) {
          scanLines.push(buffer);
          setLogs(p => [...p, `[AI] ${buffer}`]);
        }
      }

      const isTimeout = scanLines.some(l => l.includes('[TIMEOUT]'));
      if (isTimeout) {
        setLogs(p => [...p, `[ERROR] AI Timeout during Deep Scan. Please 'Retry' or change the model.`]);
        setShowProceedBtn(true);
        return false;
      }

      setCompletedSteps(prev => new Set([...prev, 'deep_scan']));

      setLogs(p => [...p,
        `[DEEP_SCAN] Scan complete. ${vulnCount} vulnerabilit${vulnCount !== 1 ? 'ies' : 'y'} documented.`,
      ]);
      setShowProceedBtn(true);
      setLogs(p => [...p, `[SYSTEM] Click 'PROCEED TO FINAL REPORT' to generate the Gold Standard Markdown report.`]);
      return true;
    } catch (e: any) {
      setLogs(p => [...p, `[FAIL] ${e.message}`]);
      setShowProceedBtn(true);
      return false;
    } finally {
      setIsSyncing(false);
    }
  };

  /* ---- Final Report (AI Streaming) ---- */
  const runFinalReport = async () => {
    if (!projectPath) { setLogs(p => [...p, '[ERROR] Set a project path first.']); return false; }
    if (ollamaStatus !== 'online') { setLogs(p => [...p, '[ERROR] Ollama is offline. Start with: ollama serve']); return false; }
    setIsSyncing(true);
    setLogs(p => [...p, '[REPORT] ═══ Generating Final Report... ═══', `[REPORT] Model: ${selectedModel}`]);
    try {
      const allLogs = logs.join('\n');
      const activeProjRaw = localStorage.getItem('activeProject');
      let pid = '';
      let pname = '';
      if (activeProjRaw) {
        try {
          const p = JSON.parse(activeProjRaw);
          pid = p.id || '';
          pname = p.name || '';
        } catch(e) {}
      }
      
      const resp = await fetch(API_FINAL_REPORT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: pid, project_name: pname, model: selectedModel }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        setLogs(p => [...p, `[FAIL] ${err.detail || 'Final Report generation failed'}`]);
        return false;
      }
      const reader = resp.body?.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      const reportLines: string[] = [];

      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';
          for (const line of lines) {
            if (!line.trim()) continue;
            reportLines.push(line);
            if (line.startsWith('[REPORT]') || line.startsWith('---')) {
              setLogs(p => [...p, line]);
            } else if (line.startsWith('#') || line.startsWith('-') || line.trim() !== '') {
              // Standard markdown streamed line
              setLogs(p => [...p, `[SENTINEL REPORT] ${line}`]);
            }
          }
        }
        if (buffer.trim()) {
          reportLines.push(buffer);
          setLogs(p => [...p, `[SENTINEL REPORT] ${buffer}`]);
        }
      }

      const isTimeout = reportLines.some(l => l.includes('[TIMEOUT]'));
      if (isTimeout) {
        setLogs(p => [...p, `[ERROR] AI Timeout during Final Report.`]);
        setShowProceedBtn(true);
        return false;
      }

      // Sync final reporting protocols
      const rModules = STEP_MODULES['report'] || [];
      await syncToBackend([...selected, ...rModules], 'FINAL REPORT SYNC');

      setCompletedSteps(prev => new Set([...prev, 'report']));
      setLogs(p => [...p, '[SYSTEM] ═══ WORKFLOW COMPLETE ═══', '[INFO] Final Report Generated natively.']);
      setShowProceedBtn(true);

      // Auto-save audit to history
      try {
        const reportText = reportLines.join('\n');
        
        const metrics = {
          architecture: (reportText.match(/architecture|iam_roles|identity|auth/gi) || []).length,
          iam: (reportText.match(/privilege|rbac|token|oauth|session/gi) || []).length,
          data_flow: (reportText.match(/injection|xss|sqli|csrf|taint|ssrf/gi) || []).length,
          business_logic: (reportText.match(/tampering|bypass|race condition|toctou/gi) || []).length,
          iac: (reportText.match(/docker|kubernetes|terraform|pipeline|secret/gi) || []).length,
          compliance: (reportText.match(/license|sbom|cve|outdated/gi) || []).length,
        };
        
        await axios.post('http://localhost:8000/api/history/save', {
          project_path: projectPath,
          status: 'completed',
          findings_stats: {
            total: (reportText.match(/\[SEC-/g) || []).length,
            critical: (reportText.match(/Критичность:\s*(CRITICAL|КРИТИЧНАЯ)/gi) || []).length,
            high: (reportText.match(/Критичность:\s*(HIGH|ВЫСОКАЯ)/gi) || []).length,
            medium: (reportText.match(/Критичность:\s*(MEDIUM|СРЕДНЯЯ)/gi) || []).length,
            low: (reportText.match(/Критичность:\s*(LOW|НИЗКАЯ)/gi) || []).length,
          },
          metrics
        });
        setLogs(p => [...p, '[SYSTEM] Audit saved to History successfully.']);
      } catch (err) {
        setLogs(p => [...p, '[WARN] Failed to auto-save audit to history.']);
        console.error(err);
      }

      return true;
    } catch (e: any) {
      setLogs(p => [...p, `[FAIL] ${e.message}`]);
      setShowProceedBtn(true);
      return false;
    } finally {
      setIsSyncing(false);
    }
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
    if (l.startsWith('[AI]')) return '#34d399';
    if (l.startsWith('[DISCOVERY]')) return '#a855f7';
    if (l.startsWith('[MODELING]')) return '#f472b6';
    if (l.startsWith('[TRUST]') || l.startsWith('[DATAFLOW]')) return '#67e8f9';
    if (l.startsWith('[THREAT]')) return '#fb923c';
    if (l.startsWith('[RECOMMEND]')) return '#c084fc';
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
        <Title level={4} style={{ margin: 0, color: '#fff', letterSpacing: '1px', whiteSpace: 'nowrap', marginRight: 16, marginTop: 14 }}>
          SECCODEREVIEW <span style={{ color: '#888', fontWeight: 400 }}>| {projectName}</span>
        </Title>
        <Button type="text" onClick={() => router.push('/projects')} style={{ color: '#aaa', fontWeight: 500 }}>Projects</Button>
        <Button type="text" onClick={() => router.push('/history')} style={{ color: '#aaa', fontWeight: 500 }}>History</Button>
        <Button type="text" onClick={handleResetSession} style={{ color: '#ef4444', fontWeight: 500 }}>Reset Session</Button>
        
        <div style={{ width: 1, height: 24, background: '#333', margin: '0 12px' }} />

        <Button type="text" icon={<FolderOpenOutlined />} onClick={pickFolder} style={{ color: '#888' }} />
        <Input value={projectPath} onChange={(e: any) => setProjectPath(e.target.value)} placeholder="Path to repository..." variant="borderless" prefix={<SearchOutlined style={{ color: '#444' }} />} style={{ flex: 1, fontFamily: 'monospace', fontSize: 14 }} />

        {/* Context tags */}
        {projectType && <Tag color="cyan" style={{ margin: 0, fontSize: 9 }}>{projectType}</Tag>}
        {techStack && <Tag color="geekblue" style={{ margin: 0, fontSize: 9 }}>{techStack}</Tag>}
        <Tag color={riskLevel === 'high' ? 'red' : riskLevel === 'low' ? 'green' : 'gold'} style={{ margin: 0, fontSize: 9 }}>{riskLevel}</Tag>
        <Tag color="blue" style={{ margin: 0, fontFamily: 'monospace', fontSize: 10, fontWeight: 700 }}>{loadedProtocolsCount > 0 ? loadedProtocolsCount : selected.length}</Tag>
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
            
            /* Phase-lock: unlock behavior */
            const phaseMap: Record<string, Phase> = { discovery: 'discovery', modeling: 'modeling', deep_scan: 'deep_scan', validating_and_reporting: 'report' };
            const cardPhase = phaseMap[sec.id] || 'discovery';
            
            // A card is active (editable) if it's the current running phase, 
            // OR if the current phase is done (showProceedBtn) and this is the NEXT phase to be started.
            const isCurrentProcessing = cardPhase === currentPhase && !showProceedBtn;
            const isNextReady = showProceedBtn && cardPhase === NEXT_STEP_MAP[currentPhase].next;
            const isActivePhase = isCurrentProcessing || isNextReady;
            const isLocked = !isActivePhase;
            
            let lockMsg = 'LOCKED';
            if (completedSteps.has(cardPhase)) lockMsg = '✓ COMPLETED';
            else if (sec.id === 'modeling') lockMsg = 'COMPLETE DISCOVERY FIRST';
            else if (sec.id === 'deep_scan') lockMsg = 'COMPLETE MODELING FIRST';
            else if (sec.id === 'validating_and_reporting') lockMsg = 'COMPLETE DEEP SCAN FIRST';

            const borderColor = isActivePhase ? '#3b82f6' : isLocked ? '#111' : '#1a1a1a';
            return (<div key={sec.id} style={{ filter: isLocked ? 'grayscale(1)' : 'none', opacity: isLocked ? 0.35 : 1, transition: 'all 0.3s', pointerEvents: isLocked ? 'none' : 'auto', position: 'relative' }}>
              {isLocked && <div style={{ position: 'absolute', inset: 0, zIndex: 2, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.4)', borderRadius: 8, pointerEvents: 'none' }}>
                <Tag color="default" style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', background: completedSteps.has(cardPhase) ? '#16653420' : '#111', borderColor: completedSteps.has(cardPhase) ? '#16653450' : '#333', color: completedSteps.has(cardPhase) ? '#4ade80' : '#888' }}>
                  {lockMsg}
                </Tag>
              </div>}
              <Card size="small" styles={{ header: { borderBottom: '1px solid #1a1a1a', padding: '12px 16px' }, body: { padding: (isOpen && sec.modules.length) ? '8px 12px' : 0 } }} style={{ background: isActivePhase ? '#0a0f1a' : '#0a0a0a', borderColor, borderWidth: isActivePhase ? 2 : 1, boxShadow: isActivePhase ? '0 0 16px #3b82f620' : 'none', transition: 'all 0.3s' }}
              title={<Flex align="center" gap={10}>
                <Checkbox checked={checked || sec.mandatory} indeterminate={indeterminate} disabled={sec.mandatory || isLocked} onChange={() => toggleSection(sec)} />
                <span onClick={() => sec.modules.length > 0 && setExpanded(p => ({ ...p, [sec.id]: !isOpen }))} style={{ cursor: sec.modules.length ? 'pointer' : 'default', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: isActivePhase ? '#60a5fa' : sec.mandatory ? '#3b82f6' : '#999', flex: 1 }}>
                  {sec.label}{sec.mandatory && <Tag color="blue" style={{ marginLeft: 8, fontSize: 9 }}>REQ</Tag>}
                  {isActivePhase && <Tag color="blue" style={{ marginLeft: 8, fontSize: 9 }}>ACTIVE</Tag>}
                </span>
                {completedSteps.has(cardPhase) && <Button size="small" type="text" icon={<ReloadOutlined />} onClick={(e: any) => { e.stopPropagation(); handleRerun(cardPhase); }} style={{ color: '#888', fontSize: 10, padding: 0 }}>Re-run</Button>}
                {sec.modules.length > 0 && <Text type="secondary" style={{ fontSize: 10, fontFamily: 'monospace' }}>{sec.modules.length}</Text>}
              </Flex>}
            >
              {isOpen && sec.modules.map(mod => {
                const isOn = selected.includes(mod.id);
                return (<Flex key={mod.id} align="center" gap={8} onClick={() => toggleModule(mod.id)} style={{ padding: '8px 10px', borderRadius: 6, cursor: (mod.mandatory || isLocked) ? 'default' : 'pointer', marginBottom: 2, background: isOn ? 'rgba(59,130,246,0.08)' : 'transparent' }}>
                  <Checkbox checked={isOn || mod.mandatory} disabled={mod.mandatory || isLocked} style={{ pointerEvents: 'none' }} />
                  <Text style={{ fontSize: 13, fontFamily: 'monospace', color: isOn ? '#93c5fd' : '#888' }}>{mod.label}</Text>
                  {mod.mandatory && <Tag color="green" style={{ marginLeft: 'auto', fontSize: 9 }}>REQ</Tag>}
                </Flex>);
              })}
            </Card></div>);
          })}
        </div>

        {/* ===== WORKFLOW PROGRESS BAR ===== */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 0, padding: '8px 0' }}>
          {WORKFLOW_ORDER.map((step, i) => {
            const isDone = completedSteps.has(step);
            const isActive = currentPhase === step;
            const canClick = false; // Progress bar clicking disabled per strict phase jumping
            const color = isDone ? '#4ade80' : isActive ? '#3b82f6' : '#333';
            const textColor = isDone ? '#4ade80' : isActive ? '#93c5fd' : '#555';

            return (
              <React.Fragment key={step}>
                {i > 0 && <div style={{ width: 40, height: 2, background: isDone || isActive ? '#3b82f6' : '#222', transition: 'background 0.3s' }} />}
                <div
                  style={{
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, cursor: 'default', opacity: !isActive && !isDone ? 0.4 : 1,
                    transition: 'opacity 0.3s',
                  }}
                >
                  <div style={{
                    width: 28, height: 28, borderRadius: '50%', border: `2px solid ${color}`, display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: isDone ? '#4ade8020' : isActive ? '#3b82f620' : 'transparent',
                    boxShadow: isActive ? '0 0 12px #3b82f640' : 'none', transition: 'all 0.3s',
                  }}>
                    {isDone ? <span style={{ color: '#4ade80', fontSize: 14, fontWeight: 700 }}>✓</span>
                     : <span style={{ color: textColor, fontSize: 11, fontWeight: 700 }}>{i + 1}</span>}
                  </div>
                  <Text style={{ fontSize: 9, fontFamily: 'monospace', color: textColor, textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: isActive ? 700 : 400, textAlign: 'center', lineHeight: 1.2 }}>
                    {WORKFLOW_LABELS[step]}
                  </Text>
                </div>
              </React.Fragment>
            );
          })}
        </div>

        {/* ===== PROCEED BUTTON ===== */}
        {showProceedBtn && (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '4px 0', gap: 16 }}>
            {completedSteps.has('report') && (
              <Button
                type="default" size="large"
                icon={<CodeOutlined />}
                onClick={() => {
                  const reportContent = logs.filter(l => l.startsWith('[SENTINEL REPORT] ')).map(l => l.replace('[SENTINEL REPORT] ', '')).join('\n');
                  const file = new Blob([reportContent || logs.join('\n')], {type: 'text/markdown'});
                  const el = document.createElement('a');
                  el.href = URL.createObjectURL(file);
                  el.download = 'Security_Audit_Report.md';
                  el.click();
                }}
                style={{
                  fontWeight: 700, fontSize: 14, height: 48, paddingInline: 32,
                  borderColor: '#3b82f6', color: '#3b82f6', background: 'transparent',
                  letterSpacing: '0.08em',
                }}
              >
                DOWNLOAD MARKDOWN
              </Button>
            )}
            <Button
              type="primary" size="large"
              icon={<RocketOutlined />}
              onClick={proceedToNextStep}
              loading={isSyncing}
              disabled={isStreaming || isOptimizing}
              style={{
                fontWeight: 700, fontSize: 14, height: 48, paddingInline: 32,
                background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)', border: 'none',
                boxShadow: '0 0 20px #3b82f640', letterSpacing: '0.08em',
              }}
            >
              {NEXT_STEP_MAP[currentPhase]?.label || 'PROCEED'}
            </Button>
          </div>
        )}

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
            <Input ref={inputRef} value={cmdInput} onChange={(e: any) => setCmdInput(e.target.value)} onKeyDown={handleKeyDown}
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