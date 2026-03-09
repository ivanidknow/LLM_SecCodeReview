import { AlertTriangle, Code, Lightbulb } from 'lucide-react';

interface FindingProps {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  remediation: string;
}

export default function FindingCard({ id, title, severity, description, remediation }: FindingProps) {
  const colors = {
    CRITICAL: 'text-red-500 border-red-500/30 bg-red-500/5',
    HIGH: 'text-orange-500 border-orange-500/30 bg-orange-500/5',
    MEDIUM: 'text-yellow-500 border-yellow-500/30 bg-yellow-500/5',
    LOW: 'text-blue-500 border-blue-500/30 bg-blue-500/5',
  };

  return (
    <div className={`glass-card p-6 rounded-2xl border ${colors[severity]} space-y-4`}>
      <div className="flex justify-between items-start">
        <div className="flex items-center gap-2">
          <AlertTriangle size={18} />
          <span className="font-mono text-xs font-bold">{id}</span>
        </div>
        <span className="text-[10px] font-bold uppercase tracking-widest opacity-60">Status: Active</span>
      </div>
      
      <h3 className="text-xl font-bold text-white">{title}</h3>
      <p className="text-sm text-white/60 leading-relaxed">{description}</p>
      
      <div className="pt-4 border-t border-white/10 flex gap-4">
        <div className="flex items-center gap-2 text-xs font-mono text-white/40 cursor-pointer hover:text-white transition-colors">
          <Code size={14} /> View Location
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-blue-400 cursor-pointer hover:text-blue-300 transition-colors">
          <Lightbulb size={14} /> Remediation Plan
        </div>
      </div>
    </div>
  );
}