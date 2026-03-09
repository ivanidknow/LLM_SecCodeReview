'use client';
import React, { useState, useEffect } from 'react';
import { ChevronRight, ChevronDown, Folder, FileCode, CheckSquare, Square } from 'lucide-react';
import axios from 'axios';

export default function MethodologyTree({ onSelectionChange }: { onSelectionChange: (ids: string[]) => void }) {
  const [data, setData] = useState<any>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [expanded, setExpanded] = useState<string[]>([]);

  useEffect(() => {
    axios.get('http://localhost:8000/api/methodology').then(res => setData(res.data));
  }, []);

  const toggleProtocol = (id: string) => {
    const newSelected = selected.includes(id) ? selected.filter(i => i !== id) : [...selected, id];
    setSelected(newSelected);
    onSelectionChange(newSelected);
  };

  if (!data) return <div className="p-4 text-white/10 font-mono text-[10px]">LOADING_STRUCTURE...</div>;

  return (
    <div className="space-y-1">
      {Object.keys(data).map((category) => (
        <div key={category} className="group">
          <div
            onClick={() => setExpanded(prev => prev.includes(category) ? prev.filter(c => c !== category) : [...prev, category])}
            className="flex items-center gap-2 py-1 px-2 hover:bg-white/5 rounded cursor-pointer transition-colors"
          >
            {expanded.includes(category) ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            <Folder size={14} className="text-blue-500/50" />
            <span className="text-[11px] font-bold text-white/60 uppercase tracking-tighter">{category}</span>
          </div>

          {expanded.includes(category) && (
            <div className="ml-4 pl-2 border-l border-white/5 mt-1 space-y-1">
              {data[category].map((proto: any) => (
                <div
                  key={proto.id}
                  onClick={() => toggleProtocol(proto.id)}
                  className="flex items-center gap-3 py-1 px-2 hover:bg-white/5 rounded cursor-pointer transition-all"
                >
                  {selected.includes(proto.id) ? <CheckSquare size={14} className="text-blue-400" /> : <Square size={14} className="text-white/10" />}
                  <div className="flex flex-col">
                    <span className={`text-[11px] ${selected.includes(proto.id) ? 'text-blue-400' : 'text-white/40'}`}>{proto.id}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}