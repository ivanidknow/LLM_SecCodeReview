'use client';
import React, { useState, useEffect, Suspense } from 'react';
import { 
  ConfigProvider, theme, Layout, Card, Button, Typography, 
  Flex, Table, Tag, Modal, message, Breadcrumb 
} from 'antd';
import { 
  GithubOutlined, ArrowLeftOutlined, DownloadOutlined, 
  BarChartOutlined, HomeOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useRouter, useSearchParams } from 'next/navigation';
import '../globals.css';

const { Text, Title } = Typography;
const { Header, Content } = Layout;

function HistoryContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [audits, setAudits] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Radar Chart Modal State
  const [metricsModalOpen, setMetricsModalOpen] = useState(false);
  const [activeMetrics, setActiveMetrics] = useState<any>(null);

  useEffect(() => {
    // If we have a project_id, fetch for it, else fetch all (API doesn't have a fetch all audits yet, so we'll just check if there's a specific project or we fallback to the active project)
    const pid = searchParams.get('project_id');
    const localProj = localStorage.getItem('activeProject');
    let targetId = pid;
    
    if (!targetId && localProj) {
      try {
        const p = JSON.parse(localProj);
        targetId = p.id;
      } catch(e) {}
    }

    if (targetId) {
      fetchAudits(targetId);
    } else {
      setLoading(false);
      message.info("No project selected to show history for.");
    }
  }, [searchParams]);

  const fetchAudits = async (projectId: string) => {
    try {
      setLoading(true);
      const res = await axios.get(`http://localhost:8000/api/history/projects/${projectId}/audits`);
      setAudits(res.data.audits || []);
    } catch (e) {
      console.error(e);
      message.error("Failed to load audit history");
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (audit: any) => {
    if (!audit.report_path) return;
    try {
      window.open(`http://localhost:8000/api/history/audits/${audit.id}/report?report_path=${encodeURIComponent(audit.report_path)}`, '_blank');
    } catch(e) {
      message.error("Failed to download report");
    }
  };

  const showMetrics = (audit: any) => {
    setActiveMetrics(audit);
    setMetricsModalOpen(true);
  };

  const columns = [
    {
      title: 'Date',
      dataIndex: 'timestamp',
      key: 'timestamp',
      render: (t: string) => new Date(t).toLocaleString(),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (s: string) => <Tag color={s === 'completed' ? 'green' : 'orange'}>{s.toUpperCase()}</Tag>,
    },
    {
      title: 'Total Vulns',
      dataIndex: 'total_findings',
      key: 'total_findings',
      render: (val: number) => <Text strong>{val}</Text>,
    },
    {
      title: 'Severity Breakdown',
      key: 'severity',
      render: (_: any, record: any) => (
        <Flex gap="small">
          {record.critical > 0 && <Tag color="red">C: {record.critical}</Tag>}
          {record.high > 0 && <Tag color="volcano">H: {record.high}</Tag>}
          {record.medium > 0 && <Tag color="orange">M: {record.medium}</Tag>}
          {record.low > 0 && <Tag color="blue">L: {record.low}</Tag>}
          {record.total_findings === 0 && <Text type="secondary">-</Text>}
        </Flex>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: any, record: any) => (
        <Flex gap="small">
          <Button 
            type="primary" ghost size="small" 
            icon={<DownloadOutlined />} 
            disabled={!record.report_path}
            onClick={() => handleDownload(record)}
          >
            Report
          </Button>
          <Button 
            size="small" 
            icon={<BarChartOutlined />} 
            onClick={() => showMetrics(record)}
          >
            Metrics
          </Button>
        </Flex>
      ),
    },
  ];

  // Helper to draw a simple static radar chart using SVG
  const renderRadarChart = (metrics: any) => {
    if (!metrics) return null;
    
    const categories = ['Architecture', 'IAM', 'Data Flow', 'Business Logic', 'IaC', 'Compliance'];
    const keys = ['architecture', 'iam', 'data_flow', 'business_logic', 'iac', 'compliance'];
    const values = keys.map(k => metrics[k] || 0);
    const maxVal = Math.max(...values, 5); // Minimum scale of 5
    
    // SVG Dimensions
    const size = 300;
    const center = size / 2;
    const radius = size * 0.35;
    
    // Calculate points
    const points = values.map((val, i) => {
      const angle = (Math.PI * 2 * i) / categories.length - Math.PI / 2;
      const r = (val / maxVal) * radius;
      return `${center + r * Math.cos(angle)},${center + r * Math.sin(angle)}`;
    }).join(' ');

    return (
      <div style={{ textAlign: 'center' }}>
        <svg width={size} height={size}>
          {/* Draw axes and background web */}
          {[0.2, 0.4, 0.6, 0.8, 1].map(scale => {
            const webPoints = categories.map((_, i) => {
              const angle = (Math.PI * 2 * i) / categories.length - Math.PI / 2;
              return `${center + radius * scale * Math.cos(angle)},${center + radius * scale * Math.sin(angle)}`;
            }).join(' ');
            return <polygon key={scale} points={webPoints} fill="none" stroke="#333" strokeDasharray="3,3" />;
          })}
          
          {/* Draw axes lines and labels */}
          {categories.map((cat, i) => {
             const angle = (Math.PI * 2 * i) / categories.length - Math.PI / 2;
             const x = center + radius * Math.cos(angle);
             const y = center + radius * Math.sin(angle);
             const labelX = center + (radius + 20) * Math.cos(angle);
             const labelY = center + (radius + 20) * Math.sin(angle);
             return (
               <g key={cat}>
                 <line x1={center} y1={center} x2={x} y2={y} stroke="#444" />
                 <text 
                   x={labelX} y={labelY} 
                   fill="#aaa" fontSize="12" 
                   textAnchor={Math.cos(angle) > 0.1 ? 'start' : Math.cos(angle) < -0.1 ? 'end' : 'middle'}
                   alignmentBaseline="middle"
                 >
                   {cat}
                 </text>
               </g>
             );
          })}
          
          {/* Draw the data polygon */}
          <polygon points={points} fill="rgba(59, 130, 246, 0.3)" stroke="#3b82f6" strokeWidth="2" />
          
          {/* Draw data points */}
          {values.map((val, i) => {
             const angle = (Math.PI * 2 * i) / categories.length - Math.PI / 2;
             const r = (val / maxVal) * radius;
             const cx = center + r * Math.cos(angle);
             const cy = center + r * Math.sin(angle);
             return <circle key={i} cx={cx} cy={cy} r="4" fill="#60a5fa" />;
          })}
        </svg>
      </div>
    );
  };

  return (
    <Layout style={{ minHeight: '100vh', background: 'transparent' }}>
      <Header style={{ 
        background: 'rgba(0,0,0,0.5)', 
        backdropFilter: 'blur(10px)',
        borderBottom: '1px solid #1f1f1f',
        display: 'flex',
        alignItems: 'center',
        padding: '0 24px'
      }}>
        <Button type="text" icon={<ArrowLeftOutlined />} onClick={() => router.push('/projects')} style={{ color: '#aaa', marginRight: 16 }} />
        <Flex align="center" gap="small">
          <GithubOutlined style={{ fontSize: 24, color: '#3b82f6' }} />
          <Title level={4} style={{ margin: 0, color: '#fff', letterSpacing: '1px' }}>
            HEXSTRIKE <span style={{ color: '#888', fontWeight: 400 }}>| Audit History</span>
          </Title>
        </Flex>
      </Header>

      <Content style={{ padding: '40px 50px', maxWidth: 1200, margin: '0 auto', width: '100%' }}>
        <Breadcrumb items={[
          { title: <a onClick={() => router.push('/')}><HomeOutlined /> Console</a> },
          { title: <a onClick={() => router.push('/projects')}>Projects</a> },
          { title: 'History' },
        ]} style={{ marginBottom: 24 }} />

        <Card className="glass-card" style={{ background: '#111', borderColor: '#222' }}>
          <Table 
            dataSource={audits}
            columns={columns}
            rowKey="id"
            loading={loading}
            pagination={{ pageSize: 10 }}
            locale={{ emptyText: "No audits found for this project." }}
          />
        </Card>
      </Content>

      <Modal
        title="Audit Metrics - Attack Vectors"
        open={metricsModalOpen}
        onCancel={() => setMetricsModalOpen(false)}
        footer={null}
        width={500}
      >
        <div style={{ paddingTop: 20 }}>
          {renderRadarChart(activeMetrics)}
          
          <div style={{ marginTop: 24 }}>
            <Text strong style={{ display: 'block', marginBottom: 8 }}>Raw Counts</Text>
            <Flex wrap="wrap" gap="small">
              <Tag color="#108ee9">Architecture: {activeMetrics?.architecture || 0}</Tag>
              <Tag color="#108ee9">IAM: {activeMetrics?.iam || 0}</Tag>
              <Tag color="#108ee9">Data Flow: {activeMetrics?.data_flow || 0}</Tag>
              <Tag color="#108ee9">Business Logic: {activeMetrics?.business_logic || 0}</Tag>
              <Tag color="#108ee9">IaC: {activeMetrics?.iac || 0}</Tag>
              <Tag color="#108ee9">Compliance: {activeMetrics?.compliance || 0}</Tag>
            </Flex>
          </div>
        </div>
      </Modal>
    </Layout>
  );
}

export default function HistoryPage() {
  return (
    <ConfigProvider theme={{ 
      algorithm: theme.darkAlgorithm, 
      token: { 
        colorBgContainer: '#0a0a0a', 
        colorBgElevated: '#111', 
        colorBgLayout: '#000', 
        colorBorder: '#1f1f1f', 
        colorPrimary: '#3b82f6', 
        borderRadius: 8 
      } 
    }}>
      <Suspense fallback={<div style={{ padding: 50, color: 'white' }}>Loading...</div>}>
         <HistoryContent />
      </Suspense>
    </ConfigProvider>
  );
}
