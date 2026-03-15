'use client';
import React, { useState, useEffect } from 'react';
import { 
  ConfigProvider, theme, Layout, Card, Button, Input, 
  Typography, Flex, Modal, App, Skeleton, Empty 
} from 'antd';
import { 
  FolderOpenOutlined, PlusOutlined, ClockCircleOutlined,
  CheckCircleOutlined, GithubOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useRouter } from 'next/navigation';
import '../globals.css'; // Make sure global styles are applied

const { Text, Title } = Typography;
const { Header, Content } = Layout;

const API_PROJECTS = 'http://localhost:8000/api/history/projects';

export default function ProjectsPage() {
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
      <App>
        <ProjectsContent />
      </App>
    </ConfigProvider>
  );
}

function ProjectsContent() {
  const router = useRouter();
  const { message } = App.useApp();
  const [projects, setProjects] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newProject, setNewProject] = useState({ name: '', absolute_path: '' });

  useEffect(() => {
    fetchProjects();
  }, []);

  const fetchProjects = async () => {
    try {
      setLoading(true);
      const res = await axios.get(API_PROJECTS);
      setProjects(res.data.projects || []);
    } catch (e) {
      console.error(e);
      message.error("Failed to load projects");
    } finally {
      setLoading(false);
    }
  };

  const selectProject = (proj: any) => {
    localStorage.setItem('activeProject', JSON.stringify(proj));
    router.push('/');
  };

  const handlePickFolder = async () => {
    try {
      const res = await axios.get('http://localhost:8000/api/utils/select-folder');
      if (res.data.path) {
        setNewProject({ ...newProject, absolute_path: res.data.path });
      }
    } catch (e) {
      console.error(e);
      message.error("Failed to open folder picker.");
    }
  };

  const handleCreate = async () => {
    if (!newProject.name || !newProject.absolute_path) {
      message.error("Please fill in both name and absolute path.");
      return;
    }
    try {
      const res = await axios.post(API_PROJECTS, newProject);
      const proj = { ...newProject, id: res.data.project_id };
      localStorage.setItem('activeProject', JSON.stringify(proj));
      message.success("Project added successfully!");
      router.push('/');
    } catch (e) {
      console.error(e);
      message.error("Failed to save project.");
    }
  };

  const formatDate = (dateString: string) => {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleString();
  };

  return (
      <Layout style={{ minHeight: '100vh', background: 'transparent' }}>
        <Header style={{ 
          background: 'rgba(0,0,0,0.5)', 
          backdropFilter: 'blur(10px)',
          borderBottom: '1px solid #1f1f1f',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 24px'
        }}>
          <Flex align="center" gap="small">
            <GithubOutlined style={{ fontSize: 24, color: '#3b82f6' }} />
            <Title level={4} style={{ margin: 0, color: '#fff', letterSpacing: '1px' }}>
              SECCODEREVIEW <span style={{ color: '#888', fontWeight: 400 }}>| Projects</span>
            </Title>
          </Flex>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalOpen(true)}>
            New Audit
          </Button>
        </Header>

        <Content style={{ padding: '40px 50px', maxWidth: 1200, margin: '0 auto', width: '100%' }}>
          <Title level={2} style={{ marginBottom: 30 }}>Select a Project</Title>

          {loading ? (
            <Skeleton active paragraph={{ rows: 6 }} />
          ) : projects.length === 0 ? (
            <Empty 
              description="No projects found. Start your first security audit." 
              image={Empty.PRESENTED_IMAGE_SIMPLE} 
            >
              <Button type="primary" onClick={() => setIsModalOpen(true)}>Create Project</Button>
            </Empty>
          ) : (
            <Flex wrap="wrap" gap="large">
              {projects.map(proj => (
                <Card 
                  key={proj.id} 
                  className="glass-card"
                  hoverable 
                  style={{ width: 350, background: '#111', borderColor: '#222' }}
                  actions={[
                    <Button type="primary" ghost key="scan" onClick={() => selectProject(proj)}>Open Console</Button>,
                    <Button key="history" onClick={() => router.push(`/history?project_id=${proj.id}`)}>History</Button>
                  ]}
                >
                  <Card.Meta 
                    avatar={<FolderOpenOutlined style={{ fontSize: 32, color: '#3b82f6' }} />}
                    title={<span style={{ fontSize: 18 }}>{proj.name}</span>}
                    description={
                      <Flex vertical gap="small" style={{ marginTop: 10 }}>
                        <Text type="secondary" ellipsis={{ tooltip: proj.absolute_path }} style={{ color: '#888' }}>
                          <FolderOpenOutlined style={{ marginRight: 6 }} /> {proj.absolute_path}
                        </Text>
                        <Text style={{ fontSize: 12, color: '#666' }}>
                          <ClockCircleOutlined style={{ marginRight: 6 }} /> Last scan: {formatDate(proj.last_scanned)}
                        </Text>
                      </Flex>
                    }
                  />
                </Card>
              ))}
            </Flex>
          )}
        </Content>

        <Modal
          title="New Project Audit"
          open={isModalOpen}
          onOk={handleCreate}
          onCancel={() => setIsModalOpen(false)}
          okText="Start Audit"
        >
          <div style={{ padding: '20px 0' }}>
            <div style={{ marginBottom: 16 }}>
              <Text strong>Project Name</Text>
              <Input 
                placeholder="e.g. My Next.js Web App" 
                value={newProject.name}
                onChange={e => setNewProject({ ...newProject, name: e.target.value })}
                style={{ marginTop: 8 }}
                autoFocus
              />
            </div>
            <div>
              <Text strong>Absolute Path</Text>
              <Input 
                placeholder="e.g. C:\Users\user\Projects\my-app" 
                value={newProject.absolute_path}
                onChange={e => setNewProject({ ...newProject, absolute_path: e.target.value })}
                style={{ marginTop: 8 }}
                suffix={
                  <FolderOpenOutlined 
                    onClick={handlePickFolder} 
                    style={{ cursor: 'pointer', color: '#3b82f6', fontSize: 16, transition: 'color 0.2s' }} 
                    onMouseEnter={e => e.currentTarget.style.color = '#93c5fd'}
                    onMouseLeave={e => e.currentTarget.style.color = '#3b82f6'}
                    title="Browse Folder"
                  />
                }
              />
              <Text type="secondary" style={{ fontSize: 12, marginTop: 4, display: 'block' }}>
                Path must exist on the local filesystem.
              </Text>
            </div>
          </div>
        </Modal>
      </Layout>
  );
}
