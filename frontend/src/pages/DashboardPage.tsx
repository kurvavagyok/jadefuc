import React, { useEffect, useState } from "react";
import { Card, Statistic, Row, Col, Typography, Table, Tag, Button, notification, Space } from "antd";
import { PlayCircleOutlined, CheckCircleOutlined, ExclamationCircleOutlined } from "@ant-design/icons";
import { getDashboardStats } from "../services/dashboard";
import { getAvailableModels, testModel, AIModel } from "../services/ai";

const DashboardPage = () => {
  const [stats, setStats] = useState<any>({});
  const [aiModels, setAiModels] = useState<Record<string, AIModel>>({});
  const [testingModel, setTestingModel] = useState<string | null>(null);

  useEffect(() => {
    getDashboardStats().then(setStats);
    loadAIModels();
  }, []);

  const loadAIModels = async () => {
    try {
      const response = await getAvailableModels();
      setAiModels(response.models);
    } catch (error) {
      console.error("Failed to load AI models:", error);
    }
  };

  const handleTestModel = async (modelName: string) => {
    setTestingModel(modelName);
    try {
      const result = await testModel(modelName);
      notification.success({
        message: 'Model Test Successful',
        description: `${modelName} responded in ${result.latency_ms.toFixed(0)}ms: ${result.response.slice(0, 100)}${result.response.length > 100 ? '...' : ''}`,
        duration: 5,
      });
    } catch (error: any) {
      notification.error({
        message: 'Model Test Failed',
        description: `${modelName}: ${error.response?.data?.detail || error.message}`,
        duration: 5,
      });
    } finally {
      setTestingModel(null);
    }
  };

  const modelColumns = [
    {
      title: 'Model Name',
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: any) => (
        <Space>
          <strong>{text}</strong>
          <Tag color={record.available ? 'green' : 'red'}>
            {record.available ? 'Available' : 'Unavailable'}
          </Tag>
        </Space>
      ),
    },
    {
      title: 'Provider',
      dataIndex: 'provider',
      key: 'provider',
      render: (provider: string) => {
        const colors: Record<string, string> = {
          openai: 'blue',
          google: 'green',
          github: 'purple',
          cerebras: 'orange',
        };
        return <Tag color={colors[provider] || 'default'}>{provider.toUpperCase()}</Tag>;
      },
    },
    {
      title: 'Model ID',
      dataIndex: 'model',
      key: 'model',
    },
    {
      title: 'Use Case',
      dataIndex: 'use_case',
      key: 'use_case',
      render: (useCase: string) => useCase.replace(/_/g, ' ').toUpperCase(),
    },
    {
      title: 'Action',
      key: 'action',
      render: (text: any, record: any) => (
        record.available ? (
          <Button
            type="primary"
            size="small"
            icon={testingModel === record.name ? <CheckCircleOutlined spin /> : <PlayCircleOutlined />}
            onClick={() => handleTestModel(record.name)}
            loading={testingModel === record.name}
            disabled={testingModel !== null}
          >
            Test
          </Button>
        ) : (
          <Button type="default" size="small" disabled>
            <ExclamationCircleOutlined /> Unavailable
          </Button>
        )
      ),
    },
  ];

  const modelData = Object.entries(aiModels).map(([name, model]) => ({
    key: name,
    name,
    ...model,
  }));

  const availableModels = Object.values(aiModels).filter(m => m.available).length;
  const totalModels = Object.keys(aiModels).length;

  return (
    <div style={{ padding: 32 }}>
      <Typography.Title level={2}>
        JADE Ultimate Security Platform Dashboard
      </Typography.Title>
      
      {/* Statistics Cards */}
      <Row gutter={24} style={{ marginBottom: 32 }}>
        <Col span={6}>
          <Card>
            <Statistic 
              title="Total Scans" 
              value={stats.total_scans || 0} 
              prefix={<CheckCircleOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic 
              title="Active Scans" 
              value={stats.active_scans || 0} 
              prefix={<PlayCircleOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic 
              title="Vulnerabilities Found" 
              value={stats.vulnerabilities_found || 0} 
              prefix={<ExclamationCircleOutlined />}
            />
          </Card>
        </Col>
        <Col span={6}>
          <Card>
            <Statistic 
              title="AI Models Available" 
              value={availableModels} 
              suffix={`/ ${totalModels}`}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: availableModels > 0 ? '#3f8600' : '#cf1322' }}
            />
          </Card>
        </Col>
      </Row>

      {/* AI Models Table */}
      <Card title="Available AI Models" style={{ marginBottom: 32 }}>
        <Table
          columns={modelColumns}
          dataSource={modelData}
          pagination={false}
          size="small"
        />
      </Card>
    </div>
  );
};

export default DashboardPage;