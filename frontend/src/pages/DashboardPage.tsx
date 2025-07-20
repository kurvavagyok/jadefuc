import React, { useEffect, useState } from "react";
import { Card, Statistic, Row, Col, Typography } from "antd";
import { getDashboardStats } from "../services/dashboard";

const DashboardPage = () => {
  const [stats, setStats] = useState<any>({});
  useEffect(() => {
    getDashboardStats().then(setStats);
  }, []);
  return (
    <div style={{ padding: 32 }}>
      <Typography.Title level={2}>Dashboard</Typography.Title>
      <Row gutter={24}>
        <Col span={8}>
          <Card>
            <Statistic title="Total Scans" value={stats.total_scans || 0} />
          </Card>
        </Col>
        <Col span={8}>
          <Card>
            <Statistic title="Total Vulnerabilities" value={stats.total_vulnerabilities || 0} />
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default DashboardPage;