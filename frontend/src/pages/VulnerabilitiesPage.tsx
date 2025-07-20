import React, { useEffect, useState } from "react";
import { Table, Typography, Tag } from "antd";
import { getVulnerabilities } from "../services/vulnerability";

const VulnerabilitiesPage = () => {
  const [vulns, setVulns] = useState<any[]>([]);
  useEffect(() => {
    getVulnerabilities().then(setVulns);
  }, []);
  return (
    <div style={{ padding: 32 }}>
      <Typography.Title level={2}>Vulnerabilities</Typography.Title>
      <Table
        rowKey="id"
        dataSource={vulns}
        columns={[
          { title: "Title", dataIndex: "title" },
          { title: "Type", dataIndex: "type" },
          { title: "Severity", dataIndex: "severity", render: (sev: string) => <Tag color={sev === "critical" ? "red" : sev === "high" ? "orange" : sev === "medium" ? "gold" : "green"}>{sev?.toUpperCase()}</Tag> },
          { title: "Host", dataIndex: "host" },
          { title: "Port", dataIndex: "port" },
        ]}
      />
    </div>
  );
};

export default VulnerabilitiesPage;