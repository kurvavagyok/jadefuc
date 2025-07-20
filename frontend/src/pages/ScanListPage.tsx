import React, { useEffect, useState } from "react";
import { Table, Button, Typography } from "antd";
import { getScans } from "../services/scan";
import { useNavigate } from "react-router-dom";

const ScanListPage = () => {
  const [scans, setScans] = useState<any[]>([]);
  const navigate = useNavigate();
  useEffect(() => {
    getScans().then((data) => setScans(data.items || []));
  }, []);
  return (
    <div style={{ padding: 32 }}>
      <Typography.Title level={2}>Scans</Typography.Title>
      <Table
        rowKey="scan_id"
        dataSource={scans}
        columns={[
          { title: "Name", dataIndex: "name" },
          { title: "Type", dataIndex: "scan_type" },
          { title: "Target", dataIndex: "target" },
          { title: "Status", dataIndex: "status" },
          {
            title: "Actions",
            render: (_, record) => (
              <Button onClick={() => navigate(`/scans/${record.scan_id}`)}>Details</Button>
            ),
          },
        ]}
      />
    </div>
  );
};

export default ScanListPage;