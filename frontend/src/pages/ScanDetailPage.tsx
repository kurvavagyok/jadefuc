import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { getScan } from "../services/scan";
import { Card, Descriptions, Typography } from "antd";

const ScanDetailPage = () => {
  const { scanId } = useParams();
  const [scan, setScan] = useState<any>(null);

  useEffect(() => {
    if (scanId) getScan(scanId).then(setScan);
  }, [scanId]);

  if (!scan) return null;
  return (
    <div style={{ padding: 32 }}>
      <Typography.Title level={3}>Scan Details</Typography.Title>
      <Card>
        <Descriptions bordered column={1}>
          <Descriptions.Item label="Scan ID">{scan.scan_id}</Descriptions.Item>
          <Descriptions.Item label="Name">{scan.name}</Descriptions.Item>
          <Descriptions.Item label="Type">{scan.scan_type}</Descriptions.Item>
          <Descriptions.Item label="Target">{scan.target}</Descriptions.Item>
          <Descriptions.Item label="Status">{scan.status}</Descriptions.Item>
          <Descriptions.Item label="Progress">{scan.progress}%</Descriptions.Item>
        </Descriptions>
      </Card>
    </div>
  );
};

export default ScanDetailPage;