import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../services/auth";
import { Button, Input, Form, Typography, message } from "antd";

const LoginPage = () => {
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const onFinish = async (values: any) => {
    setLoading(true);
    try {
      await login(values.username, values.password);
      message.success("Logged in!");
      navigate("/dashboard");
    } catch (e: any) {
      message.error(e?.response?.data?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  };
  return (
    <div style={{ maxWidth: 320, margin: "100px auto" }}>
      <Typography.Title level={2} style={{ textAlign: "center" }}>
        JADE Ultimate Login
      </Typography.Title>
      <Form onFinish={onFinish} layout="vertical">
        <Form.Item name="username" label="Username" rules={[{ required: true }]}>
          <Input autoFocus />
        </Form.Item>
        <Form.Item name="password" label="Password" rules={[{ required: true }]}>
          <Input.Password />
        </Form.Item>
        <Form.Item>
          <Button type="primary" htmlType="submit" loading={loading} block>
            Login
          </Button>
        </Form.Item>
      </Form>
    </div>
  );
};

export default LoginPage;