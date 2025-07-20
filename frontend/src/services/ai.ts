import axios from "axios";
import { getToken } from "./auth";

const API_URL = import.meta.env.REACT_APP_API_URL || import.meta.env.VITE_API_URL || "/api/v1";

export interface AIModel {
  provider: string;
  model: string;
  use_case: string;
  available: boolean;
}

export interface ModelResponse {
  models: Record<string, AIModel>;
}

export interface TestResponse {
  model: string;
  status: string;
  response: string;
  provider: string;
  latency_ms: number;
  tokens_used?: number;
}

export async function getAvailableModels(): Promise<ModelResponse> {
  const { data } = await axios.get(`${API_URL}/ai/models`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  return data;
}

export async function testModel(modelName: string): Promise<TestResponse> {
  const { data } = await axios.post(`${API_URL}/ai/test/${modelName}`, {}, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  return data;
}

export async function analyzeData(scanId: string, model: string = "gpt-4"): Promise<any> {
  const { data } = await axios.post(`${API_URL}/ai/analyze`, {
    scan_id: scanId,
    model: model
  }, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  return data;
}