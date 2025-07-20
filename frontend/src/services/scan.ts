import axios from "axios";
import { getToken } from "./auth";
const API_URL = import.meta.env.VITE_API_URL || "/api/v1";

export async function getScans() {
  const { data } = await axios.get(`${API_URL}/scans`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  return data;
}

export async function getScan(scanId: string) {
  const { data } = await axios.get(`${API_URL}/scans/${scanId}`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  return data;
}