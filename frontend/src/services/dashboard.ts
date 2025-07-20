import axios from "axios";
import { getToken } from "./auth";
const API_URL = import.meta.env.REACT_APP_API_URL || import.meta.env.VITE_API_URL || "/api/v1";

export async function getDashboardStats() {
  const { data } = await axios.get(`${API_URL}/dashboard/stats`, {
    headers: { Authorization: `Bearer ${getToken()}` },
  });
  return data;
}