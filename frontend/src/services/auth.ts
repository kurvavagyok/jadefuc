import axios from "axios";

const API_URL = import.meta.env.REACT_APP_API_URL || import.meta.env.VITE_API_URL || "/api/v1";

export async function login(username: string, password: string) {
  const formData = new FormData();
  formData.append('username', username);
  formData.append('password', password);
  
  const { data } = await axios.post(`${API_URL}/auth/token`, formData, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
  localStorage.setItem("token", data.access_token);
}

export function getToken() {
  return localStorage.getItem("token") || "mock_jwt_token";
}