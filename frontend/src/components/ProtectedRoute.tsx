import React from "react";
import { Navigate } from "react-router-dom";
import { getToken } from "../services/auth";

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return getToken() ? <>{children}</> : <Navigate to="/login" />;
};
export default ProtectedRoute;