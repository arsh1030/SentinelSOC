import axios from "axios";
import { API_BASE } from "@/constants/config";

/** Pre-configured client for the SentinelSOC backend. */
const api = axios.create({ baseURL: API_BASE, timeout: 300_000 });

export default api;
