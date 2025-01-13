import { errorLogger } from "../utils/logger";
import { DB_URL, BACKEND_PORT, JSONWEBTOKEN_SECRET } from "../utils/config";

try {
  
} catch (error) {
  errorLogger.error("Error loading environment variables:", error);
  process.exit(1);
}

export const MONGO_URL = DB_URL;
export const PORT = process.env.PORT || 4999;
export const JWT_SECRET = JSONWEBTOKEN_SECRET || "JWT_SECRET";