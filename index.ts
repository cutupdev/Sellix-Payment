import bodyParser from "body-parser";
import cors from "cors";
import express from "express";
import path from 'path';
import { logLogger, defaultLogger } from "./utils/logger";
import { PORT, connectMongoDB } from "./config";
import http from "http";
import { UserRouter, ServiceRouter, SubscriptionRouter, PaymentRouter, PurchaseRouter, ApiKeyRouter, IPWhiteListRouter, ProxyRouter } from "./routes";
import passport from "passport";
import session from "express-session";

// Connect to the MongoDB database
connectMongoDB();

// Create an instance of the Express application
const app = express();

const whitelist = [
  "https://dev.portal-frontend.solanavibestation.com",
  "http://localhost:3999"
];
const corsOptions = {
  origin: whitelist,
  credentials: false,
  sameSite: "none",
};

app.use(cors(corsOptions));

// Set up Cross-Origin Resource Sharing (CORS) options
app.use(cors());

// Serve static files from the 'public' folder
app.use(express.static(path.join(__dirname, './public')));

// Parse incoming JSON requests using body-parser
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

app.use(session({
  secret: 'SECRET',
  resave: false,
  saveUninitialized: false,
}))

app.use(passport.initialize());
app.use(passport.session());


const server = http.createServer(app);

// Define routes for different API endpoints
app.use("/api/users", UserRouter);
app.use("/api/services", ServiceRouter);
app.use("/api/subscriptions", SubscriptionRouter);
app.use("/api/payments", PaymentRouter);
app.use("/api/purchase", PurchaseRouter)
app.use("/api/apiKey", ApiKeyRouter);
app.use("/api/ipWhiteList", IPWhiteListRouter);
app.use("/api/proxy", ProxyRouter);

// Define a route to check if the backend server is running
app.get("/", async (req: any, res: any) => {
  res.send("Backend Server is Running now!");
});

// Start the Express server to listen on the specified port
server.listen(PORT, () => {
  logLogger.debug(`Server is running on port ${PORT}`);
  defaultLogger.debug(`Server is running on port ${PORT}`);
});
