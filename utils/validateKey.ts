import axios from "axios";
import { Request, Response, Router } from "express";
import ServiceModel from "../model/ServiceModel";
import SubscriptionModel from "../model/SubscriptionModel";
import IpWhiteListModel from "../model/IpWhiteListModel";
import ApiKeyModel from "../model/ApiKeyModel";
import ProxyModel from "../model/ProxyModel";
import mongoose from "mongoose";


const validateKey = async (apiKey: string, req: Request, res: Response) => {

    const apiKeyData = await ApiKeyModel.findOne({ apiKey: apiKey });
    if (!apiKeyData) {
        return res.status(400).json({ success: false, error: "Api key doesn't exist" })
    }

    const subscriptionId = apiKeyData.subscriptionId;
    const subscriptionData = await SubscriptionModel.findById(new mongoose.Types.ObjectId(subscriptionId));
    if (!subscriptionData) {
        return res.status(400).json({ success: false, error: "Subscription data doesn't exist" })
    }

    const serviceId = subscriptionData.serviceId;

    // Get ip_address from Proxies table using the serviceId
    const proxy = await ProxyModel.findOne({ serviceId: serviceId });

    if (!proxy) {
        console.log("Proxy not found");
        return false;
    }

    const ipAddress = proxy.ipAddress;

    // Add API key to backend proxy
    try {
        const response = await axios.post(`http://${ipAddress}:5000/add`, { apiKey });

        // Check if API key was added successfully
        if (response.status === 200) {
            console.log("API key added successfully");
            return res.json({ success: true });
        } else {
            return res.status(401).json({ success: false, error: "Api key doesn't valid" });
        }
    } catch (error) {
        console.error("Error adding API key:", error);
        return res.status(401).json({ success: false, error: "Api key doesn't valid" });
    }
};

export default validateKey;