import { Request, Response, Router } from "express";
import { check, validationResult } from "express-validator";
import axios from "axios";
import qs from "qs";
import ServiceModel from "../../model/ServiceModel";
import SubscriptionModel from "../../model/SubscriptionModel";
import ApiKeyModel from "../../model/ApiKeyModel";
import IpWhiteListModel from "../../model/IpWhiteListModel";
import activateSubscription from "../../utils/activateSubscription";
import deactivateSubscription from "../../utils/deactivateSubscription";
import { authMiddleware } from "../../middleware";
import mongoose from "mongoose";

// Create a new instance of the Express Router
const SubscriptionRouter = Router();

// @route    Post api/subscriptions/
// @desc     Get all subscriptions for user
// @access   Private
SubscriptionRouter.post(
    '/',
    check("userId", "UserId is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        const userId = req.body.userId;

        try {
            const subscriptions = await SubscriptionModel.aggregate([
                {
                    $match: { userId: new mongoose.Types.ObjectId(userId), status: "active" } // Filter by user ID
                },
                {
                    // Join with the Services collection
                    $lookup: {
                        from: 'services',
                        localField: 'serviceId',
                        foreignField: '_id',
                        as: 'service'
                    }
                },
                {
                    $unwind: { path: '$service', preserveNullAndEmptyArrays: true } // Flatten the service array
                },
                {
                    // Join with the IPWhitelist collection for grpc services
                    $lookup: {
                        from: 'ipwhitelists',
                        localField: '_id',
                        foreignField: 'subscriptionId',
                        as: 'ipWhitelist'
                    }
                },
                {
                    // Join with the APIKeys collection for rpc or stakedrpc services
                    $lookup: {
                        from: 'apikeys',
                        localField: '_id',
                        foreignField: 'subscriptionId',
                        as: 'apiKey'
                    }
                },
                {
                    // Project the necessary fields
                    $project: {
                        subscriptionId: '$_id',
                        userId: '$userId',
                        serviceId: '$serviceId',
                        status: '$status',
                        createdAt: '$createdAt',
                        whitelistedIp: '$ipWhitelist', 
                        apiKey: '$apiKey', 
                        customName: '$customName',
                        serviceName: '$service.serviceName',
                        tierName: '$service.tierName',
                        expireDate: '$expireDate',
                        updatedAt: '$updatedAt',
                    }
                },
            ]);

            return res.status(200).json({ subscriptions: subscriptions});
        } catch (error) {
            console.error("Error retrieving subscriptions:", error);
            return res.status(500).json({ error: "An error occurred while retrieving subscriptions." });
        }
    }
);

// @route    Post api/subscriptions/
// @desc     Get all subscriptions for user
// @access   Private
SubscriptionRouter.post(
    '/',
    check("userId", "UserId is required").notEmpty(),
    // check("active", "Active is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        const userId = req.body.userId;

        try {
            const subscriptions = await SubscriptionModel.aggregate([
                {
                    $match: { userId: new mongoose.Types.ObjectId(userId), status: "active" } // Filter by user ID
                },
                {
                    // Join with the Services collection
                    $lookup: {
                        from: 'services',
                        localField: 'serviceId',
                        foreignField: '_id',
                        as: 'service'
                    }
                },
                {
                    $unwind: { path: '$service', preserveNullAndEmptyArrays: true } // Flatten the service array
                },
                {
                    // Join with the IPWhitelist collection for grpc services
                    $lookup: {
                        from: 'ipwhitelists',
                        localField: '_id',
                        foreignField: 'subscriptionId',
                        as: 'ipWhitelist'
                    }
                },
                {
                    // Join with the APIKeys collection for rpc or stakedrpc services
                    $lookup: {
                        from: 'apikeys',
                        localField: '_id',
                        foreignField: 'subscriptionId',
                        as: 'apiKey'
                    }
                },
                {
                    // Project the necessary fields
                    $project: {
                        subscriptionId: '$_id',
                        userId: '$userId',
                        serviceId: '$serviceId',
                        status: '$status',
                        createdAt: '$createdAt',
                        whitelistedIp: '$ipWhitelist', 
                        apiKey: '$apiKey', 
                        customName: '$customName',
                        serviceName: '$service.serviceName',
                        tierName: '$service.tierName',
                        expireDate: '$expireDate',
                        updatedAt: '$updatedAt',
                    }
                },
            ]);

            return res.status(200).json({ subscriptions: subscriptions});
        } catch (error) {
            console.error("Error retrieving subscriptions:", error);
            return res.status(500).json({ error: "An error occurred while retrieving subscriptions." });
        }
    }
);

// @route    Post api/subscriptions/getByIdAndUser
// @desc     Get subscription by subscription id and user
// @access   Private
SubscriptionRouter.post(
    '/getByIdAndUser',
    check("userId", "UserId is required").notEmpty(),
    check("subscriptionId", "SubscriptionId is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        
        const subscriptionId = req.body.subscriptionId;
        const userId = req.body.userId;

        try {
            const result = await SubscriptionModel.aggregate([
                {
                    $match: { _id: new mongoose.Types.ObjectId(subscriptionId) } // Match subscription and user ID
                },
                {
                    $lookup: {
                        from: 'services',
                        localField: 'serviceId',
                        foreignField: '_id',
                        as: 'service'
                    }
                },
                {
                    $unwind: { path: '$service', preserveNullAndEmptyArrays: true } // Unwind to access service properties
                },
                {
                    $lookup: {
                        from: 'ipwhitelists',
                        localField: '_id',
                        foreignField: 'subscriptionId',
                        as: 'ipWhitelist'
                    }
                },
                {
                    $lookup: {
                        from: 'apikeys',
                        localField: '_id',
                        foreignField: 'subscriptionId',
                        as: 'apiKey'
                    }
                },
                {
                    $project: {
                        subscription_id: 1,
                        user_id: 1,
                        service_id: 1,
                        status: 1,
                        created_at: 1,
                        'service.serviceName': 1,
                        'service.tierName': 1,
                        whitelistedIp: '$ipWhitelist', 
                        apiKey: '$apiKey', 
                    }
                }

            ]);

            if (result.length === 0) {
                return res.status(400).json({ error: "Subscription not found" });
            }
            return res.status(200).json({ subscription: result[0] }); // Return the first result object

        } catch (error) {
            console.error("Error retrieving subscriptions:", error);
            return res.status(500).json({ error: "An error occurred while retrieving subscriptions." });
        }
    }
);

// @route    Post api/subscriptions/updateCustomName
// @desc     Update subscription customName 
// @access   Private
SubscriptionRouter.post(
    '/updateCustomName',
    check("subscriptionId", "SubscriptionId is required").notEmpty(),
    check("customName", "CustomName is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        const customName = req.body.customName;
        const subscriptionId = req.body.subscriptionId;
        try {
            const updatedData = await SubscriptionModel.findOneAndUpdate(
                { _id: subscriptionId },
                { customName: customName },
                { new: true }
            )
            return res.json({ data: updatedData });
        } catch (err) {
            console.log('error updating subscription data ===> ', err)
            return res.status(500).json({ error: "An error occurred while updating subscription" });
        }
    }
);

// @route    Post api/subscriptions/verify
// @desc     Verify subscription API key
// @access   Private
SubscriptionRouter.post(
    '/verify',
    check("subscriptionId", "SubscriptionId is required").notEmpty(),
    check("userId", "UserId is required").notEmpty(),
    authMiddleware,
    async (req: Request, res: Response) => {
        const subscriptionId = req.body.subscriptionId;
        const userId = req.body.userId; // Extract user ID from the JWT token

        try {
            // Fetch the subscription
            const subscription = await SubscriptionModel.findById(subscriptionId);

            if (!subscription) {
                return res.status(400).json({ success: true, error: "Subscription not found" });
            }

            if (subscription.userId !== userId) {
                return res.status(403).json({ success: true, error: "Subscription does not belong to user" });
            }

            // Fetch the associated service
            const service = await ServiceModel.findById(subscription.serviceId);

            if (!service) {
                return res.status(404).json({ success: true, error: "Service not found" });
            }

            // Verify the service type
            if (service.serviceName !== "rpc" && service.serviceName !== "stakedrpc") {
                return res.status(400).json({ success: true, error: "Subscription is not an API subscription" });
            }

            // Fetch the API key
            const apiKey = await ApiKeyModel.findOne({ subscriptionId: subscriptionId });

            if (!apiKey) {
                return res.status(404).json({ success: true, error: "API key not found" });
            }

            // Construct the URL for health check
            const url = `http://${service.connectionURL}/?api_key=${apiKey.apiKey}`;

            // Perform health check against RPC endpoint
            try {
                const headers = { "Content-Type": "application/json" };
                const data = {
                    jsonrpc: "2.0",
                    id: 1,
                    method: "getHealth",
                };

                // Send POST request for health check
                const response = await axios.post(url, data, { headers });

                // If status is 200, return the health check result
                if (response.status === 200) {
                    return res.status(200).json({ success: true });
                } else {
                    return res.status(500).json({ success: true, error: "Health check failed due to some unknown error" });
                }
            } catch (error) {
                return res.status(500).json({ success: true, error: `Health check failed: ${error}` });
            }
        } catch (err) {
            console.error("Error verifying API key:", err);
            return res.status(500).json({ success: true, error: "An error occurred while verifying the API key." });
        }
    }
)

export default SubscriptionRouter;